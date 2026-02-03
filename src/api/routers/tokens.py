"""
Token 充值路由
"""
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db, User, TokenPurchase, SystemSettings
from ..auth.dependencies import get_current_user
from ..services.token_purchase_service import TokenPurchaseService

router = APIRouter(prefix="/tokens", tags=["tokens"])


# =============================================================================
# 请求/响应模型
# =============================================================================

class PurchaseRequest(BaseModel):
    """充值请求"""
    transaction_digest: str = Field(..., description="Sui 交易哈希")


class PurchaseResponse(BaseModel):
    """充值响应"""
    status: str = Field(..., description="状态：success, already_processed, price_mismatch")
    purchase_id: str = Field(..., description="充值记录 ID")
    token_amount: int | None = Field(None, description="获得的 Token 数量")
    new_balance: int | None = Field(None, description="新的余额")
    message: str = Field(..., description="消息")
    requires_manual_review: bool = Field(False, description="是否需要人工审核")


class TokenBalanceResponse(BaseModel):
    """Token 余额响应"""
    balance: int = Field(..., description="当前 Token 余额")
    quota: int | None = Field(None, description="配额上限（NULL = 无限）")
    used: int = Field(..., description="已使用 Token")


class PurchaseHistoryItem(BaseModel):
    """充值历史记录"""
    id: str
    transaction_digest: str
    wallet_address: str
    sui_amount: int  # MIST
    usd_amount: int  # cents
    sui_usd_price: float
    token_amount: int
    token_usd_price: float
    status: str
    error_message: str | None
    blockchain_timestamp: str | None
    confirmed_at: str | None
    created_at: str


class PurchaseHistoryResponse(BaseModel):
    """充值历史响应"""
    purchases: list[PurchaseHistoryItem]
    total: int


# =============================================================================
# 路由
# =============================================================================

@router.post("/purchase", response_model=PurchaseResponse)
async def purchase_tokens(
    req: PurchaseRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    提交充值交易进行验证

    用户在前端通过钱包调用智能合约后，将交易哈希提交到后端进行验证。
    后端验证交易有效性和价格合理性后，充值 Token 到用户账户。

    Args:
        req: 充值请求
        user: 当前用户
        db: 数据库会话

    Returns:
        PurchaseResponse: 充值结果
    """
    # 1. 读取系统配置
    result = await db.execute(
        select(SystemSettings).where(
            SystemSettings.key.in_([
                "sui_rpc_url",
                "sui_package_id",
                "sui_price_tolerance"
            ])
        )
    )
    settings_list = result.scalars().all()
    settings_dict = {s.key: s.value for s in settings_list}

    sui_rpc_url = settings_dict.get("sui_rpc_url", "https://fullnode.testnet.sui.io:443")
    sui_package_id = settings_dict.get("sui_package_id")
    price_tolerance = float(settings_dict.get("sui_price_tolerance", "0.05"))

    if not sui_package_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="智能合约未配置，请联系管理员",
        )

    # 2. 创建服务并处理充值
    service = TokenPurchaseService(
        sui_rpc_url=sui_rpc_url,
        package_id=sui_package_id,
        price_tolerance=price_tolerance
    )

    try:
        result = await service.verify_and_process_purchase(
            db=db,
            transaction_digest=req.transaction_digest,
            user_id=user.id
        )

        return PurchaseResponse(**result)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"充值处理失败: {str(e)}",
        )


@router.get("/balance", response_model=TokenBalanceResponse)
async def get_token_balance(user: User = Depends(get_current_user)):
    """
    获取当前用户 Token 余额

    Returns:
        TokenBalanceResponse: 余额信息
    """
    return TokenBalanceResponse(
        balance=user.token_balance,
        quota=user.token_quota,
        used=user.tokens_used,
    )


@router.get("/purchase-history", response_model=PurchaseHistoryResponse)
async def get_purchase_history(
    limit: int = 20,
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    获取充值历史记录

    Args:
        limit: 每页数量
        offset: 偏移量
        user: 当前用户
        db: 数据库会话

    Returns:
        PurchaseHistoryResponse: 充值历史
    """
    # 查询总数
    from sqlalchemy import func
    result = await db.execute(
        select(func.count(TokenPurchase.id)).where(
            TokenPurchase.user_id == user.id
        )
    )
    total = result.scalar_one()

    # 查询记录
    result = await db.execute(
        select(TokenPurchase)
        .where(TokenPurchase.user_id == user.id)
        .order_by(desc(TokenPurchase.created_at))
        .limit(limit)
        .offset(offset)
    )
    purchases = result.scalars().all()

    items = [
        PurchaseHistoryItem(
            id=p.id,
            transaction_digest=p.transaction_digest,
            wallet_address=p.wallet_address,
            sui_amount=p.sui_amount,
            usd_amount=p.usd_amount,
            sui_usd_price=p.sui_usd_price,
            token_amount=p.token_amount,
            token_usd_price=p.token_usd_price,
            status=p.status.value,
            error_message=p.error_message,
            blockchain_timestamp=p.blockchain_timestamp.isoformat() if p.blockchain_timestamp else None,
            confirmed_at=p.confirmed_at.isoformat() if p.confirmed_at else None,
            created_at=p.created_at.isoformat(),
        )
        for p in purchases
    ]

    return PurchaseHistoryResponse(
        purchases=items,
        total=total,
    )


@router.get("/sui-price")
async def get_sui_price():
    """
    获取实时 SUI/USD 价格（Pyth Network）

    Returns:
        价格信息
    """
    from ..services.token_purchase_service import TokenPurchaseService

    service = TokenPurchaseService(
        sui_rpc_url="",  # 不需要 RPC
        package_id="",   # 不需要 Package ID
    )

    try:
        price = await service._get_sui_usd_price()
        return {
            "sui_usd": price,
            "source": "Pyth Network",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"无法获取价格: {str(e)}",
        )
