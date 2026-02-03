"""
用户管理路由

- Admin: 用户列表、角色修改、删除用户
- User: 自己的 API Key 管理、审计配置管理
"""
from typing import Optional, List
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db, User, UserRole, TokenUsage, PaymentMode
from ..auth import encrypt_api_keys, decrypt_api_keys, verify_password, hash_password
from ..auth.dependencies import get_current_user, get_current_admin
from ..auth.password_validator import validate_password_strength
from ..services.token_stats_service import (
    get_token_usage_trend,
    get_token_usage_by_project,
    get_token_usage_by_agent,
)

router = APIRouter(prefix="/users", tags=["users"])


# =============================================================================
# 请求/响应模型
# =============================================================================

class UserListItem(BaseModel):
    id: str
    username: str
    role: str
    is_active: bool
    allow_shared_api_keys: bool = True  # 🔥 是否允许使用共享 API Keys
    token_quota: Optional[int] = None  # 🔥 Token 额度
    tokens_used: int = 0               # 🔥 已使用
    created_at: str
    updated_at: Optional[str] = None


class UserListResponse(BaseModel):
    users: List[UserListItem]
    total: int


class UpdateRoleRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|user)$")


class UpdateStatusRequest(BaseModel):
    is_active: bool


class UpdateSharedApiKeysRequest(BaseModel):
    allow_shared_api_keys: bool


class ApiKeysStatusResponse(BaseModel):
    """API Key 状态（不返回明文）"""
    dashscope: bool = False
    anthropic: bool = False
    openai: bool = False
    deepseek: bool = False
    zhipu: bool = False


class ApiKeysUpdateRequest(BaseModel):
    """更新 API Keys（空字符串表示删除该 key）"""
    dashscope: Optional[str] = None
    anthropic: Optional[str] = None
    openai: Optional[str] = None
    deepseek: Optional[str] = None
    zhipu: Optional[str] = None


class AuditConfigResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    model_preset: str = "auto"
    agent_architecture: str = "3-agent"
    max_retries: int = 15
    enable_security_scan: bool = True


class AuditConfigUpdateRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    model_preset: Optional[str] = None
    agent_architecture: Optional[str] = None
    max_retries: Optional[int] = None
    enable_security_scan: Optional[bool] = None


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=6, max_length=100)


class PaymentModeResponse(BaseModel):
    """付费模式信息"""
    payment_mode: str  # own_key | platform_token
    tokens_used_own_key: int = 0  # 使用自己 API Key 消耗的 tokens
    tokens_used_platform: int = 0  # 使用平台 Token 消耗的 tokens
    token_balance: int = 0  # 当前可用余额（购买获得）


class PaymentModeUpdateRequest(BaseModel):
    """更新付费模式"""
    payment_mode: str = Field(..., pattern="^(own_key|platform_token)$")


# =============================================================================
# Admin: 用户管理
# =============================================================================

@router.get("", response_model=UserListResponse)
async def list_users(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """获取用户列表（管理员）"""
    result = await db.execute(
        select(User).order_by(User.created_at.desc())
    )
    users = result.scalars().all()

    return UserListResponse(
        users=[
            UserListItem(
                id=u.id,
                username=u.username,
                role=u.role.value,
                is_active=u.is_active,
                allow_shared_api_keys=u.allow_shared_api_keys,
                token_quota=u.token_quota,
                tokens_used=u.tokens_used or 0,
                created_at=u.created_at.isoformat(),
                updated_at=u.updated_at.isoformat() if u.updated_at else None,
            )
            for u in users
        ],
        total=len(users),
    )


@router.post("/{user_id}/role")
async def update_user_role(
    user_id: str,
    req: UpdateRoleRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """修改用户角色（管理员）"""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="不能修改自己的角色")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    user.role = UserRole(req.role)
    return {"message": "角色已更新", "user_id": user_id, "role": req.role}


@router.post("/{user_id}/status")
async def update_user_status(
    user_id: str,
    req: UpdateStatusRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """启用/禁用用户（管理员）"""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="不能禁用自己")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    user.is_active = req.is_active
    return {"message": "状态已更新", "user_id": user_id, "is_active": req.is_active}


@router.post("/{user_id}/shared-api-keys")
async def update_user_shared_api_keys(
    user_id: str,
    req: UpdateSharedApiKeysRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """允许/禁止用户使用共享 API Keys（管理员）"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    user.allow_shared_api_keys = req.allow_shared_api_keys
    return {
        "message": "API Keys 共享权限已更新",
        "user_id": user_id,
        "allow_shared_api_keys": req.allow_shared_api_keys
    }


@router.post("/{user_id}/delete")
async def delete_user(
    user_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """删除用户（管理员）"""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="不能删除自己")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    await db.delete(user)
    return {"message": "用户已删除", "user_id": user_id}


# =============================================================================
# User: API Key 管理
# =============================================================================

@router.get("/me/shared-api-keys-permission")
async def get_shared_api_keys_permission(user: User = Depends(get_current_user)):
    """获取当前用户是否允许使用共享 API Keys"""
    return {"allow_shared_api_keys": user.allow_shared_api_keys}


@router.get("/me/api-keys", response_model=ApiKeysStatusResponse)
async def get_api_keys_status(user: User = Depends(get_current_user)):
    """获取当前用户 API Key 配置状态"""
    keys = decrypt_api_keys(user.api_keys_encrypted) if user.api_keys_encrypted else {}
    return ApiKeysStatusResponse(
        dashscope=bool(keys.get("dashscope")),
        anthropic=bool(keys.get("anthropic")),
        openai=bool(keys.get("openai")),
        deepseek=bool(keys.get("deepseek")),
        zhipu=bool(keys.get("zhipu")),
    )


@router.post("/me/api-keys")
async def update_api_keys(
    req: ApiKeysUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """更新当前用户 API Keys"""
    # 解密现有 keys
    current_keys = decrypt_api_keys(user.api_keys_encrypted) if user.api_keys_encrypted else {}

    # 合并更新（None=不变, 空字符串=删除, 有值=更新）
    update_data = req.model_dump(exclude_none=True)
    for key, value in update_data.items():
        if value == "":
            current_keys.pop(key, None)
        else:
            current_keys[key] = value

    # 重新加密存储
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one()
    db_user.api_keys_encrypted = encrypt_api_keys(current_keys) if current_keys else None

    return {"message": "API Keys 已更新"}


# =============================================================================
# User: 审计配置管理
# =============================================================================

@router.get("/me/audit-config", response_model=AuditConfigResponse)
async def get_audit_config(user: User = Depends(get_current_user)):
    """获取当前用户审计配置"""
    config = user.audit_config or {}
    return AuditConfigResponse(
        model_preset=config.get("model_preset", "auto"),
        agent_architecture=config.get("agent_architecture", "3-agent"),
        max_retries=config.get("max_retries", 15),
        enable_security_scan=config.get("enable_security_scan", True),
    )


@router.post("/me/audit-config")
async def update_audit_config(
    req: AuditConfigUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """更新当前用户审计配置"""
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one()

    config = db_user.audit_config or {}
    update_data = req.model_dump(exclude_none=True)
    config.update(update_data)
    db_user.audit_config = config

    return {"message": "审计配置已更新", "config": config}


# =============================================================================
# User: 付费模式管理
# =============================================================================

@router.get("/me/payment-mode", response_model=PaymentModeResponse)
async def get_payment_mode(user: User = Depends(get_current_user)):
    """获取当前用户付费模式"""
    return PaymentModeResponse(
        payment_mode=user.payment_mode.value,
        tokens_used_own_key=user.tokens_used_own_key or 0,
        tokens_used_platform=user.tokens_used_platform or 0,
        token_balance=user.token_balance or 0,
    )


@router.post("/me/payment-mode")
async def update_payment_mode(
    req: PaymentModeUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """更新当前用户付费模式"""
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one()

    db_user.payment_mode = PaymentMode(req.payment_mode)

    return {
        "message": "付费模式已更新",
        "payment_mode": req.payment_mode,
    }


# =============================================================================
# User: 修改密码
# =============================================================================

@router.post("/me/password")
async def change_password(
    req: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """修改当前用户密码"""
    result = await db.execute(select(User).where(User.id == user.id))
    db_user = result.scalar_one()

    # 1. 验证原密码
    if not verify_password(req.old_password, db_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="原密码错误",
        )

    # 2. 验证新密码强度
    is_valid, errors = validate_password_strength(req.new_password, min_length=8)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"密码强度不足: {', '.join(errors)}",
        )

    # 3. 修改密码并取消强制修改标记
    db_user.password_hash = hash_password(req.new_password)
    db_user.password_must_change = False  # 🔥 修改后取消强制修改标记
    return {"message": "密码已修改"}


# =============================================================================
# Token 额度管理 - 请求/响应模型
# =============================================================================

class TokenQuotaResponse(BaseModel):
    """Token 额度信息"""
    token_quota: Optional[int] = None  # None = 无限
    tokens_used: int = 0
    tokens_used_own_key: int = 0  # 使用自己 API Key 消耗的 tokens
    tokens_used_platform: int = 0  # 使用平台 Token 消耗的 tokens
    remaining: Optional[int] = None    # None = 无限
    is_unlimited: bool = True
    usage_percent: Optional[float] = None  # 使用百分比


class TokenQuotaUpdateRequest(BaseModel):
    """更新 Token 额度"""
    token_quota: Optional[int] = Field(None, ge=0)  # None = 无限, 0+ = 限制


class TokenUsageRecord(BaseModel):
    """单次 Token 使用记录"""
    id: str
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    audit_id: Optional[str] = None
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    agent_breakdown: dict
    audit_status: Optional[str] = None
    created_at: str


class TokenUsageListResponse(BaseModel):
    """Token 使用记录列表"""
    records: List[TokenUsageRecord]
    total_count: int
    total_tokens: int


class UserTokenStatsItem(BaseModel):
    """用户 Token 统计项"""
    user_id: str
    username: str
    role: str
    token_quota: Optional[int] = None
    tokens_used: int
    remaining: Optional[int] = None
    is_unlimited: bool
    audit_count: int


class AllUsersTokenStatsResponse(BaseModel):
    """所有用户 Token 统计"""
    users: List[UserTokenStatsItem]
    system_total_tokens: int


# =============================================================================
# User: Token 额度查看
# =============================================================================

@router.get("/me/token-quota", response_model=TokenQuotaResponse)
async def get_my_token_quota(user: User = Depends(get_current_user)):
    """获取当前用户 Token 额度和使用量"""
    is_unlimited = user.token_quota is None
    remaining = None if is_unlimited else max(0, user.token_quota - user.tokens_used)
    usage_percent = None if is_unlimited else (
        (user.tokens_used / user.token_quota * 100) if user.token_quota > 0 else 100
    )

    return TokenQuotaResponse(
        token_quota=user.token_quota,
        tokens_used=user.tokens_used or 0,
        tokens_used_own_key=user.tokens_used_own_key or 0,
        tokens_used_platform=user.tokens_used_platform or 0,
        remaining=remaining,
        is_unlimited=is_unlimited,
        usage_percent=round(usage_percent, 2) if usage_percent is not None else None,
    )


@router.get("/me/token-usage", response_model=TokenUsageListResponse)
async def get_my_token_usage(
    limit: int = 50,
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """获取当前用户 Token 使用记录"""
    # 查询使用记录
    result = await db.execute(
        select(TokenUsage)
        .where(TokenUsage.user_id == user.id)
        .order_by(TokenUsage.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    records = result.scalars().all()

    # 统计总量
    count_result = await db.execute(
        select(func.count(TokenUsage.id), func.sum(TokenUsage.total_tokens))
        .where(TokenUsage.user_id == user.id)
    )
    count_row = count_result.one()
    total_count = count_row[0] or 0
    total_tokens = count_row[1] or 0

    return TokenUsageListResponse(
        records=[
            TokenUsageRecord(
                id=r.id,
                project_id=r.project_id,
                project_name=r.project_name,
                audit_id=r.audit_id,
                prompt_tokens=r.prompt_tokens or 0,
                completion_tokens=r.completion_tokens or 0,
                total_tokens=r.total_tokens or 0,
                agent_breakdown=r.agent_breakdown or {},
                audit_status=r.audit_status,
                created_at=r.created_at.isoformat(),
            )
            for r in records
        ],
        total_count=total_count,
        total_tokens=total_tokens,
    )


# =============================================================================
# Admin: Token 额度管理
# =============================================================================

@router.get("/admin/token-stats", response_model=AllUsersTokenStatsResponse)
async def get_all_users_token_stats(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """获取所有用户 Token 统计（管理员）"""
    # 获取所有用户
    users_result = await db.execute(
        select(User).order_by(User.tokens_used.desc())
    )
    users = users_result.scalars().all()

    # 获取每个用户的审计次数
    audit_counts = {}
    for user in users:
        count_result = await db.execute(
            select(func.count(TokenUsage.id))
            .where(TokenUsage.user_id == user.id)
        )
        audit_counts[user.id] = count_result.scalar() or 0

    # 系统总 Token
    total_result = await db.execute(
        select(func.sum(TokenUsage.total_tokens))
    )
    system_total = total_result.scalar() or 0

    return AllUsersTokenStatsResponse(
        users=[
            UserTokenStatsItem(
                user_id=u.id,
                username=u.username,
                role=u.role.value,
                token_quota=u.token_quota,
                tokens_used=u.tokens_used or 0,
                remaining=None if u.token_quota is None else max(0, u.token_quota - (u.tokens_used or 0)),
                is_unlimited=u.token_quota is None,
                audit_count=audit_counts.get(u.id, 0),
            )
            for u in users
        ],
        system_total_tokens=system_total,
    )


@router.get("/{user_id}/token-quota", response_model=TokenQuotaResponse)
async def get_user_token_quota(
    user_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """获取指定用户 Token 额度（管理员）"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    is_unlimited = user.token_quota is None
    remaining = None if is_unlimited else max(0, user.token_quota - (user.tokens_used or 0))
    usage_percent = None if is_unlimited else (
        ((user.tokens_used or 0) / user.token_quota * 100) if user.token_quota > 0 else 100
    )

    return TokenQuotaResponse(
        token_quota=user.token_quota,
        tokens_used=user.tokens_used or 0,
        remaining=remaining,
        is_unlimited=is_unlimited,
        usage_percent=round(usage_percent, 2) if usage_percent is not None else None,
    )


@router.post("/{user_id}/token-quota")
async def set_user_token_quota(
    user_id: str,
    req: TokenQuotaUpdateRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """设置用户 Token 额度（管理员，包括设置自己的额度）"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    user.token_quota = req.token_quota
    quota_str = "无限" if req.token_quota is None else f"{req.token_quota:,}"
    return {
        "message": f"Token 额度已更新为 {quota_str}",
        "user_id": user_id,
        "token_quota": req.token_quota,
    }


@router.post("/{user_id}/reset-token-usage")
async def reset_user_token_usage(
    user_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """重置用户已使用 Token（管理员）"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    old_usage = user.tokens_used or 0
    user.tokens_used = 0
    return {
        "message": f"已重置 Token 使用量 (从 {old_usage:,} 重置为 0)",
        "user_id": user_id,
        "old_usage": old_usage,
    }


@router.get("/{user_id}/token-usage", response_model=TokenUsageListResponse)
async def get_user_token_usage(
    user_id: str,
    limit: int = 50,
    offset: int = 0,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """获取指定用户 Token 使用记录（管理员）"""
    # 检查用户存在
    user_result = await db.execute(select(User).where(User.id == user_id))
    if not user_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="用户不存在")

    # 查询使用记录
    result = await db.execute(
        select(TokenUsage)
        .where(TokenUsage.user_id == user_id)
        .order_by(TokenUsage.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    records = result.scalars().all()

    # 统计总量
    count_result = await db.execute(
        select(func.count(TokenUsage.id), func.sum(TokenUsage.total_tokens))
        .where(TokenUsage.user_id == user_id)
    )
    count_row = count_result.one()
    total_count = count_row[0] or 0
    total_tokens = count_row[1] or 0

    return TokenUsageListResponse(
        records=[
            TokenUsageRecord(
                id=r.id,
                project_id=r.project_id,
                project_name=r.project_name,
                audit_id=r.audit_id,
                prompt_tokens=r.prompt_tokens or 0,
                completion_tokens=r.completion_tokens or 0,
                total_tokens=r.total_tokens or 0,
                agent_breakdown=r.agent_breakdown or {},
                audit_status=r.audit_status,
                created_at=r.created_at.isoformat(),
            )
            for r in records
        ],
        total_count=total_count,
        total_tokens=total_tokens,
    )

# =============================================================================
# Token 使用量趋势统计 (用户)
# =============================================================================

@router.get("/me/token-stats/trend")
async def get_my_token_trend(
    time_range: str = "week",  # day/week/month
    limit: int = 30,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """获取当前用户的 Token 使用量趋势"""
    data = await get_token_usage_trend(db, user.id, time_range, limit)
    return {"data": data}


@router.get("/me/token-stats/by-project")
async def get_my_token_by_project(
    limit: int = 10,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """获取当前用户按项目统计的 Token 使用量"""
    data = await get_token_usage_by_project(db, user.id, limit)
    return {"data": data}


@router.get("/me/token-stats/by-agent")
async def get_my_token_by_agent(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """获取当前用户按 Agent 统计的 Token 使用量"""
    data = await get_token_usage_by_agent(db, user.id)
    return {"data": data}
