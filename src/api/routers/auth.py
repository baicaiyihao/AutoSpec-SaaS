"""
认证路由 (登录/注册/当前用户)
"""
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db, User, UserRole, SystemSettings, RefreshToken
from ..auth import create_access_token, hash_password, verify_password
from ..auth.jwt import create_refresh_token
from ..auth.dependencies import get_current_user
from ..auth.captcha import captcha_store, generate_captcha_image
from ..auth.password_validator import validate_password_strength

router = APIRouter(prefix="/auth", tags=["auth"])


# =============================================================================
# 请求/响应模型
# =============================================================================

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=1)
    captcha_id: str | None = None  # 验证码 ID（如果启用）
    captcha_code: str | None = None  # 用户输入的验证码


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=6, max_length=100)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str = ""  # 🔥 Refresh token (长期)
    token_type: str = "bearer"
    user: "UserInfoResponse"
    pending: bool = False
    password_must_change: bool = False  # 🔥 是否需要强制修改密码


class UserInfoResponse(BaseModel):
    id: str
    username: str
    role: str
    is_active: bool
    wallet_address: str | None
    token_balance: int
    tokens_used: int
    tokens_used_own_key: int
    tokens_used_platform: int
    payment_mode: str
    created_at: str

    class Config:
        from_attributes = True


# =============================================================================
# 路由
# =============================================================================

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    """用户登录"""
    # 1. 读取系统配置
    result = await db.execute(
        select(SystemSettings).where(
            SystemSettings.key.in_([
                "enable_login_captcha",
                "jwt_access_token_expire_minutes",
                "jwt_refresh_token_expire_days"
            ])
        )
    )
    settings_list = result.scalars().all()
    settings_dict = {s.key: s.value for s in settings_list}

    captcha_enabled = settings_dict.get("enable_login_captcha") == "true"
    access_expire_minutes = int(settings_dict.get("jwt_access_token_expire_minutes", "15"))
    refresh_expire_days = int(settings_dict.get("jwt_refresh_token_expire_days", "7"))

    # 2. 如果启用验证码，先验证验证码
    if captcha_enabled:
        if not req.captcha_id or not req.captcha_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="请输入验证码",
            )
        if not captcha_store.verify(req.captcha_id, req.captcha_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="验证码错误或已过期",
            )

    # 3. 验证用户名密码
    result = await db.execute(
        select(User).where(User.username == req.username)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账户已被禁用",
        )

    # 生成 access token 和 refresh token（使用数据库配置）
    access_token = create_access_token(user.id, user.role.value, access_expire_minutes)
    refresh_token, expires_at = create_refresh_token(user.id, refresh_expire_days)

    # 保存 refresh token 到数据库
    db_refresh_token = RefreshToken(
        user_id=user.id,
        token=refresh_token,
        expires_at=expires_at,
    )
    db.add(db_refresh_token)
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,  # 🔥 返回 refresh token
        user=UserInfoResponse(
            id=user.id,
            username=user.username,
            role=user.role.value,
            is_active=user.is_active,
            wallet_address=user.wallet_address,
            token_balance=user.token_balance,
            tokens_used=user.tokens_used,
            tokens_used_own_key=user.tokens_used_own_key or 0,
            tokens_used_platform=user.tokens_used_platform or 0,
            payment_mode=user.payment_mode.value,
            created_at=user.created_at.isoformat(),
        ),
        password_must_change=user.password_must_change,  # 🔥 是否需要强制修改密码
    )


@router.post("/register", response_model=TokenResponse)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """用户注册"""
    # 1. 验证密码强度
    is_valid, errors = validate_password_strength(req.password, min_length=8)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"密码强度不足: {', '.join(errors)}",
        )

    # 2. 检查用户名是否已存在
    result = await db.execute(
        select(User).where(User.username == req.username)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="用户名已存在",
        )

    # 3. 读取系统配置
    result = await db.execute(
        select(SystemSettings).where(
            SystemSettings.key.in_([
                "registration_mode",
                "jwt_access_token_expire_minutes",
                "jwt_refresh_token_expire_days"
            ])
        )
    )
    settings_list = result.scalars().all()
    settings_dict = {s.key: s.value for s in settings_list}

    registration_mode = settings_dict.get("registration_mode", "open")
    access_expire_minutes = int(settings_dict.get("jwt_access_token_expire_minutes", "15"))
    refresh_expire_days = int(settings_dict.get("jwt_refresh_token_expire_days", "7"))

    # review 模式: 新用户默认禁用，需管理员审核
    need_review = registration_mode == "review"

    user = User(
        username=req.username,
        password_hash=hash_password(req.password),
        role=UserRole.USER,
        is_active=not need_review,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    # 生成 token（如果不需要审核，使用数据库配置）
    access_token = ""
    refresh_token_str = ""
    if not need_review:
        access_token = create_access_token(user.id, user.role.value, access_expire_minutes)
        refresh_token_str, expires_at = create_refresh_token(user.id, refresh_expire_days)
        db_refresh_token = RefreshToken(
            user_id=user.id,
            token=refresh_token_str,
            expires_at=expires_at,
        )
        db.add(db_refresh_token)

    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,  # 🔥 返回 refresh token
        user=UserInfoResponse(
            id=user.id,
            username=user.username,
            role=user.role.value,
            is_active=user.is_active,
            wallet_address=user.wallet_address,
            token_balance=user.token_balance,
            tokens_used=user.tokens_used,
            tokens_used_own_key=user.tokens_used_own_key or 0,
            tokens_used_platform=user.tokens_used_platform or 0,
            payment_mode=user.payment_mode.value,
            created_at=user.created_at.isoformat(),
        ),
        pending=need_review,
    )


@router.get("/me", response_model=UserInfoResponse)
async def get_me(user: User = Depends(get_current_user)):
    """获取当前用户信息"""
    return UserInfoResponse(
        id=user.id,
        username=user.username,
        role=user.role.value,
        is_active=user.is_active,
        wallet_address=user.wallet_address,
        token_balance=user.token_balance,
        tokens_used=user.tokens_used,
        tokens_used_own_key=user.tokens_used_own_key or 0,
        tokens_used_platform=user.tokens_used_platform or 0,
        payment_mode=user.payment_mode.value,
        created_at=user.created_at.isoformat(),
    )


@router.get("/captcha-config")
async def get_captcha_config(db: AsyncSession = Depends(get_db)):
    """获取验证码配置"""
    result = await db.execute(
        select(SystemSettings).where(SystemSettings.key == "enable_login_captcha")
    )
    setting = result.scalar_one_or_none()
    enabled = setting.value == "true" if setting else False
    return {"enabled": enabled}


@router.get("/captcha")
async def get_captcha():
    """生成验证码图片

    Returns:
        PNG 图片 + captcha_id（在响应头中）
    """
    captcha_id, code = captcha_store.generate()
    image_bytes = generate_captcha_image(code)

    return Response(
        content=image_bytes,
        media_type="image/png",
        headers={"X-Captcha-Id": captcha_id},
    )


# =============================================================================
# Refresh Token 刷新
# =============================================================================

class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """使用 refresh token 刷新 access token"""
    from datetime import datetime, timezone

    # 1. 读取 JWT 配置
    result = await db.execute(
        select(SystemSettings).where(
            SystemSettings.key == "jwt_access_token_expire_minutes"
        )
    )
    setting = result.scalar_one_or_none()
    access_expire_minutes = int(setting.value) if setting else 15

    # 2. 查询 refresh token
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token == req.refresh_token)
    )
    db_token = result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的 refresh token",
        )

    # 3. 检查是否已撤销
    if db_token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token 已被撤销",
        )

    # 4. 检查是否过期
    if datetime.now(timezone.utc) > db_token.expires_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token 已过期",
        )

    # 5. 查询用户信息
    result = await db.execute(
        select(User).where(User.id == db_token.user_id)
    )
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户不存在或已被禁用",
        )

    # 6. 生成新的 access token（使用数据库配置）
    new_access_token = create_access_token(user.id, user.role.value, access_expire_minutes)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=req.refresh_token,  # 返回原 refresh token（或生成新的）
        user=UserInfoResponse(
            id=user.id,
            username=user.username,
            role=user.role.value,
            is_active=user.is_active,
            wallet_address=user.wallet_address,
            token_balance=user.token_balance,
            tokens_used=user.tokens_used,
            tokens_used_own_key=user.tokens_used_own_key or 0,
            tokens_used_platform=user.tokens_used_platform or 0,
            payment_mode=user.payment_mode.value,
            created_at=user.created_at.isoformat(),
        ),
    )


@router.post("/logout")
async def logout(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """退出登录（撤销 refresh token）"""
    from datetime import datetime, timezone

    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token == req.refresh_token)
    )
    db_token = result.scalar_one_or_none()

    if db_token and not db_token.is_revoked:
        db_token.is_revoked = True
        db_token.revoked_at = datetime.now(timezone.utc)
        await db.commit()

    return {"message": "已退出登录"}


# =============================================================================
# 钱包登录（Sui Wallet）
# =============================================================================

from ..auth.wallet import (
    generate_challenge,
    verify_wallet_signature,
    validate_challenge_message,
    WalletChallenge,
    WalletVerifyRequest,
    WalletBindRequest,
)


@router.post("/wallet/challenge", response_model=WalletChallenge)
async def get_wallet_challenge(wallet_address: str = Body(..., embed=True)):
    """
    生成钱包签名挑战

    Args:
        wallet_address: Sui 钱包地址（0x + 64 hex）

    Returns:
        WalletChallenge: 挑战消息（需要用户签名）
    """
    if not wallet_address.startswith("0x") or len(wallet_address) != 66:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的钱包地址格式（应为 0x + 64 hex）",
        )

    return generate_challenge(wallet_address)


@router.post("/wallet/verify", response_model=TokenResponse)
async def verify_wallet_login(req: WalletVerifyRequest, db: AsyncSession = Depends(get_db)):
    """
    验证钱包签名并登录

    如果钱包地址未注册，自动创建新账户。
    如果已注册，直接登录。

    Args:
        req: 签名验证请求

    Returns:
        TokenResponse: JWT tokens
    """
    # 1. 验证挑战消息有效性
    if not validate_challenge_message(req.message, req.wallet_address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="挑战消息无效或已过期",
        )

    # 2. 验证签名
    try:
        if not verify_wallet_signature(
            req.message,
            req.signature,
            req.public_key,
            req.wallet_address
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="签名验证失败",
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # 3. 读取系统配置
    result = await db.execute(
        select(SystemSettings).where(
            SystemSettings.key.in_([
                "jwt_access_token_expire_minutes",
                "jwt_refresh_token_expire_days"
            ])
        )
    )
    settings_list = result.scalars().all()
    settings_dict = {s.key: s.value for s in settings_list}

    access_expire_minutes = int(settings_dict.get("jwt_access_token_expire_minutes", "15"))
    refresh_expire_days = int(settings_dict.get("jwt_refresh_token_expire_days", "7"))

    # 4. 查找或创建用户
    result = await db.execute(
        select(User).where(User.wallet_address == req.wallet_address.lower())
    )
    user = result.scalar_one_or_none()

    if not user:
        # 自动创建新用户（钱包地址作为用户名）
        user = User(
            username=f"wallet_{req.wallet_address[:10]}",  # wallet_0xabcd1234
            password_hash=hash_password(req.wallet_address),  # 随机密码
            wallet_address=req.wallet_address.lower(),
            role=UserRole.USER,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账户已被禁用",
        )

    # 5. 生成 tokens
    access_token = create_access_token(user.id, user.role.value, access_expire_minutes)
    refresh_token_str, expires_at = create_refresh_token(user.id, refresh_expire_days)

    db_refresh_token = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=expires_at,
    )
    db.add(db_refresh_token)
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        user=UserInfoResponse(
            id=user.id,
            username=user.username,
            role=user.role.value,
            is_active=user.is_active,
            wallet_address=user.wallet_address,
            token_balance=user.token_balance,
            tokens_used=user.tokens_used,
            tokens_used_own_key=user.tokens_used_own_key or 0,
            tokens_used_platform=user.tokens_used_platform or 0,
            payment_mode=user.payment_mode.value,
            created_at=user.created_at.isoformat(),
        ),
    )


@router.post("/wallet/bind")
async def bind_wallet(
    req: WalletBindRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    绑定钱包到已有账户

    需要用户已登录（通过邮箱/密码）

    Args:
        req: 签名验证请求
        user: 当前登录用户

    Returns:
        成功消息
    """
    # 1. 验证挑战消息
    if not validate_challenge_message(req.message, req.wallet_address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="挑战消息无效或已过期",
        )

    # 2. 验证签名
    try:
        if not verify_wallet_signature(
            req.message,
            req.signature,
            req.public_key,
            req.wallet_address
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="签名验证失败",
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # 3. 检查钱包是否已被其他用户绑定
    result = await db.execute(
        select(User).where(User.wallet_address == req.wallet_address.lower())
    )
    existing_user = result.scalar_one_or_none()

    if existing_user and existing_user.id != user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="该钱包已绑定到其他账户",
        )

    # 4. 绑定钱包
    user.wallet_address = req.wallet_address.lower()
    await db.commit()

    return {
        "message": "钱包绑定成功",
        "wallet_address": req.wallet_address.lower(),
    }
