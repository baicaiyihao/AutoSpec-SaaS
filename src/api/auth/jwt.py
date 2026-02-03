"""JWT token 创建与验证"""
from datetime import datetime, timedelta, timezone
from typing import Optional
import secrets
from jose import JWTError, jwt
from ..config import get_settings


def create_access_token(user_id: str, role: str, expire_minutes: Optional[int] = None) -> str:
    """创建 access token

    Args:
        user_id: 用户 ID
        role: 用户角色
        expire_minutes: 过期时间（分钟），如果为 None 则使用配置文件默认值
    """
    settings = get_settings()
    if expire_minutes is None:
        expire_minutes = settings.jwt_access_token_expire_minutes
    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    payload = {
        "sub": user_id,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def verify_token(token: str) -> Optional[dict]:
    """验证 token，返回 payload 或 None"""
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError:
        return None


def create_refresh_token(user_id: str, expire_days: Optional[int] = None) -> tuple[str, datetime]:
    """创建 refresh token

    Args:
        user_id: 用户 ID
        expire_days: 过期时间（天），如果为 None 则使用配置文件默认值

    Returns:
        (token, expires_at): 随机 token 和过期时间
    """
    settings = get_settings()
    if expire_days is None:
        expire_days = settings.jwt_refresh_token_expire_days
    token = secrets.token_urlsafe(64)  # 生成随机 token
    expires_at = datetime.now(timezone.utc) + timedelta(days=expire_days)
    return token, expires_at
