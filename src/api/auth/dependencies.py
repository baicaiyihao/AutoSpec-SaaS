"""FastAPI 认证依赖"""
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db, User, UserRole
from .jwt import verify_token

security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """获取当前认证用户（必须登录）"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登录",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token 无效或已过期",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token 无效")

    result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户不存在或已禁用")

    return user


async def get_current_admin(user: User = Depends(get_current_user)) -> User:
    """获取当前管理员用户（必须是 admin 角色）"""
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="需要管理员权限",
        )
    return user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """可选获取用户（兼容未登录场景，迁移过渡用）"""
    if not credentials:
        return None
    payload = verify_token(credentials.credentials)
    if not payload:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    return result.scalar_one_or_none()
