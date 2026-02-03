"""
初始化数据库脚本
直接使用 SQLAlchemy 创建所有表
"""
import asyncio
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy.ext.asyncio import create_async_engine
from src.storage.database import Base, User
from src.api.auth.password import hash_password


async def init_db():
    """初始化数据库"""
    print("🔄 初始化数据库...")

    # 创建数据库引擎
    db_path = project_root / "data" / "autospec.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        echo=False,
    )

    # 创建所有表
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("✅ 数据库表创建完成")

    # 创建默认管理员账号
    from src.storage.database import _get_session_factory

    session_factory = _get_session_factory()
    async with session_factory() as session:
        from sqlalchemy import select

        # 检查是否已存在 admin 用户
        result = await session.execute(select(User).where(User.username == "admin"))
        admin = result.scalar_one_or_none()

        if not admin:
            # 创建管理员账号
            from src.storage.database import UserRole

            admin = User(
                username="admin",
                password_hash=hash_password("admin123"),
                role=UserRole.ADMIN,
                password_must_change=True,  # 首次登录需要修改密码
                token_balance=1000000,  # 初始 100万 tokens
            )
            session.add(admin)
            await session.commit()
            print("✅ 创建默认管理员账号: admin / admin123 (首次登录需修改密码)")
        else:
            print("✅ 管理员账号已存在")

    await engine.dispose()
    print("✅ 数据库初始化完成！")


if __name__ == "__main__":
    asyncio.run(init_db())
