"""
API 配置模块
"""
from pathlib import Path
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """API 配置"""

    # 应用信息
    app_name: str = "AutoSpec API"
    app_version: str = "0.1.0"
    debug: bool = True

    # 数据库
    database_url: str = "sqlite+aiosqlite:///./data/autospec.db"

    # 项目存储路径
    projects_dir: Path = Path("./data/projects")
    reports_dir: Path = Path("./reports/security_audits")

    # CORS 配置
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # LLM API Keys (从环境变量读取)
    dashscope_api_key: str = ""

    # JWT 配置
    jwt_secret_key: str = "autospec-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15  # 15 minutes (短期 token)
    jwt_refresh_token_expire_days: int = 7  # 7 days (长期 refresh token)

    # API Key 加密密钥 (Fernet, 生成: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    api_keys_encryption_key: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # 忽略 .env 中的额外字段


@lru_cache
def get_settings() -> Settings:
    """获取配置单例"""
    return Settings()
