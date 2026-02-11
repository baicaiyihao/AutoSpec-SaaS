"""
数据库模型与连接管理

使用 SQLAlchemy 2.0 异步模式
"""
import uuid
from datetime import datetime, timezone


def utc_now():
    """返回当前 UTC 时间 (timezone-aware)"""
    return datetime.now(timezone.utc)
from enum import Enum as PyEnum
from typing import AsyncGenerator, Optional

from sqlalchemy import (
    Column,
    String,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Float,
    Enum,
    Integer,
    Boolean,
)
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)

from ..api.config import get_settings


# =============================================================================
# 枚举类型
# =============================================================================

class AuditStatus(str, PyEnum):
    """审计状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, PyEnum):
    """漏洞严重性"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ADVISORY = "advisory"


class FindingStatus(str, PyEnum):
    """漏洞状态"""
    OPEN = "open"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    FIXED = "fixed"


class ReviewActionType(str, PyEnum):
    """Review 操作类型"""
    CONFIRM = "confirm"
    REJECT = "reject"
    DOWNGRADE = "downgrade"
    UPGRADE = "upgrade"
    ADD_NOTE = "add_note"


class UserRole(str, PyEnum):
    """用户角色"""
    ADMIN = "admin"
    USER = "user"


class PaymentMode(str, PyEnum):
    """Token 付费模式"""
    OWN_KEY = "own_key"                    # 用户自己的 API Key，直接付费给 LLM 供应商
    PLATFORM_TOKEN = "platform_token"      # 使用平台共享 Key，扣除购买的 Token 余额


class FindingMarkType(str, PyEnum):
    """漏洞标记类型"""
    ISSUE = "issue"              # 是问题
    NOT_ISSUE = "not_issue"      # 不是问题
    LEGACY = "legacy"            # 遗留问题


class Blockchain(str, PyEnum):
    """支持的区块链"""
    SUI = "sui"                # Sui Move
    # 后续可扩展：
    # APTOS = "aptos"          # Aptos Move
    # SOLANA = "solana"        # Solana Rust
    # COMMON = "common"        # 通用规则


class RuleCategory(str, PyEnum):
    """规则分类"""
    LANGUAGE_PROTECTION = "language_protection"  # 语言级保护
    ACCESS_CONTROL = "access_control"            # 访问控制
    ARITHMETIC = "arithmetic"                    # 算术安全
    RESOURCE_SAFETY = "resource_safety"          # 资源安全
    DESIGN_PATTERN = "design_pattern"            # 设计模式
    CODE_QUALITY = "code_quality"                # 代码质量
    DEFI_SPECIFIC = "defi_specific"              # DeFi 特定
    PRODUCTION_PATTERN = "production_pattern"    # 生产合约模式
    SEMANTIC = "semantic"                        # 语义分析
    CUSTOM = "custom"                            # 自定义


# =============================================================================
# 基类
# =============================================================================

class Base(DeclarativeBase):
    """SQLAlchemy 基类"""
    pass


def generate_uuid() -> str:
    """生成 UUID"""
    return str(uuid.uuid4())


# =============================================================================
# 数据模型
# =============================================================================

class User(Base):
    """用户表"""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(100), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)

    # 用户级配置
    api_keys_encrypted = Column(Text, nullable=True)  # Fernet 加密的 JSON
    audit_config = Column(JSON, default=dict)          # {model_preset, agent_architecture, ...}
    allow_shared_api_keys = Column(Boolean, default=True, nullable=False)  # 是否允许使用管理员共享的 API Keys

    # 🔥 Web3 钱包（SaaS 模式）
    wallet_address = Column(String(66), nullable=True, unique=True, index=True)  # Sui 钱包地址 (0x + 64 hex)

    # 🔥 Token 额度管理（单位：LLM tokens）
    token_quota = Column(Integer, nullable=True)       # 配额上限 (NULL = 无限)，单位：LLM tokens
    tokens_used = Column(Integer, default=0)           # 累计已使用 LLM tokens（所有模式总计）
    tokens_used_own_key = Column(Integer, default=0)   # 使用自己 API Key 的 token 消耗
    tokens_used_platform = Column(Integer, default=0)  # 使用平台 Token 的消耗
    token_balance = Column(Integer, default=0)         # 当前可用 LLM tokens 余额（充值获得）
    payment_mode = Column(Enum(PaymentMode), default=PaymentMode.OWN_KEY, nullable=False)  # Token 付费模式

    # 🔥 安全配置
    password_must_change = Column(Boolean, default=False)  # 是否强制修改密码（首次登录/重置密码后）

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # 关系
    projects = relationship("Project", back_populates="owner")
    audits = relationship("Audit", back_populates="owner")
    token_usages = relationship("TokenUsage", back_populates="user")

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"


class RefreshToken(Base):
    """Refresh Token 表（用于 JWT 刷新机制）"""
    __tablename__ = "refresh_tokens"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String(500), unique=True, nullable=False, index=True)  # Refresh token
    expires_at = Column(DateTime, nullable=False, index=True)  # 过期时间
    is_revoked = Column(Boolean, default=False)  # 是否已撤销
    created_at = Column(DateTime, default=utc_now)
    revoked_at = Column(DateTime, nullable=True)  # 撤销时间

    # 关系
    user = relationship("User", backref="refresh_tokens")

    def __repr__(self):
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, revoked={self.is_revoked})>"


class SystemSettings(Base):
    """全局系统设置表（管理员管理）"""
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=False)
    value_type = Column(String(20), default="string")  # string, int, float, bool, json
    category = Column(String(50), nullable=False)
    description = Column(String(500), nullable=True)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
    updated_by = Column(String(36), nullable=True)

    def __repr__(self):
        return f"<SystemSettings(key={self.key})>"


class Project(Base):
    """项目表"""
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_path = Column(String(512), nullable=False)  # Move 项目路径
    blockchain = Column(Enum(Blockchain), nullable=True)  # 所属链（用户选择）
    file_count = Column(Integer, default=0)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # 关系
    owner = relationship("User", back_populates="projects")
    audits = relationship("Audit", back_populates="project", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Project(id={self.id}, name={self.name})>"


class Audit(Base):
    """审计任务表"""
    __tablename__ = "audits"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    status = Column(Enum(AuditStatus), default=AuditStatus.PENDING)

    # 配置
    config = Column(JSON, default=dict)  # 审计配置
    progress = Column(JSON, default=dict)  # 进度信息

    # 时间
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # 错误信息
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, default=utc_now)

    # 关系
    owner = relationship("User", back_populates="audits")
    project = relationship("Project", back_populates="audits")
    report = relationship("Report", back_populates="audit", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Audit(id={self.id}, status={self.status})>"


class Report(Base):
    """审计报告表"""
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id"), nullable=False, unique=True)

    # 报告内容
    findings = Column(JSON, default=list)  # 漏洞列表
    summary = Column(JSON, default=dict)   # 摘要信息
    risk_score = Column(Float, default=0.0)

    # 统计
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    advisory_count = Column(Integer, default=0)

    # 报告文件路径
    report_path = Column(String(512), nullable=True)  # Markdown 报告路径

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # 关系
    audit = relationship("Audit", back_populates="report")
    review_sessions = relationship("ReviewSession", back_populates="report", cascade="all, delete-orphan")
    finding_marks = relationship("FindingMark", back_populates="report", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Report(id={self.id}, total_findings={self.total_findings})>"


class ReviewSession(Base):
    """Review 会话表"""
    __tablename__ = "review_sessions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.id"), nullable=False)

    # 聚焦的漏洞
    focused_finding_id = Column(String(64), nullable=True)

    # 状态
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # 关系
    report = relationship("Report", back_populates="review_sessions")
    messages = relationship("ReviewMessage", back_populates="session", cascade="all, delete-orphan")
    actions = relationship("ReviewAction", back_populates="session", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ReviewSession(id={self.id}, is_active={self.is_active})>"


class ReviewMessage(Base):
    """Review 消息表"""
    __tablename__ = "review_messages"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    session_id = Column(String(36), ForeignKey("review_sessions.id"), nullable=False)

    role = Column(String(20), nullable=False)  # user, assistant, system
    content = Column(Text, nullable=False)
    extra_data = Column(JSON, nullable=True)  # 工具调用结果、代码引用等

    created_at = Column(DateTime, default=utc_now)

    # 关系
    session = relationship("ReviewSession", back_populates="messages")

    def __repr__(self):
        return f"<ReviewMessage(id={self.id}, role={self.role})>"


class ReviewAction(Base):
    """Review 操作记录表"""
    __tablename__ = "review_actions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    session_id = Column(String(36), ForeignKey("review_sessions.id"), nullable=False)

    finding_id = Column(String(64), nullable=False)
    action_type = Column(Enum(ReviewActionType), nullable=False)

    # 变更记录
    from_value = Column(String(50), nullable=True)  # 原值
    to_value = Column(String(50), nullable=True)    # 新值
    reason = Column(Text, nullable=True)            # 操作理由
    ai_analysis = Column(Text, nullable=True)       # AI 分析结论

    created_at = Column(DateTime, default=utc_now)

    # 关系
    session = relationship("ReviewSession", back_populates="actions")

    def __repr__(self):
        return f"<ReviewAction(id={self.id}, action_type={self.action_type})>"


class FindingMark(Base):
    """漏洞审计标记表"""
    __tablename__ = "finding_marks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.id"), nullable=False)
    finding_id = Column(String(64), nullable=False)

    # 标记信息
    mark_type = Column(Enum(FindingMarkType), nullable=False)
    severity = Column(String(20), nullable=True)  # high, medium (仅 mark_type=issue 时)
    note = Column(Text, nullable=True)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # 关系
    report = relationship("Report", back_populates="finding_marks")

    def __repr__(self):
        return f"<FindingMark(id={self.id}, finding_id={self.finding_id}, mark_type={self.mark_type})>"


class SystemRule(Base):
    """系统规则元数据表（逻辑在 Python 代码中）"""
    __tablename__ = "system_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)       # check_overflow_bypass
    display_name = Column(String(200), nullable=False)            # 算术溢出保护
    description = Column(Text, nullable=True)
    blockchain = Column(Enum(Blockchain), nullable=True)          # 所属链（NULL=通用）
    category = Column(Enum(RuleCategory), nullable=False)

    # 状态控制
    is_enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=100)  # 执行优先级，数字越小越先执行

    # 统计
    trigger_count = Column(Integer, default=0)          # 触发次数
    last_triggered_at = Column(DateTime, nullable=True) # 最后触发时间

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    def __repr__(self):
        return f"<SystemRule(name={self.name}, enabled={self.is_enabled})>"


class CustomExclusion(Base):
    """用户自定义排除规则表（简单模式匹配）"""
    __tablename__ = "custom_exclusions"

    id = Column(String(36), primary_key=True, default=generate_uuid)

    # 归属
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=True)  # NULL = 全局
    blockchain = Column(Enum(Blockchain), nullable=True)  # 所属链（NULL=通用）

    # 规则定义
    name = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)

    # 匹配条件 (JSON)
    match_config = Column(JSON, nullable=False)
    """
    match_config 结构:
    {
        "title_contains": ["test", "mock"],           # 标题包含任一
        "description_contains": ["helper"],           # 描述包含任一
        "function_pattern": "^test_|_mock$",          # 函数名正则
        "file_pattern": "tests/.*",                   # 文件路径正则
        "severity_in": ["LOW", "ADVISORY"],           # 严重性范围
        "match_all": false                            # true=全部满足, false=任一满足
    }
    """

    is_enabled = Column(Boolean, default=True)

    # 统计
    trigger_count = Column(Integer, default=0)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # 关系
    owner = relationship("User")
    project = relationship("Project")

    def __repr__(self):
        return f"<CustomExclusion(name={self.name}, owner={self.owner_id})>"


class TokenUsage(Base):
    """
    Token 使用记录表

    记录每次审计的 token 消耗，用于：
    - 用户额度管理（管理员配置所有用户额度）
    - 项目成本追踪
    - 系统使用统计
    """
    __tablename__ = "token_usages"

    id = Column(String(36), primary_key=True, default=generate_uuid)

    # 关联
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=True, index=True)
    audit_id = Column(String(36), ForeignKey("audits.id"), nullable=True, index=True)

    # Token 统计
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)

    # 详细分解 (各 agent 消耗)
    agent_breakdown = Column(JSON, default=dict)
    """
    agent_breakdown 结构:
    {
        "analyst": {"prompt": 1000, "completion": 200, "total": 1200, "calls": 2},
        "auditor": {"prompt": 2000, "completion": 500, "total": 2500, "calls": 5},
        "verifier": {"prompt": 5000, "completion": 1000, "total": 6000, "calls": 10},
        "white_hat": {"prompt": 3000, "completion": 800, "total": 3800, "calls": 8}
    }
    """

    # 审计信息快照
    project_name = Column(String(255), nullable=True)  # 冗余存储，方便查询
    audit_status = Column(String(20), nullable=True)   # completed, failed, cancelled

    created_at = Column(DateTime, default=utc_now)

    # 关系
    user = relationship("User", back_populates="token_usages")
    project = relationship("Project")
    audit = relationship("Audit")

    def __repr__(self):
        return f"<TokenUsage(id={self.id}, user={self.user_id}, tokens={self.total_tokens})>"


class TokenPurchaseStatus(str, PyEnum):
    """Token 充值状态"""
    PENDING = "pending"       # 等待链上确认
    CONFIRMED = "confirmed"   # 已确认，Token 已充值
    FAILED = "failed"         # 失败（价格偏差过大、交易失败等）


class TokenPurchase(Base):
    """
    Token 充值记录表

    记录用户通过 SUI 充值 Token 的历史
    """
    __tablename__ = "token_purchases"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)

    # 区块链交易信息
    transaction_digest = Column(String(64), unique=True, nullable=False, index=True)  # Sui 交易哈希
    wallet_address = Column(String(66), nullable=False)  # 买家钱包地址

    # 支付金额
    sui_amount = Column(Integer, nullable=False)    # 支付的 SUI 数量（MIST，1 SUI = 10^9 MIST）
    usd_amount = Column(Integer, nullable=False)    # 对应的 USD 金额（美分，1 USD = 100 cents）
    sui_usd_price = Column(Float, nullable=False)   # 当时的 SUI/USD 汇率

    # Token 信息
    token_amount = Column(Integer, nullable=False)  # 获得的 LLM tokens 数量
    token_usd_price = Column(Float, nullable=False) # 当时的 LLM tokens 单价 (USD per 1K tokens)

    # 状态
    status = Column(Enum(TokenPurchaseStatus), default=TokenPurchaseStatus.PENDING, nullable=False)
    error_message = Column(Text, nullable=True)     # 失败原因

    # 时间戳
    blockchain_timestamp = Column(DateTime, nullable=True)  # 链上时间戳
    confirmed_at = Column(DateTime, nullable=True)          # 后端确认时间
    created_at = Column(DateTime, default=utc_now)

    # 关系
    user = relationship("User")

    def __repr__(self):
        return f"<TokenPurchase(id={self.id}, user={self.user_id}, tokens={self.token_amount}, status={self.status})>"


# =============================================================================
# 数据库连接
# =============================================================================

# 引擎和会话工厂（延迟初始化）
_engine = None
_async_session_factory = None


def _get_engine():
    """获取数据库引擎"""
    global _engine
    if _engine is None:
        settings = get_settings()
        # SQLite-specific optimizations for concurrent access
        connect_args = {}
        if settings.database_url.startswith("sqlite"):
            connect_args = {
                "timeout": 30,  # 增加超时时间到 30 秒
                "check_same_thread": False,  # 允许多线程访问
            }
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            connect_args=connect_args,
        )
    return _engine


def _get_session_factory():
    """获取会话工厂"""
    global _async_session_factory
    if _async_session_factory is None:
        _async_session_factory = async_sessionmaker(
            bind=_get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _async_session_factory


async def _enable_wal_mode():
    """启用 SQLite WAL 模式（提高并发性能）"""
    settings = get_settings()
    if settings.database_url.startswith("sqlite"):
        engine = _get_engine()
        async with engine.begin() as conn:
            # 启用 WAL 模式
            await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            # 增加 busy_timeout
            await conn.exec_driver_sql("PRAGMA busy_timeout=30000")
        print("✅ SQLite WAL 模式已启用（提高并发性能）")


async def init_db():
    """初始化数据库（创建表）

    注意：此方法仅用于快速开发。生产环境建议使用 Alembic 进行数据库迁移：
    - 运行迁移: python scripts/migrate.py 或 alembic upgrade head
    - 创建迁移: python scripts/migrate.py revision
    """
    engine = _get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ 数据库初始化完成（建议使用 Alembic 进行迁移管理）")

    # 启用 WAL 模式
    await _enable_wal_mode()


async def seed_default_admin():
    """创建默认 admin 账户（如不存在）"""
    from ..api.auth.password import hash_password
    from sqlalchemy import select

    session_factory = _get_session_factory()
    async with session_factory() as session:
        result = await session.execute(
            select(User).where(User.username == "admin")
        )
        if result.scalar_one_or_none() is None:
            admin = User(
                username="admin",
                password_hash=hash_password("admin123"),
                role=UserRole.ADMIN,
                password_must_change=True,  # 🔥 首次登录强制修改密码
            )
            session.add(admin)
            await session.commit()
            print("✅ 默认管理员账户已创建 (admin / admin123) - 首次登录需修改密码")
        else:
            print("✅ 管理员账户已存在")

        # 种子系统规则
        from .seed_rules import seed_system_rules
        await seed_system_rules(session)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """获取数据库会话（依赖注入用）"""
    session_factory = _get_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
