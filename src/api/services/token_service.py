"""
Token 额度管理服务

提供：
- 配额检查（审计前）
- 使用量记录（审计后）
- 用户额度更新
"""
from typing import Dict, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import User, TokenUsage, UserRole, PaymentMode
from ..auth import decrypt_api_keys


class TokenQuotaExceededError(Exception):
    """Token 额度超限异常"""
    def __init__(self, user_id: str, quota: int, used: int, required: int = 0):
        self.user_id = user_id
        self.quota = quota
        self.used = used
        self.required = required
        remaining = max(0, quota - used)
        super().__init__(
            f"Token 额度不足: 配额 {quota:,}, 已用 {used:,}, 剩余 {remaining:,}"
        )


class InsufficientBalanceError(Exception):
    """余额不足异常"""
    def __init__(self, balance: int, required: int):
        self.balance = balance
        self.required = required
        super().__init__(
            f"Token 余额不足: 当前余额 {balance:,}, 需要 {required:,}"
        )


async def check_audit_permission(
    db: AsyncSession,
    user_id: str,
) -> Tuple[bool, Optional[str]]:
    """
    检查用户是否允许启动审计

    检查逻辑：
    1. 如果是 own_key 模式：必须配置至少一个 API Key
    2. 如果是 platform_token 模式：必须有 Token 余额
    3. 如果两者都没有：拒绝审计

    Returns:
        (is_allowed, error_message)
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        return False, "用户不存在"

    if not user.is_active:
        return False, "用户已被禁用"

    # 检查付费模式
    if user.payment_mode == PaymentMode.OWN_KEY:
        # 检查是否配置了 API Key
        if not user.api_keys_encrypted:
            return False, "请先在用户设置中配置您的 API Key"

        keys = decrypt_api_keys(user.api_keys_encrypted)
        if not keys or not any(keys.values()):
            return False, "请先在用户设置中配置您的 API Key"

        return True, None

    elif user.payment_mode == PaymentMode.PLATFORM_TOKEN:
        # 检查 Token 余额
        if (user.token_balance or 0) <= 0:
            return False, "Token 余额不足，请先充值"

        return True, None

    return False, "未知的付费模式"


async def check_token_quota(
    db: AsyncSession,
    user_id: str,
    estimated_tokens: int = 0,
) -> Tuple[bool, Optional[str]]:
    """
    检查用户 Token 额度是否足够

    Args:
        db: 数据库会话
        user_id: 用户 ID
        estimated_tokens: 预估需要的 tokens（可选，用于预检查）

    Returns:
        (is_allowed, error_message)
        - is_allowed=True: 允许执行
        - is_allowed=False: 额度不足，error_message 包含原因
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        return False, "用户不存在"

    if not user.is_active:
        return False, "用户已被禁用"

    # 无限额度
    if user.token_quota is None:
        return True, None

    # 检查是否超限
    used = user.tokens_used or 0
    remaining = user.token_quota - used

    if remaining <= 0:
        return False, f"Token 额度已用尽 (配额: {user.token_quota:,}, 已用: {used:,})"

    if estimated_tokens > 0 and remaining < estimated_tokens:
        return False, f"Token 额度可能不足 (剩余: {remaining:,}, 预估需要: {estimated_tokens:,})"

    return True, None


async def record_token_usage(
    db: AsyncSession,
    user_id: str,
    total_tokens: int,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    agent_breakdown: Optional[Dict] = None,
    project_id: Optional[str] = None,
    project_name: Optional[str] = None,
    audit_id: Optional[str] = None,
    audit_status: Optional[str] = None,
) -> TokenUsage:
    """
    记录 Token 使用量（根据付费模式分别统计和扣费）

    Args:
        db: 数据库会话
        user_id: 用户 ID
        total_tokens: 总 tokens
        prompt_tokens: prompt tokens
        completion_tokens: completion tokens
        agent_breakdown: 各 agent 消耗明细
        project_id: 项目 ID
        project_name: 项目名称
        audit_id: 审计 ID
        audit_status: 审计状态

    Returns:
        创建的 TokenUsage 记录

    Raises:
        InsufficientBalanceError: platform_token 模式下余额不足
    """
    # 获取用户
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise ValueError(f"用户不存在: {user_id}")

    # 根据付费模式处理
    if user.payment_mode == PaymentMode.PLATFORM_TOKEN:
        # 检查余额
        if (user.token_balance or 0) < total_tokens:
            raise InsufficientBalanceError(user.token_balance or 0, total_tokens)

        # 扣除余额
        user.token_balance = (user.token_balance or 0) - total_tokens
        # 更新 platform 模式消耗
        user.tokens_used_platform = (user.tokens_used_platform or 0) + total_tokens

    elif user.payment_mode == PaymentMode.OWN_KEY:
        # 更新 own_key 模式消耗（不扣余额）
        user.tokens_used_own_key = (user.tokens_used_own_key or 0) + total_tokens

    # 更新总消耗
    user.tokens_used = (user.tokens_used or 0) + total_tokens

    # 创建使用记录
    usage = TokenUsage(
        user_id=user_id,
        project_id=project_id,
        audit_id=audit_id,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        agent_breakdown=agent_breakdown or {},
        project_name=project_name,
        audit_status=audit_status,
    )
    db.add(usage)

    await db.flush()
    return usage


async def get_user_remaining_quota(
    db: AsyncSession,
    user_id: str,
) -> Optional[int]:
    """
    获取用户剩余额度

    Returns:
        剩余额度，None 表示无限
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or user.token_quota is None:
        return None  # 无限

    return max(0, user.token_quota - (user.tokens_used or 0))


def format_token_stats(agent_stats: Dict[str, Dict]) -> Dict:
    """
    格式化 agent token 统计为存储格式

    Args:
        agent_stats: 从 engine 获取的统计
        {
            "analyst": {"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200, "call_count": 2},
            ...
        }

    Returns:
        格式化的字典，用于存储到 agent_breakdown
    """
    formatted = {}
    for agent_name, stats in agent_stats.items():
        formatted[agent_name] = {
            "prompt": stats.get("prompt_tokens", 0),
            "completion": stats.get("completion_tokens", 0),
            "total": stats.get("total_tokens", 0),
            "calls": stats.get("call_count", 0),
        }
    return formatted
