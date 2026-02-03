"""
Token 统计服务 - 按时间维度聚合
"""
from datetime import datetime, timedelta
from typing import List, Dict, Any, Literal
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import TokenUsage


TimeRange = Literal["day", "week", "month"]


async def get_token_usage_trend(
    db: AsyncSession,
    user_id: str,
    time_range: TimeRange = "week",
    limit: int = 30
) -> List[Dict[str, Any]]:
    """获取 Token 使用量趋势数据

    Args:
        db: 数据库会话
        user_id: 用户 ID
        time_range: 时间范围 (day/week/month)
        limit: 返回数据点数量

    Returns:
        List[{"date": "2026-01-27", "tokens": 12345, "audits": 3}]
    """
    # 计算起始日期
    now = datetime.utcnow()
    if time_range == "day":
        start_date = now - timedelta(days=limit)
        date_format = "%Y-%m-%d"
    elif time_range == "week":
        start_date = now - timedelta(weeks=limit)
        date_format = "%Y-W%W"  # ISO week
    else:  # month
        start_date = now - timedelta(days=limit * 30)
        date_format = "%Y-%m"

    # 查询数据
    result = await db.execute(
        select(
            func.strftime(date_format, TokenUsage.created_at).label("date"),
            func.sum(TokenUsage.total_tokens).label("tokens"),
            func.count(TokenUsage.id).label("audits"),
        )
        .where(
            TokenUsage.user_id == user_id,
            TokenUsage.created_at >= start_date
        )
        .group_by("date")
        .order_by("date")
    )

    rows = result.all()
    return [
        {
            "date": row.date,
            "tokens": int(row.tokens or 0),
            "audits": int(row.audits or 0),
        }
        for row in rows
    ]


async def get_token_usage_by_project(
    db: AsyncSession,
    user_id: str,
    limit: int = 10
) -> List[Dict[str, Any]]:
    """获取按项目统计的 Token 使用量（Top N）

    Returns:
        List[{"project_name": "xxx", "tokens": 12345, "audits": 3}]
    """
    result = await db.execute(
        select(
            TokenUsage.project_name,
            func.sum(TokenUsage.total_tokens).label("tokens"),
            func.count(TokenUsage.id).label("audits"),
        )
        .where(
            TokenUsage.user_id == user_id,
            TokenUsage.project_name.isnot(None)
        )
        .group_by(TokenUsage.project_name)
        .order_by(func.sum(TokenUsage.total_tokens).desc())
        .limit(limit)
    )

    rows = result.all()
    return [
        {
            "project_name": row.project_name,
            "tokens": int(row.tokens or 0),
            "audits": int(row.audits or 0),
        }
        for row in rows
    ]


async def get_token_usage_by_agent(
    db: AsyncSession,
    user_id: str
) -> Dict[str, int]:
    """获取按 Agent 统计的 Token 使用量

    Returns:
        {"manager": 12345, "auditor": 23456, ...}
    """
    result = await db.execute(
        select(TokenUsage.agent_breakdown)
        .where(TokenUsage.user_id == user_id)
    )

    rows = result.scalars().all()

    # 聚合所有 agent 的 token
    agent_totals: Dict[str, int] = {}
    for breakdown in rows:
        if not breakdown:
            continue
        for agent_name, stats in breakdown.items():
            if agent_name not in agent_totals:
                agent_totals[agent_name] = 0
            agent_totals[agent_name] += stats.get("total", 0)

    return agent_totals
