"""
规则管理 API 路由

v3.0: 系统规则和自定义排除规则管理
"""
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.dependencies import get_current_user, get_current_admin
from ...storage.database import (
    get_db,
    SystemRule,
    CustomExclusion,
    User,
    UserRole,
    RuleCategory,
    Blockchain,
)


def utc_now():
    return datetime.now(timezone.utc)


router = APIRouter(prefix="/rules", tags=["rules"])


# =============================================================================
# Pydantic Models
# =============================================================================

class SystemRuleResponse(BaseModel):
    id: int
    name: str
    display_name: str
    description: Optional[str]
    blockchain: Optional[str]  # 所属链
    category: str
    is_enabled: bool
    priority: int
    trigger_count: int
    last_triggered_at: Optional[str]
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class SystemRuleUpdate(BaseModel):
    is_enabled: Optional[bool] = None
    priority: Optional[int] = None


class SystemRuleBatchUpdate(BaseModel):
    rule_ids: List[int]
    is_enabled: bool


class CustomExclusionCreate(BaseModel):
    name: str
    description: Optional[str] = None
    project_id: Optional[str] = None
    blockchain: Optional[str] = None  # 所属链
    match_config: dict
    is_enabled: bool = True


class CustomExclusionUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    blockchain: Optional[str] = None
    match_config: Optional[dict] = None
    is_enabled: Optional[bool] = None


class CustomExclusionResponse(BaseModel):
    id: str
    owner_id: str
    project_id: Optional[str]
    blockchain: Optional[str]
    name: str
    description: Optional[str]
    match_config: dict
    is_enabled: bool
    trigger_count: int
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


# =============================================================================
# 系统规则 API
# =============================================================================

@router.get("/system", response_model=List[SystemRuleResponse])
async def list_system_rules(
    blockchain: Optional[str] = None,
    category: Optional[str] = None,
    enabled_only: bool = False,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """获取系统规则列表"""
    query = select(SystemRule).order_by(SystemRule.priority, SystemRule.id)

    if blockchain:
        query = query.where(SystemRule.blockchain == Blockchain(blockchain))

    if category:
        query = query.where(SystemRule.category == RuleCategory(category))

    if enabled_only:
        query = query.where(SystemRule.is_enabled == True)

    result = await db.execute(query)
    rules = result.scalars().all()

    return [
        SystemRuleResponse(
            id=r.id,
            name=r.name,
            display_name=r.display_name,
            description=r.description,
            blockchain=r.blockchain.value if r.blockchain else None,
            category=r.category.value if r.category else "custom",
            is_enabled=r.is_enabled,
            priority=r.priority,
            trigger_count=r.trigger_count,
            last_triggered_at=r.last_triggered_at.isoformat() if r.last_triggered_at else None,
            created_at=r.created_at.isoformat() if r.created_at else "",
            updated_at=r.updated_at.isoformat() if r.updated_at else "",
        )
        for r in rules
    ]


@router.get("/system/stats")
async def get_system_rules_stats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """获取系统规则统计"""
    # 总数
    total_result = await db.execute(select(func.count(SystemRule.id)))
    total = total_result.scalar() or 0

    # 启用数
    enabled_result = await db.execute(
        select(func.count(SystemRule.id)).where(SystemRule.is_enabled == True)
    )
    enabled = enabled_result.scalar() or 0

    # 按分类统计
    category_result = await db.execute(
        select(SystemRule.category, func.count(SystemRule.id))
        .group_by(SystemRule.category)
    )
    by_category = {row[0].value if row[0] else "unknown": row[1] for row in category_result.fetchall()}

    # 总触发次数
    trigger_result = await db.execute(select(func.sum(SystemRule.trigger_count)))
    total_triggers = trigger_result.scalar() or 0

    return {
        "total": total,
        "enabled": enabled,
        "disabled": total - enabled,
        "by_category": by_category,
        "total_triggers": total_triggers,
    }


@router.get("/system/{rule_id}", response_model=SystemRuleResponse)
async def get_system_rule(
    rule_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """获取单个系统规则"""
    result = await db.execute(select(SystemRule).where(SystemRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")

    return SystemRuleResponse(
        id=rule.id,
        name=rule.name,
        display_name=rule.display_name,
        description=rule.description,
        blockchain=rule.blockchain.value if rule.blockchain else None,
        category=rule.category.value if rule.category else "custom",
        is_enabled=rule.is_enabled,
        priority=rule.priority,
        trigger_count=rule.trigger_count,
        last_triggered_at=rule.last_triggered_at.isoformat() if rule.last_triggered_at else None,
        created_at=rule.created_at.isoformat() if rule.created_at else "",
        updated_at=rule.updated_at.isoformat() if rule.updated_at else "",
    )


@router.put("/system/{rule_id}", response_model=SystemRuleResponse)
async def update_system_rule(
    rule_id: int,
    update: SystemRuleUpdate,
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """更新系统规则（仅管理员）"""
    result = await db.execute(select(SystemRule).where(SystemRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")

    if update.is_enabled is not None:
        rule.is_enabled = update.is_enabled

    if update.priority is not None:
        rule.priority = update.priority

    await db.commit()
    await db.refresh(rule)

    return SystemRuleResponse(
        id=rule.id,
        name=rule.name,
        display_name=rule.display_name,
        description=rule.description,
        blockchain=rule.blockchain.value if rule.blockchain else None,
        category=rule.category.value if rule.category else "custom",
        is_enabled=rule.is_enabled,
        priority=rule.priority,
        trigger_count=rule.trigger_count,
        last_triggered_at=rule.last_triggered_at.isoformat() if rule.last_triggered_at else None,
        created_at=rule.created_at.isoformat() if rule.created_at else "",
        updated_at=rule.updated_at.isoformat() if rule.updated_at else "",
    )


@router.post("/system/batch-update")
async def batch_update_system_rules(
    update: SystemRuleBatchUpdate,
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """批量更新系统规则启用状态（仅管理员）"""
    result = await db.execute(
        select(SystemRule).where(SystemRule.id.in_(update.rule_ids))
    )
    rules = result.scalars().all()

    for rule in rules:
        rule.is_enabled = update.is_enabled

    await db.commit()

    return {"updated": len(rules), "is_enabled": update.is_enabled}


# =============================================================================
# 自定义排除规则 API
# =============================================================================

@router.get("/custom", response_model=List[CustomExclusionResponse])
async def list_custom_exclusions(
    project_id: Optional[str] = None,
    blockchain: Optional[str] = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """获取用户的自定义排除规则"""
    query = select(CustomExclusion).where(CustomExclusion.owner_id == user.id)

    if project_id:
        # 项目级别 + 全局规则
        query = query.where(
            (CustomExclusion.project_id == project_id) |
            (CustomExclusion.project_id == None)
        )

    if blockchain:
        query = query.where(
            (CustomExclusion.blockchain == Blockchain(blockchain)) |
            (CustomExclusion.blockchain == None)
        )

    query = query.order_by(CustomExclusion.created_at.desc())
    result = await db.execute(query)
    exclusions = result.scalars().all()

    return [
        CustomExclusionResponse(
            id=e.id,
            owner_id=e.owner_id,
            project_id=e.project_id,
            blockchain=e.blockchain.value if e.blockchain else None,
            name=e.name,
            description=e.description,
            match_config=e.match_config,
            is_enabled=e.is_enabled,
            trigger_count=e.trigger_count,
            created_at=e.created_at.isoformat() if e.created_at else "",
            updated_at=e.updated_at.isoformat() if e.updated_at else "",
        )
        for e in exclusions
    ]


@router.post("/custom", response_model=CustomExclusionResponse)
async def create_custom_exclusion(
    data: CustomExclusionCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """创建自定义排除规则"""
    exclusion = CustomExclusion(
        owner_id=user.id,
        project_id=data.project_id,
        blockchain=Blockchain(data.blockchain) if data.blockchain else None,
        name=data.name,
        description=data.description,
        match_config=data.match_config,
        is_enabled=data.is_enabled,
    )

    db.add(exclusion)
    await db.commit()
    await db.refresh(exclusion)

    return CustomExclusionResponse(
        id=exclusion.id,
        owner_id=exclusion.owner_id,
        project_id=exclusion.project_id,
        blockchain=exclusion.blockchain.value if exclusion.blockchain else None,
        name=exclusion.name,
        description=exclusion.description,
        match_config=exclusion.match_config,
        is_enabled=exclusion.is_enabled,
        trigger_count=exclusion.trigger_count,
        created_at=exclusion.created_at.isoformat() if exclusion.created_at else "",
        updated_at=exclusion.updated_at.isoformat() if exclusion.updated_at else "",
    )


@router.put("/custom/{exclusion_id}", response_model=CustomExclusionResponse)
async def update_custom_exclusion(
    exclusion_id: str,
    data: CustomExclusionUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """更新自定义排除规则"""
    result = await db.execute(
        select(CustomExclusion).where(CustomExclusion.id == exclusion_id)
    )
    exclusion = result.scalar_one_or_none()

    if not exclusion:
        raise HTTPException(status_code=404, detail="规则不存在")

    # 检查权限
    if exclusion.owner_id != user.id and user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权修改此规则")

    if data.name is not None:
        exclusion.name = data.name
    if data.description is not None:
        exclusion.description = data.description
    if data.blockchain is not None:
        exclusion.blockchain = Blockchain(data.blockchain) if data.blockchain else None
    if data.match_config is not None:
        exclusion.match_config = data.match_config
    if data.is_enabled is not None:
        exclusion.is_enabled = data.is_enabled

    await db.commit()
    await db.refresh(exclusion)

    return CustomExclusionResponse(
        id=exclusion.id,
        owner_id=exclusion.owner_id,
        project_id=exclusion.project_id,
        blockchain=exclusion.blockchain.value if exclusion.blockchain else None,
        name=exclusion.name,
        description=exclusion.description,
        match_config=exclusion.match_config,
        is_enabled=exclusion.is_enabled,
        trigger_count=exclusion.trigger_count,
        created_at=exclusion.created_at.isoformat() if exclusion.created_at else "",
        updated_at=exclusion.updated_at.isoformat() if exclusion.updated_at else "",
    )


@router.delete("/custom/{exclusion_id}")
async def delete_custom_exclusion(
    exclusion_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """删除自定义排除规则"""
    result = await db.execute(
        select(CustomExclusion).where(CustomExclusion.id == exclusion_id)
    )
    exclusion = result.scalar_one_or_none()

    if not exclusion:
        raise HTTPException(status_code=404, detail="规则不存在")

    # 检查权限
    if exclusion.owner_id != user.id and user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权删除此规则")

    await db.delete(exclusion)
    await db.commit()

    return {"message": "规则已删除"}
