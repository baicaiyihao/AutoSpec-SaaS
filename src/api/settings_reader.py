"""
运行时配置读取器

审计引擎通过此模块读取配置，优先级:
1. 数据库中的设置 (Web后台配置)
2. DEFAULT_SETTINGS 默认值 (初始模版)

使用方式:
    from src.api.settings_reader import get_runtime_config
    config = await get_runtime_config()
    # config.concurrency, config.context, config.truncate, config.risk, config.security
    # config.agent_configs  → Dict[str, AgentConfig]
"""
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..storage.database import _get_session_factory, SystemSettings
from .routers.settings import DEFAULT_SETTINGS, BUILTIN_PRESETS, _PRESETS_DB_PREFIX


@dataclass
class RuntimeConfig:
    """运行时配置，替代 config.py 中的各个 dict"""

    # 并发配置
    concurrency: Dict[str, Any] = field(default_factory=dict)

    # 上下文组装配置
    context: Dict[str, Any] = field(default_factory=dict)

    # LLM 输入限制
    truncate: Dict[str, Any] = field(default_factory=dict)

    # 风险阈值
    risk: Dict[str, Any] = field(default_factory=dict)

    # 安全扫描配置
    security: Dict[str, Any] = field(default_factory=dict)

    # Agent 配置 (按角色)
    agent_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # 当前预设名称
    active_preset: str = "auto"


# =============================================================================
# 类型转换
# =============================================================================

def _cast_value(value: str, value_type: str) -> Any:
    """将字符串值转换为对应类型"""
    if value_type == "bool":
        return value.lower() in ("true", "1", "yes")
    elif value_type == "int":
        return int(value) if value else 0
    elif value_type == "float":
        return float(value) if value else 0.0
    return value


# =============================================================================
# 核心读取函数
# =============================================================================

async def get_runtime_config(db: Optional[AsyncSession] = None) -> RuntimeConfig:
    """
    从数据库读取所有运行时配置

    Args:
        db: 可选的数据库会话。如果未提供，会自动创建一个。

    Returns:
        RuntimeConfig: 包含所有配置分类的运行时配置对象
    """
    if db:
        return await _load_config(db)

    session_factory = _get_session_factory()
    async with session_factory() as session:
        return await _load_config(session)


async def _load_config(db: AsyncSession) -> RuntimeConfig:
    """从数据库加载配置"""
    # 读取所有 DB 设置
    result = await db.execute(
        select(SystemSettings).where(
            ~SystemSettings.key.like("_preset:%"),
            SystemSettings.key != "_server_api_keys",
        )
    )
    db_settings = {s.key: s for s in result.scalars().all()}

    # 合并默认值 + DB 值
    all_settings: Dict[str, Any] = {}
    for default in DEFAULT_SETTINGS:
        key = default["key"]
        db_item = db_settings.get(key)
        if db_item:
            all_settings[key] = _cast_value(db_item.value, default["value_type"])
        else:
            all_settings[key] = _cast_value(default["value"], default["value_type"])

    # 构建分类配置
    config = RuntimeConfig()

    # 并发配置
    config.concurrency = {
        "max_concurrent_scan": all_settings.get("max_concurrent_scan", 20),
        "max_concurrent_verify": all_settings.get("max_concurrent_verify", 15),
        "max_concurrent_exploit": all_settings.get("max_concurrent_exploit", 15),
        "batch_size": all_settings.get("batch_size", 50),
        "batch_cooldown": all_settings.get("batch_cooldown", 0.5),
    }

    # 上下文配置
    config.context = {
        "neighbor_depth": all_settings.get("neighbor_depth", 1),
        "max_neighbors_per_level": all_settings.get("max_neighbors_per_level", 3),
        "max_context_tokens": all_settings.get("max_context_tokens", 8000),
        "target_function_ratio": all_settings.get("target_function_ratio", 0.3),
        "neighbors_ratio": all_settings.get("neighbors_ratio", 0.4),
        "summary_ratio": all_settings.get("summary_ratio", 0.2),
        "types_ratio": all_settings.get("types_ratio", 0.1),
        "module_summary_length": all_settings.get("module_summary_length", 100),
        "function_summary_length": all_settings.get("function_summary_length", 50),
        "include_type_definitions": all_settings.get("include_type_definitions", True),
        "cch_enabled": all_settings.get("cch_enabled", True),
        "cch_max_length": all_settings.get("cch_max_length", 500),
        "cch_include_risk": all_settings.get("cch_include_risk", True),
        "cch_include_deps": all_settings.get("cch_include_deps", True),
        "cch_summary_max": all_settings.get("cch_summary_max", 100),
    }

    # LLM 输入限制
    config.truncate = {
        "max_input_chars": all_settings.get("max_input_chars", 200000),
        "broad_analysis": all_settings.get("truncate_broad_analysis", 200000),
        "targeted_analysis": all_settings.get("truncate_targeted_analysis", 150000),
        "contract_analysis": all_settings.get("truncate_contract_analysis", 200000),
        "expert_review": all_settings.get("truncate_expert_review", 150000),
        "role_swap": all_settings.get("truncate_role_swap", 100000),
    }

    # 风险阈值
    config.risk = {
        "skip_llm_below": all_settings.get("skip_llm_below", 30),
        "critical_above": all_settings.get("risk_score_critical", 80),
        "high_above": all_settings.get("risk_score_high", 60),
        "medium_above": all_settings.get("risk_score_medium", 30),
        "max_score": all_settings.get("risk_max_score", 100),
        "default_no_callgraph": all_settings.get("default_no_callgraph", 25),
    }

    # 安全配置
    config.security = {
        "enable_security_scan": all_settings.get("enable_security_scan", True),
        "whitehat_severity_filter": all_settings.get("whitehat_severity_filter", "high"),
    }

    # Agent 配置: 直接从当前预设读取
    config.active_preset = all_settings.get("default_model_preset", "auto")
    config.agent_configs = await _resolve_agent_configs(db, config.active_preset)

    return config


async def _resolve_agent_configs(
    db: AsyncSession, preset_key: str
) -> Dict[str, Dict[str, Any]]:
    """
    从当前选中的预设模版读取 Agent 配置
    """
    agent_roles = ["manager", "analyst", "auditor", "verifier", "white_hat", "review"]
    preset_agents = await _load_preset_agents(db, preset_key)

    configs: Dict[str, Dict[str, Any]] = {}
    for role in agent_roles:
        if preset_agents and role in preset_agents:
            preset_cfg = preset_agents[role]
            cfg: Dict[str, Any] = {
                "provider": preset_cfg.get("provider", "auto"),
                "model": preset_cfg.get("model", "auto"),
            }
            max_tokens = preset_cfg.get("max_tokens")
            if max_tokens and max_tokens > 0:
                cfg["max_tokens"] = max_tokens
            fb_provider = preset_cfg.get("fallback_provider", "")
            if fb_provider:
                cfg["fallback_provider"] = fb_provider
            fb_model = preset_cfg.get("fallback_model", "")
            if fb_model:
                cfg["fallback_model"] = fb_model
            configs[role] = cfg
        else:
            configs[role] = {"provider": "auto", "model": "auto"}

    return configs


async def _load_preset_agents(db: AsyncSession, preset_key: str) -> Optional[Dict[str, Any]]:
    """加载预设的 agents 配置"""
    if not preset_key or preset_key == "auto":
        # auto 预设: 所有 agent 都是 auto
        return None

    # 先查 DB (自定义覆盖)
    db_key = f"{_PRESETS_DB_PREFIX}{preset_key}"
    result = await db.execute(
        select(SystemSettings).where(SystemSettings.key == db_key)
    )
    db_setting = result.scalar_one_or_none()
    if db_setting:
        try:
            data = json.loads(db_setting.value)
            return data.get("agents", {})
        except json.JSONDecodeError:
            pass

    # 回退到内置预设
    if preset_key in BUILTIN_PRESETS:
        return BUILTIN_PRESETS[preset_key].get("agents", {})

    return None


# =============================================================================
# 便捷函数 (向后兼容 config.py 的使用方式)
# =============================================================================

async def get_agent_configs_from_db() -> Dict[str, Any]:
    """
    获取 Agent 配置 (替代 config.py 的 get_agent_configs)

    Returns:
        Dict[str, dict]: 角色 → {provider, model, max_tokens?, fallback_provider?, fallback_model?}
    """
    config = await get_runtime_config()
    return config.agent_configs


async def get_concurrency_config() -> Dict[str, Any]:
    """获取并发配置 (替代 config.py 的 AUDIT_CONCURRENCY)"""
    config = await get_runtime_config()
    return config.concurrency


async def get_context_config() -> Dict[str, Any]:
    """获取上下文配置 (替代 config.py 的 CONTEXT_CONFIG)"""
    config = await get_runtime_config()
    return config.context


async def get_truncate_limits() -> Dict[str, Any]:
    """获取截断限制 (替代 config.py 的 CODE_TRUNCATE_LIMITS)"""
    config = await get_runtime_config()
    return config.truncate


async def get_risk_thresholds() -> Dict[str, Any]:
    """获取风险阈值 (替代 config.py 的 RISK_THRESHOLDS)"""
    config = await get_runtime_config()
    return config.risk
