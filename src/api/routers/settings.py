"""
系统设置路由（管理员专用）

子功能:
1. 全局配置 (并发、上下文、安全、风险等)
2. Agent 预设模版 (CRUD: 查看、新建、编辑、删除)
3. 服务端 API Keys (加密存储，替代 .env 配置)
"""
import json
from typing import List, Optional, Dict
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db, User, SystemSettings
from ..auth.dependencies import get_current_admin, get_current_user
from ..auth.crypto import encrypt_api_keys, decrypt_api_keys

router = APIRouter(prefix="/settings", tags=["settings"])


# =============================================================================
# 默认系统设置
# =============================================================================

DEFAULT_SETTINGS = [
    # =========================================================================
    # 并发配置 (审计各阶段并行数)
    # =========================================================================
    {"key": "max_concurrent_scan", "value": "20", "value_type": "int", "category": "concurrency", "description": "Phase 2 漏洞扫描并行数"},
    {"key": "max_concurrent_verify", "value": "15", "value_type": "int", "category": "concurrency", "description": "Phase 3 Agent验证并行数"},
    {"key": "max_concurrent_exploit", "value": "15", "value_type": "int", "category": "concurrency", "description": "Phase 4 WhiteHat并行分析数"},
    {"key": "batch_size", "value": "50", "value_type": "int", "category": "concurrency", "description": "每批处理数量"},
    {"key": "batch_cooldown", "value": "0.5", "value_type": "float", "category": "concurrency", "description": "批次间冷却时间(秒)"},

    # =========================================================================
    # 上下文组装配置 (Agent代码上下文)
    # =========================================================================
    {"key": "neighbor_depth", "value": "1", "value_type": "int", "category": "context", "description": "邻居层级深度"},
    {"key": "max_neighbors_per_level", "value": "3", "value_type": "int", "category": "context", "description": "每层最多邻居数"},
    {"key": "max_context_tokens", "value": "8000", "value_type": "int", "category": "context", "description": "总上下文Token限制"},
    {"key": "target_function_ratio", "value": "0.3", "value_type": "float", "category": "context", "description": "目标函数Token占比"},
    {"key": "neighbors_ratio", "value": "0.4", "value_type": "float", "category": "context", "description": "邻居Token占比"},
    {"key": "summary_ratio", "value": "0.2", "value_type": "float", "category": "context", "description": "摘要Token占比"},
    {"key": "types_ratio", "value": "0.1", "value_type": "float", "category": "context", "description": "类型定义Token占比"},
    {"key": "module_summary_length", "value": "100", "value_type": "int", "category": "context", "description": "模块摘要长度(字符)"},
    {"key": "function_summary_length", "value": "50", "value_type": "int", "category": "context", "description": "函数摘要长度(字符)"},
    {"key": "include_type_definitions", "value": "true", "value_type": "bool", "category": "context", "description": "包含类型定义"},
    {"key": "cch_enabled", "value": "true", "value_type": "bool", "category": "context", "description": "启用CCH(上下文块头)"},
    {"key": "cch_max_length", "value": "500", "value_type": "int", "category": "context", "description": "CCH最大长度(字符)"},
    {"key": "cch_include_risk", "value": "true", "value_type": "bool", "category": "context", "description": "CCH包含风险指标"},
    {"key": "cch_include_deps", "value": "true", "value_type": "bool", "category": "context", "description": "CCH包含依赖信息"},
    {"key": "cch_summary_max", "value": "100", "value_type": "int", "category": "context", "description": "CCH模块摘要最大长度"},

    # =========================================================================
    # LLM 输入限制 (各阶段代码截断)
    # =========================================================================
    {"key": "max_input_chars", "value": "200000", "value_type": "int", "category": "truncate", "description": "最大输入字符数"},
    {"key": "truncate_broad_analysis", "value": "200000", "value_type": "int", "category": "truncate", "description": "BA广度分析截断限制"},
    {"key": "truncate_targeted_analysis", "value": "150000", "value_type": "int", "category": "truncate", "description": "TA针对性分析截断限制"},
    {"key": "truncate_contract_analysis", "value": "200000", "value_type": "int", "category": "truncate", "description": "合约结构分析截断限制"},
    {"key": "truncate_expert_review", "value": "150000", "value_type": "int", "category": "truncate", "description": "专家验证截断限制"},
    {"key": "truncate_role_swap", "value": "100000", "value_type": "int", "category": "truncate", "description": "角色交换截断限制"},

    # =========================================================================
    # Agent 配置
    # =========================================================================
    {"key": "default_model_preset", "value": "auto", "value_type": "string", "category": "agent", "description": "当前使用的模型预设"},


    # =========================================================================
    # 安全扫描配置
    # =========================================================================
    {"key": "enable_security_scan", "value": "true", "value_type": "bool", "category": "security", "description": "启用安全模式扫描"},
    {"key": "whitehat_severity_filter", "value": "high", "value_type": "string", "category": "security", "description": "WhiteHat最低处理级别"},

    # =========================================================================
    # 风险阈值
    # =========================================================================
    {"key": "risk_score_critical", "value": "80", "value_type": "int", "category": "risk", "description": "Critical 阈值"},
    {"key": "risk_score_high", "value": "60", "value_type": "int", "category": "risk", "description": "High 阈值"},
    {"key": "risk_score_medium", "value": "30", "value_type": "int", "category": "risk", "description": "Medium 阈值"},
    {"key": "skip_llm_below", "value": "30", "value_type": "int", "category": "risk", "description": "低于此分跳过LLM分析"},
    {"key": "risk_max_score", "value": "100", "value_type": "int", "category": "risk", "description": "风险分数上限"},
    {"key": "default_no_callgraph", "value": "25", "value_type": "int", "category": "risk", "description": "无调用图时默认风险分"},

    # =========================================================================
    # 注册配置
    # =========================================================================
    {"key": "registration_mode", "value": "open", "value_type": "string", "category": "registration", "description": "注册模式: open(自动通过) / review(需要审核)"},

    # =========================================================================
    # 安全配置
    # =========================================================================
    {"key": "enable_login_captcha", "value": "false", "value_type": "bool", "category": "security", "description": "启用登录验证码"},
    {"key": "jwt_access_token_expire_minutes", "value": "15", "value_type": "int", "category": "security", "description": "访问令牌有效期(分钟)"},
    {"key": "jwt_refresh_token_expire_days", "value": "7", "value_type": "int", "category": "security", "description": "刷新令牌有效期(天)"},
]


# =============================================================================
# 内置预设模版 (只读，可复制为自定义模版)
# =============================================================================

BUILTIN_PRESETS = {
    "auto": {
        "name": "自动检测",
        "description": "根据已配置的API Key自动选择最佳模型",
        "builtin": True,
        "agents": {
            "manager": {"provider": "auto", "model": "auto"},
            "analyst": {"provider": "auto", "model": "auto"},
            "auditor": {"provider": "auto", "model": "auto"},
            "verifier": {"provider": "auto", "model": "auto"},
            "white_hat": {"provider": "auto", "model": "auto"},
            "review": {"provider": "auto", "model": "auto"},
        }
    },
    "claude": {
        "name": "全Claude (最高质量)",
        "description": "所有Agent使用Claude Sonnet 4.5，质量最高，成本较高",
        "builtin": True,
        "agents": {
            "manager": {"provider": "anthropic", "model": "claude-sonnet-4-5"},
            "analyst": {"provider": "anthropic", "model": "claude-sonnet-4-5"},
            "auditor": {"provider": "anthropic", "model": "claude-sonnet-4-5"},
            "verifier": {"provider": "anthropic", "model": "claude-sonnet-4-5"},
            "white_hat": {"provider": "anthropic", "model": "claude-sonnet-4-5"},
            "review": {"provider": "anthropic", "model": "claude-sonnet-4-5"},
        }
    },
    "deepseek": {
        "name": "全DeepSeek (性价比)",
        "description": "所有Agent使用DeepSeek-Chat，性价比最高",
        "builtin": True,
        "agents": {
            "manager": {"provider": "deepseek", "model": "deepseek-chat"},
            "analyst": {"provider": "deepseek", "model": "deepseek-chat"},
            "auditor": {"provider": "deepseek", "model": "deepseek-chat"},
            "verifier": {"provider": "deepseek", "model": "deepseek-chat"},
            "white_hat": {"provider": "deepseek", "model": "deepseek-chat"},
            "review": {"provider": "deepseek", "model": "deepseek-chat"},
        }
    },
    "hybrid": {
        "name": "混合配置 (推荐)",
        "description": "不同Agent使用最适合的模型，平衡成本和质量",
        "builtin": True,
        "agents": {
            "manager": {"provider": "openai", "model": "gpt-4o", "fallback_provider": "dashscope", "fallback_model": "qwen-max"},
            "analyst": {"provider": "dashscope", "model": "qwen-max"},
            "auditor": {"provider": "deepseek", "model": "deepseek-chat"},
            "verifier": {"provider": "anthropic", "model": "claude-sonnet-4-5", "fallback_provider": "deepseek", "fallback_model": "deepseek-chat"},
            "white_hat": {"provider": "deepseek", "model": "deepseek-chat"},
            "review": {"provider": "dashscope", "model": "qwen-plus", "max_tokens": 32768},
        }
    },
    "china": {
        "name": "国内方案 (无需翻墙)",
        "description": "使用DashScope+智谱，国内直接访问",
        "builtin": True,
        "agents": {
            "manager": {"provider": "dashscope", "model": "qwen-max"},
            "analyst": {"provider": "dashscope", "model": "qwen-max"},
            "auditor": {"provider": "dashscope", "model": "deepseek-v3.2"},
            "verifier": {"provider": "zhipu", "model": "glm-4.7"},
            "white_hat": {"provider": "zhipu", "model": "glm-4.7"},
            "review": {"provider": "dashscope", "model": "qwen-plus", "max_tokens": 32768},
        }
    },
    "qwen": {
        "name": "全Qwen-Plus (高并发)",
        "description": "高并发15000RPM，适合大规模审计",
        "builtin": True,
        "agents": {
            "manager": {"provider": "dashscope", "model": "qwen-plus", "max_tokens": 32768},
            "analyst": {"provider": "dashscope", "model": "qwen-plus", "max_tokens": 32768},
            "auditor": {"provider": "dashscope", "model": "qwen-plus", "max_tokens": 32768},
            "verifier": {"provider": "dashscope", "model": "qwen-plus", "max_tokens": 32768},
            "white_hat": {"provider": "dashscope", "model": "qwen-plus", "max_tokens": 32768},
            "review": {"provider": "dashscope", "model": "qwen-plus", "max_tokens": 32768},
        }
    },
    "glm": {
        "name": "全GLM-4.7 (128K输出)",
        "description": "超长输出支持，适合复杂分析",
        "builtin": True,
        "agents": {
            "manager": {"provider": "zhipu", "model": "glm-4.7", "max_tokens": 131072},
            "analyst": {"provider": "zhipu", "model": "glm-4.7", "max_tokens": 131072},
            "auditor": {"provider": "zhipu", "model": "glm-4.7", "max_tokens": 131072},
            "verifier": {"provider": "zhipu", "model": "glm-4.7", "max_tokens": 131072},
            "white_hat": {"provider": "zhipu", "model": "glm-4.7", "max_tokens": 131072},
            "review": {"provider": "zhipu", "model": "glm-4.7", "max_tokens": 131072},
        }
    },
    "local": {
        "name": "本地Ollama",
        "description": "使用本地部署的模型，完全离线",
        "builtin": True,
        "agents": {
            "manager": {"provider": "ollama", "model": "llama3.3:70b"},
            "analyst": {"provider": "ollama", "model": "llama3.3:70b"},
            "auditor": {"provider": "ollama", "model": "llama3.3:70b"},
            "verifier": {"provider": "ollama", "model": "llama3.3:70b"},
            "white_hat": {"provider": "ollama", "model": "llama3.3:70b"},
            "review": {"provider": "ollama", "model": "llama3.3:70b"},
        }
    },
}


# 服务端 API Key 提供商列表
SERVER_API_KEY_PROVIDERS = [
    {"key": "DASHSCOPE_API_KEY", "label": "DashScope (阿里云)", "provider": "dashscope"},
    {"key": "ANTHROPIC_API_KEY", "label": "Anthropic (Claude)", "provider": "anthropic"},
    {"key": "OPENAI_API_KEY", "label": "OpenAI (GPT)", "provider": "openai"},
    {"key": "DEEPSEEK_API_KEY", "label": "DeepSeek", "provider": "deepseek"},
    {"key": "ZHIPU_API_KEY", "label": "智谱AI (GLM)", "provider": "zhipu"},
    {"key": "GOOGLE_API_KEY", "label": "Google (Gemini)", "provider": "google"},
]


# =============================================================================
# 请求/响应模型
# =============================================================================

class SettingItem(BaseModel):
    key: str
    value: str
    value_type: str
    category: str
    description: Optional[str] = None
    updated_at: Optional[str] = None


class SettingsResponse(BaseModel):
    settings: List[SettingItem]


class SettingUpdateItem(BaseModel):
    key: str
    value: str


class SettingsUpdateRequest(BaseModel):
    settings: List[SettingUpdateItem]


class PresetAgentConfig(BaseModel):
    provider: str
    model: str
    max_tokens: Optional[int] = None
    fallback_provider: Optional[str] = None
    fallback_model: Optional[str] = None


class PresetTemplate(BaseModel):
    name: str
    description: str = ""
    builtin: bool = False
    agents: Dict[str, PresetAgentConfig]


class PresetsResponse(BaseModel):
    presets: Dict[str, PresetTemplate]


class PresetCreateRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=50, pattern=r'^[a-z0-9_]+$')
    name: str = Field(..., min_length=1, max_length=100)
    description: str = ""
    agents: Dict[str, PresetAgentConfig]


class PresetUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    agents: Optional[Dict[str, PresetAgentConfig]] = None


class ApiKeyStatusItem(BaseModel):
    key: str
    label: str
    provider: str
    source: str  # "none" | "env" | "db" | "both"


class ApiKeysStatusResponse(BaseModel):
    keys: List[ApiKeyStatusItem]


class ApiKeysUpdateRequest(BaseModel):
    """更新服务端 API Keys（空字符串表示删除）"""
    DASHSCOPE_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    DEEPSEEK_API_KEY: Optional[str] = None
    ZHIPU_API_KEY: Optional[str] = None
    GOOGLE_API_KEY: Optional[str] = None


# =============================================================================
# 路由: 全局配置
# =============================================================================

@router.get("", response_model=SettingsResponse)
async def get_settings(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """获取所有系统设置（管理员）"""
    result = await db.execute(
        select(SystemSettings).order_by(SystemSettings.category, SystemSettings.key)
    )
    db_settings = {s.key: s for s in result.scalars().all()}

    items = []
    for default in DEFAULT_SETTINGS:
        db_item = db_settings.get(default["key"])
        if db_item:
            items.append(SettingItem(
                key=db_item.key,
                value=db_item.value,
                value_type=db_item.value_type,
                category=db_item.category,
                description=db_item.description,
                updated_at=db_item.updated_at.isoformat() if db_item.updated_at else None,
            ))
        else:
            items.append(SettingItem(
                key=default["key"],
                value=default["value"],
                value_type=default["value_type"],
                category=default["category"],
                description=default["description"],
            ))

    return SettingsResponse(settings=items)


@router.post("")
async def update_settings(
    req: SettingsUpdateRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """批量更新系统设置（管理员）"""
    valid_keys = {d["key"] for d in DEFAULT_SETTINGS}
    updated = []

    for item in req.settings:
        if item.key not in valid_keys:
            raise HTTPException(status_code=400, detail=f"未知设置项: {item.key}")

        result = await db.execute(
            select(SystemSettings).where(SystemSettings.key == item.key)
        )
        db_setting = result.scalar_one_or_none()
        default = next(d for d in DEFAULT_SETTINGS if d["key"] == item.key)

        if db_setting:
            db_setting.value = item.value
            db_setting.updated_by = admin.id
        else:
            db_setting = SystemSettings(
                key=item.key,
                value=item.value,
                value_type=default["value_type"],
                category=default["category"],
                description=default["description"],
                updated_by=admin.id,
            )
            db.add(db_setting)
        updated.append(item.key)

    return {"message": f"已更新 {len(updated)} 项设置", "updated_keys": updated}


# =============================================================================
# 路由: Agent 预设模版 CRUD
# =============================================================================

_PRESETS_DB_PREFIX = "_preset:"


async def _load_custom_presets(db: AsyncSession) -> Dict[str, dict]:
    """从数据库加载自定义预设"""
    result = await db.execute(
        select(SystemSettings).where(SystemSettings.key.like("_preset:%"))
    )
    presets = {}
    for row in result.scalars().all():
        key = row.key.replace(_PRESETS_DB_PREFIX, "")
        try:
            data = json.loads(row.value)
            data["builtin"] = False
            presets[key] = data
        except json.JSONDecodeError:
            pass
    return presets


@router.get("/presets", response_model=PresetsResponse)
async def get_presets(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """获取所有 Agent 预设模版（内置 + 自定义，所有认证用户可读）"""
    custom = await _load_custom_presets(db)
    all_presets = {**BUILTIN_PRESETS, **custom}
    return PresetsResponse(presets=all_presets)


@router.post("/presets")
async def create_preset(
    req: PresetCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """新建自定义预设模版（所有认证用户）"""
    if req.key in BUILTIN_PRESETS:
        raise HTTPException(status_code=400, detail=f"不能使用内置预设名: {req.key}")

    db_key = f"{_PRESETS_DB_PREFIX}{req.key}"
    result = await db.execute(select(SystemSettings).where(SystemSettings.key == db_key))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"预设已存在: {req.key}")

    data = {
        "name": req.name,
        "description": req.description,
        "agents": {k: v.model_dump() for k, v in req.agents.items()},
    }
    db.add(SystemSettings(
        key=db_key,
        value=json.dumps(data, ensure_ascii=False),
        value_type="json",
        category="preset",
        description=f"自定义预设: {req.name}",
        updated_by=user.id,
    ))
    return {"message": f"预设 '{req.name}' 已创建", "key": req.key}


@router.post("/presets/{preset_key}")
async def update_preset(
    preset_key: str,
    req: PresetUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """编辑预设模版（内置预设会复制为自定义后编辑，所有认证用户）"""
    db_key = f"{_PRESETS_DB_PREFIX}{preset_key}"
    result = await db.execute(select(SystemSettings).where(SystemSettings.key == db_key))
    db_setting = result.scalar_one_or_none()

    if db_setting:
        # 编辑已有自定义预设
        data = json.loads(db_setting.value)
    elif preset_key in BUILTIN_PRESETS:
        # 内置预设 → 复制一份到DB再编辑
        builtin = BUILTIN_PRESETS[preset_key]
        data = {
            "name": builtin["name"],
            "description": builtin["description"],
            "agents": builtin["agents"],
        }
    else:
        raise HTTPException(status_code=404, detail=f"预设不存在: {preset_key}")

    # 应用更新
    if req.name is not None:
        data["name"] = req.name
    if req.description is not None:
        data["description"] = req.description
    if req.agents is not None:
        data["agents"] = {k: v.model_dump() for k, v in req.agents.items()}

    if db_setting:
        db_setting.value = json.dumps(data, ensure_ascii=False)
        db_setting.updated_by = user.id
    else:
        db.add(SystemSettings(
            key=db_key,
            value=json.dumps(data, ensure_ascii=False),
            value_type="json",
            category="preset",
            description=f"自定义预设: {data['name']}",
            updated_by=user.id,
        ))

    return {"message": f"预设 '{data['name']}' 已更新"}


@router.post("/presets/{preset_key}/delete")
async def delete_preset(
    preset_key: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """删除自定义预设（所有认证用户）"""
    if preset_key in BUILTIN_PRESETS:
        # 检查是否有自定义覆盖
        db_key = f"{_PRESETS_DB_PREFIX}{preset_key}"
        result = await db.execute(select(SystemSettings).where(SystemSettings.key == db_key))
        db_setting = result.scalar_one_or_none()
        if db_setting:
            await db.delete(db_setting)
            return {"message": f"已恢复内置预设: {preset_key}"}
        raise HTTPException(status_code=400, detail="不能删除内置预设")

    db_key = f"{_PRESETS_DB_PREFIX}{preset_key}"
    result = await db.execute(select(SystemSettings).where(SystemSettings.key == db_key))
    db_setting = result.scalar_one_or_none()
    if not db_setting:
        raise HTTPException(status_code=404, detail=f"预设不存在: {preset_key}")

    await db.delete(db_setting)
    return {"message": f"预设已删除: {preset_key}"}


# =============================================================================
# 路由: 服务端 API Keys
# =============================================================================

_SERVER_API_KEYS_DB_KEY = "_server_api_keys"


@router.get("/api-keys", response_model=ApiKeysStatusResponse)
async def get_server_api_keys(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """获取服务端 API Key 配置状态（不返回明文）"""
    import os

    result = await db.execute(
        select(SystemSettings).where(SystemSettings.key == _SERVER_API_KEYS_DB_KEY)
    )
    db_setting = result.scalar_one_or_none()
    stored_keys = {}
    if db_setting and db_setting.value:
        stored_keys = decrypt_api_keys(db_setting.value)

    items = []
    for provider in SERVER_API_KEY_PROVIDERS:
        has_db = bool(stored_keys.get(provider["key"]))
        has_env = bool(os.environ.get(provider["key"]))
        # 区分来源
        if has_db and has_env:
            source = "both"
        elif has_db:
            source = "db"
        elif has_env:
            source = "env"
        else:
            source = "none"
        items.append(ApiKeyStatusItem(
            key=provider["key"],
            label=provider["label"],
            provider=provider["provider"],
            source=source,
        ))

    return ApiKeysStatusResponse(keys=items)


@router.post("/api-keys")
async def update_server_api_keys(
    req: ApiKeysUpdateRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """更新服务端 API Keys（加密存储）"""
    import os

    result = await db.execute(
        select(SystemSettings).where(SystemSettings.key == _SERVER_API_KEYS_DB_KEY)
    )
    db_setting = result.scalar_one_or_none()

    current_keys = {}
    if db_setting and db_setting.value:
        current_keys = decrypt_api_keys(db_setting.value)

    update_data = req.model_dump(exclude_none=True)
    updated_providers = []
    for key, value in update_data.items():
        if value == "":
            current_keys.pop(key, None)
            updated_providers.append(key)
        else:
            current_keys[key] = value
            updated_providers.append(key)

    encrypted = encrypt_api_keys(current_keys) if current_keys else ""

    if db_setting:
        db_setting.value = encrypted
        db_setting.updated_by = admin.id
    else:
        db_setting = SystemSettings(
            key=_SERVER_API_KEYS_DB_KEY,
            value=encrypted,
            value_type="secret",
            category="system",
            description="服务端 API Keys (加密)",
            updated_by=admin.id,
        )
        db.add(db_setting)

    # 同时设置到环境变量（立即生效）
    for key, value in update_data.items():
        if value == "":
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

    return {"message": f"已更新 {len(updated_providers)} 个 API Key", "updated": updated_providers}
