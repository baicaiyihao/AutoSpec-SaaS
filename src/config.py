"""
AutoSpec 配置模块

包含:
- 基础路径配置
- 环境变量
- 上下文组装配置
- 验证相关配置
- 多模型配置 (Agent Presets)
"""

import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"
from pathlib import Path
from typing import Dict, Optional
from dotenv import load_dotenv

load_dotenv()

# 基础路径
BASE_DIR = Path(__file__).resolve().parent.parent
VECTOR_DB_DIR = os.path.join(BASE_DIR, "data", "vector_store")
TEMP_PROJECT_DIR = os.path.join(BASE_DIR, "temp_move_project")

# 环境变量
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")
GOOGLE_API_KEY = os.getenv("DASHSCOPE_API_KEY")
# 确保必要的目录存在
os.makedirs(VECTOR_DB_DIR, exist_ok=True)
# 注意: TEMP_PROJECT_DIR 不再自动创建
# - 测试脚本: LocalExecutor.setup_project() 会按需创建
# - 批量验证: 使用 temp_verification_projects/ (由 project_builder.py 管理)


# ============================================================================
# LLM 输入/输出限制配置 (适配 qwen-plus 套餐: 输入 ≤ 128K tokens)
# ============================================================================

# 最大输入字符数 (约 50K tokens，远低于 128K 限制，留有余量)
MAX_INPUT_CHARS = 200000

# 各阶段代码截断限制 (字符数)
CODE_TRUNCATE_LIMITS = {
    "broad_analysis": 200000,      # BA 广度分析
    "targeted_analysis": 150000,   # TA 针对性分析
    "contract_analysis": 200000,   # 合约结构分析
    "expert_review": 150000,       # 专家验证
    "role_swap": 100000,           # 角色交换验证
}


# ============================================================================
# Phase 2: Fail-Fast 依赖校验
# ============================================================================

REQUIRED_DEPENDENCIES = {
    "api_key": "DASHSCOPE_API_KEY",
    "security_dataset": "reports/datasets/security_patterns.jsonl",
    "security_vector_store": "data/vector_store/security_patterns/",
    "success_cases_store": "data/vector_store/",  # 非必需，缺失时禁用 RAG
}


# ============================================================================
# Phase 2: 上下文组装配置
# ============================================================================

CONTEXT_CONFIG = {
    # 邻居层级 (减少以降低 prompt 大小，避免 LLM 输出截断)
    "neighbor_depth": 1,           # 默认 1 层邻居 (降低 context 压力)
    "max_neighbors_per_level": 3,  # 每层最多 3 个邻居

    # Token 预算分配
    "max_context_tokens": 8000,    # 总上下文限制
    "target_function_ratio": 0.3,  # 目标函数占比
    "neighbors_ratio": 0.4,        # 邻居占比
    "summary_ratio": 0.2,          # 摘要占比
    "types_ratio": 0.1,            # 类型定义占比

    # 摘要配置
    "module_summary_length": 100,  # 模块摘要长度
    "function_summary_length": 50, # 函数摘要长度
    "include_type_definitions": True,  # 是否包含类型定义

    # CCH (Contextual Chunk Headers) 开关
    "cch_enabled": True,
    "cch_max_length": 500,
    "cch_include_risk": True,      # 是否包含风险指标
    "cch_include_deps": True,      # 是否包含依赖信息
    "cch_summary_max": 100,        # 模块摘要最大长度
}


# ============================================================================
# Phase 2: 调用图输出目录
# ============================================================================

CALLGRAPH_DIR = os.path.join(BASE_DIR, "data", "callgraph")
os.makedirs(CALLGRAPH_DIR, exist_ok=True)


# ============================================================================
# Phase 2: 报告输出目录
# ============================================================================

REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SECURITY_AUDITS_DIR = os.path.join(REPORTS_DIR, "security_audits")
DATASETS_DIR = os.path.join(REPORTS_DIR, "datasets")

os.makedirs(SECURITY_AUDITS_DIR, exist_ok=True)
os.makedirs(DATASETS_DIR, exist_ok=True)


# ============================================================================
# 审计并发配置 (Agent System)
# ============================================================================
# qwen-plus: 15000 RPM = 250 RPS, 可用高并发
# glm-4.7: 3-5 并发, 需要低并发
# 修改此处即可统一调整所有阶段的并发参数

AUDIT_CONCURRENCY = {
    # Phase 2: 漏洞扫描
    "max_concurrent_scan": 20,      # BA/TA 并行扫描数

    # Phase 3: 多Agent验证
    "max_concurrent_verify": 15,    # 同时验证的发现数

    # Phase 4: 利用链验证 (处理所有高危漏洞，用 semaphore 控制并发)
    "max_concurrent_exploit": 15,   # WhiteHat 并行分析数

    # 通用
    "batch_size": 50,               # 每批处理数量 (大批次减少开销)
    "batch_cooldown": 0.5,          # 批次间冷却秒数
}


# ============================================================================
# Phase 2: 验证相关配置
# ============================================================================

VERIFICATION_CONFIG = {
    "max_retries": 15,             # 最大重试次数
    "prover_timeout": 180,         # sui-prover 默认超时 (秒)
    "prover_max_timeout": 600,     # sui-prover 最大超时 (秒)
    "conservative_rounds": (1, 5), # 保守期轮次
    "enhanced_rounds": (6, 10),    # 增强期轮次
    "degraded_rounds": (11, 15),   # 降级期轮次
}


# ============================================================================
# Phase 2: 大模块分批验证配置
# ============================================================================

BATCH_CONFIG = {
    "max_functions_per_batch": 1,     # 每批只验证 1 个函数 (确保 LLM 专注生成完善的 spec)
    "split_threshold": 2,             # 超过此函数数量时自动拆分
    "prioritize_high_risk": True,     # 优先验证高风险函数
    "combine_specs_on_success": True, # 成功后合并所有批次的 spec
}


# ============================================================================
# Phase 2: 风险评分阈值
# ============================================================================

RISK_THRESHOLDS = {
    "skip_llm_below": 30,          # 风险分低于此值跳过 LLM 分析
    "critical_above": 80,          # 高于此值标记为 critical
    "high_above": 60,              # 高于此值标记为 high
    "medium_above": 30,            # 高于此值标记为 medium
    "max_score": 100,              # 风险分数上限 (cap)
    "default_no_callgraph": 25,    # 无调用图时的默认风险分 (中等偏高)
}


# ============================================================================
# Phase 2: 失败处理策略配置
# ============================================================================

FAILURE_HANDLING_CONFIG = {
    # 提前终止阈值
    "repeated_error_threshold": 3,   # 连续同类错误 N 次后终止
    "no_progress_threshold": 5,      # 无进展 N 轮后终止

    # 风险调整
    "verification_failed_penalty": 10,  # 验证失败的风险惩罚分
    "max_risk_score": 100,              # 风险分数上限

    # 致命错误类型 (立即终止)
    "fatal_error_types": [
        "unsupported_feature",
        "unresolved_module",
    ],

    # 降级策略映射
    "degradation_strategies": {
        "timeout": "split_function",
        "assertion_failed": "weaken_ensures",
        "loop_invariant_missing": "skip_loop",
        "solver_unknown": "simplify_spec",
    },

    # 产物输出
    "save_draft_on_failure": True,      # 失败时保存草稿 spec
    "save_all_attempts": False,         # 保存所有尝试 (调试用)
    "max_attempts_in_log": 5,           # failure_log 中保留的最近尝试数
}


# ============================================================================
# Phase 2: 函数级验证 - 风险折扣矩阵
# ============================================================================

RISK_DISCOUNT_CONFIG = {
    # 验证状态 -> (折扣系数, 说明)
    # 折扣系数: 0.1 = -90%, 0.5 = -50%, 1.0 = 不折扣, 1.1 = +10%惩罚
    "verified": {
        "discount": 0.1,
        "description": "已验证，风险 -90%",
    },
    "partial": {
        "discount": 0.5,
        "description": "部分验证，风险 -50%",
    },
    "pending": {
        "discount": 1.0,
        "description": "待验证，风险不变",
    },
    "skipped": {
        "discount": 1.0,
        "description": "跳过，风险不变",
    },
    "failed": {
        "discount": 1.1,
        "description": "验证失败，风险 +10%",
    },
}


# ============================================================================
# Phase 2: 函数级验证 - 跳过规则
# ============================================================================

SKIP_RULES_CONFIG = {
    # 规则1: 低风险辅助函数
    "low_risk_helper": {
        "enabled": True,
        "description": "低风险辅助函数",
        "patterns": ["get_", "is_", "has_", "check_", "assert_"],
        "max_lines": 20,
    },
    # 规则2: 只读视图函数
    "view_function": {
        "enabled": True,
        "description": "只读视图函数",
        "patterns": ["view_", "query_", "read_"],
        "risk_threshold": 10,
    },
    # 规则3: 多次超时
    "timeout_exceeded": {
        "enabled": True,
        "description": "多次超时后跳过",
        "max_timeout_attempts": 3,
    },
    # 规则4: 过于复杂的函数
    "too_complex": {
        "enabled": False,  # 默认关闭，需手动启用
        "description": "过于复杂的函数",
        "max_cyclomatic_complexity": 20,
        "max_lines": 200,
    },
}


# ============================================================================
# 多模型配置 (Agent Presets)
# ============================================================================
# 为不同的Agent分配不同的LLM模型，发挥各模型的优势。
#
# 使用方式:
# 1. 设置环境变量 (推荐在.env文件中):
#    OPENAI_API_KEY=sk-xxx
#    ANTHROPIC_API_KEY=sk-ant-xxx
#    DEEPSEEK_API_KEY=sk-xxx
#    ZHIPU_API_KEY=xxx
#    DASHSCOPE_API_KEY=xxx
#    GOOGLE_API_KEY=xxx
#
# 2. 导入配置:
#    from src.config import get_agent_configs
#    configs = get_agent_configs()


def _get_agent_config_class():
    """延迟导入 AgentConfig 避免循环导入"""
    from src.agents.base_agent import AgentConfig
    return AgentConfig


def _create_presets():
    """延迟创建预设配置"""
    AgentConfig = _get_agent_config_class()

    # 方案1: 全Claude (最高质量，成本最高)
    PRESET_ALL_CLAUDE = {
        "manager": AgentConfig(provider="anthropic", model="claude-sonnet-4-5"),
        "analyst": AgentConfig(provider="anthropic", model="claude-sonnet-4-5"),
        "auditor": AgentConfig(provider="anthropic", model="claude-sonnet-4-5"),
        "expert": AgentConfig(provider="anthropic", model="claude-sonnet-4-5"),
        "white_hat": AgentConfig(provider="anthropic", model="claude-sonnet-4-5"),
        "review": AgentConfig(provider="anthropic", model="claude-sonnet-4-5"),
    }

    # 方案2: 全DeepSeek (性价比最高)
    PRESET_ALL_DEEPSEEK = {
        "manager": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "analyst": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "auditor": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "expert": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "white_hat": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "review": AgentConfig(provider="deepseek", model="deepseek-chat"),
    }

    # 方案3: 混合配置 (推荐 - 平衡成本和质量)
    PRESET_HYBRID = {
        "expert": AgentConfig(
            provider="anthropic",
            model="claude-sonnet-4-5",
            fallback_provider="deepseek",
            fallback_model="deepseek-chat"
        ),
        "auditor": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "analyst": AgentConfig(provider="dashscope", model="qwen-max"),
        "manager": AgentConfig(
            provider="openai",
            model="gpt-4o",
            fallback_provider="dashscope",
            fallback_model="qwen-max"
        ),
        "white_hat": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "review": AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768),
    }

    # 方案4: 国内方案 (无需翻墙)
    PRESET_CHINA = {
        "manager": AgentConfig(provider="dashscope", model="qwen-max"),
        "analyst": AgentConfig(provider="dashscope", model="qwen-max"),
        "auditor": AgentConfig(provider="dashscope", model="deepseek-v3.2"),
        "expert": AgentConfig(provider="zhipu", model="glm-4.7"),
        "white_hat": AgentConfig(provider="zhipu", model="glm-4.7"),
        "review": AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768),
    }

    # 方案5: 本地方案 (Ollama)
    PRESET_LOCAL = {
        "manager": AgentConfig(provider="ollama", model="llama3.3:70b"),
        "analyst": AgentConfig(provider="ollama", model="llama3.3:70b"),
        "auditor": AgentConfig(provider="ollama", model="llama3.3:70b"),
        "expert": AgentConfig(provider="ollama", model="llama3.3:70b"),
        "white_hat": AgentConfig(provider="ollama", model="llama3.3:70b"),
        "review": AgentConfig(provider="ollama", model="llama3.3:70b"),
    }

    # 方案6: 多模型对比测试
    PRESET_COMPARISON = {
        "manager": AgentConfig(provider="openai", model="gpt-4o"),
        "analyst": AgentConfig(provider="anthropic", model="claude-sonnet-4-5"),
        "auditor": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "expert": AgentConfig(provider="google", model="gemini-3-flash"),
        "white_hat": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "review": AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768),
    }

    # 方案7: 全智谱GLM-4.6 (支持128K输出)
    PRESET_ALL_GLM = {
        "manager": AgentConfig(provider="zhipu", model="glm-4.7", max_tokens=131072),
        "analyst": AgentConfig(provider="zhipu", model="glm-4.7", max_tokens=131072),
        "auditor": AgentConfig(provider="zhipu", model="glm-4.7", max_tokens=131072),
        "expert": AgentConfig(provider="zhipu", model="glm-4.7", max_tokens=131072),
        "white_hat": AgentConfig(provider="zhipu", model="glm-4.7", max_tokens=131072),
        "review": AgentConfig(provider="zhipu", model="glm-4.7", max_tokens=131072),
    }

    # 方案8: 全通义千问Plus (高并发 15000 RPM, 100万上下文)
    # ⚠️ 套餐价格要求: 输入 ≤ 128K tokens (约50万字符)
    # 输出: 32768 tokens (qwen-plus 最大值)
    PRESET_ALL_QWEN = {
        "manager": AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768),
        "analyst": AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768),
        "auditor": AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768),
        "expert": AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768),
        "white_hat": AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768),
        "review": AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768),
    }

    return {
        "claude": PRESET_ALL_CLAUDE,
        "deepseek": PRESET_ALL_DEEPSEEK,
        "hybrid": PRESET_HYBRID,
        "china": PRESET_CHINA,
        "local": PRESET_LOCAL,
        "comparison": PRESET_COMPARISON,
        "glm": PRESET_ALL_GLM,
        "qwen": PRESET_ALL_QWEN,
    }


def get_agent_configs(preset: str = "auto", api_keys: Optional[Dict[str, str]] = None) -> Dict[str, "AgentConfig"]:
    """
    获取Agent配置

    Args:
        preset: 预设方案名称
            - "auto": 根据可用API自动选择
            - "claude": 全Claude
            - "deepseek": 全DeepSeek
            - "hybrid": 混合配置
            - "china": 国内方案
            - "local": 本地Ollama
            - "comparison": 多模型对比
            - "glm": 全智谱GLM
        api_keys: 可选的 API Keys 字典，如果提供则优先使用，否则从环境变量读取

    Returns:
        Dict[str, AgentConfig]: Agent角色到配置的映射
    """
    presets = _create_presets()

    if preset != "auto" and preset in presets:
        return presets[preset]

    return _auto_detect_configs(api_keys)


def _auto_detect_configs(api_keys: Optional[Dict[str, str]] = None) -> Dict[str, "AgentConfig"]:
    """根据环境变量或传入的 API Keys 自动检测最佳配置

    Args:
        api_keys: 可选的 API Keys 字典，如果提供则优先使用
    """
    AgentConfig = _get_agent_config_class()

    # 优先使用传入的 API Keys，否则从环境变量读取
    def has_key(key_name: str) -> bool:
        if api_keys:
            return bool(api_keys.get(key_name))
        return bool(os.getenv(key_name))

    has_anthropic = has_key("ANTHROPIC_API_KEY")
    has_openai = has_key("OPENAI_API_KEY")
    has_deepseek = has_key("DEEPSEEK_API_KEY")
    has_dashscope = has_key("DASHSCOPE_API_KEY")
    has_zhipu = has_key("ZHIPU_API_KEY")
    has_google = has_key("GOOGLE_API_KEY")

    configs = {}

    # Expert: 优先Claude > DeepSeek > GPT-4 > Qwen
    if has_anthropic:
        configs["expert"] = AgentConfig(provider="anthropic", model="claude-sonnet-4-5")
    elif has_deepseek:
        configs["expert"] = AgentConfig(provider="deepseek", model="deepseek-chat")
    elif has_openai:
        configs["expert"] = AgentConfig(provider="openai", model="gpt-4o")
    elif has_dashscope:
        configs["expert"] = AgentConfig(provider="dashscope", model="qwen-max")
    else:
        configs["expert"] = AgentConfig(provider="ollama", model="llama3.3")

    # Auditor: 优先DeepSeek (性价比) > Qwen > GPT-4
    if has_deepseek:
        configs["auditor"] = AgentConfig(provider="deepseek", model="deepseek-chat")
    elif has_dashscope:
        configs["auditor"] = AgentConfig(provider="dashscope", model="deepseek-v3.2")
    elif has_openai:
        configs["auditor"] = AgentConfig(provider="openai", model="gpt-4o-mini")
    else:
        configs["auditor"] = configs["expert"]

    # Analyst: 优先Qwen (中文好) > GPT-4 > DeepSeek
    if has_dashscope:
        configs["analyst"] = AgentConfig(provider="dashscope", model="qwen-max")
    elif has_openai:
        configs["analyst"] = AgentConfig(provider="openai", model="gpt-4o")
    elif has_deepseek:
        configs["analyst"] = AgentConfig(provider="deepseek", model="deepseek-chat")
    else:
        configs["analyst"] = configs["expert"]

    # Manager: 优先GPT-4 (报告生成好) > Claude > Qwen
    if has_openai:
        configs["manager"] = AgentConfig(provider="openai", model="gpt-4o")
    elif has_anthropic:
        configs["manager"] = AgentConfig(provider="anthropic", model="claude-sonnet-4-5")
    elif has_dashscope:
        configs["manager"] = AgentConfig(provider="dashscope", model="qwen-max")
    else:
        configs["manager"] = configs["expert"]

    # WhiteHat: 优先GLM (128K输出) > DeepSeek > Claude
    if has_zhipu:
        configs["white_hat"] = AgentConfig(provider="zhipu", model="glm-4.6", max_tokens=131072)
    elif has_deepseek:
        configs["white_hat"] = AgentConfig(provider="deepseek", model="deepseek-chat")
    elif has_anthropic:
        configs["white_hat"] = AgentConfig(provider="anthropic", model="claude-sonnet-4-5")
    else:
        configs["white_hat"] = configs["expert"]

    # Review: 优先DashScope/qwen-plus (高并发、中文好) > DeepSeek > Claude
    if has_dashscope:
        configs["review"] = AgentConfig(provider="dashscope", model="qwen-plus", max_tokens=32768)
    elif has_deepseek:
        configs["review"] = AgentConfig(provider="deepseek", model="deepseek-chat")
    elif has_anthropic:
        configs["review"] = AgentConfig(provider="anthropic", model="claude-sonnet-4-5")
    else:
        configs["review"] = configs["expert"]

    return configs


def print_available_providers():
    """打印当前可用的Provider"""
    providers = {
        "OpenAI": bool(os.getenv("OPENAI_API_KEY")),
        "Anthropic": bool(os.getenv("ANTHROPIC_API_KEY")),
        "DeepSeek": bool(os.getenv("DEEPSEEK_API_KEY")),
        "DashScope": bool(os.getenv("DASHSCOPE_API_KEY")),
        "ZhipuAI": bool(os.getenv("ZHIPU_API_KEY")),
        "Google": bool(os.getenv("GOOGLE_API_KEY")),
    }

    print("=" * 40)
    print("LLM Provider 可用性检测")
    print("=" * 40)
    for name, available in providers.items():
        status = "✅ 可用" if available else "❌ 未配置"
        print(f"  {name}: {status}")
    print("=" * 40)


# ============================================================================
# 模型信息
# ============================================================================

MODEL_INFO = {
    # OpenAI
    "gpt-4o": {"provider": "openai", "context": 128000, "cost": "$$"},
    "gpt-4o-mini": {"provider": "openai", "context": 128000, "cost": "$"},
    "o1": {"provider": "openai", "context": 128000, "cost": "$$$"},

    # Anthropic
    "claude-opus-4-5": {"provider": "anthropic", "context": 200000, "cost": "$$$", "input": 5, "output": 25},
    "claude-opus-4": {"provider": "anthropic", "context": 200000, "cost": "$$$", "input": 15, "output": 75},
    "claude-sonnet-4-5": {"provider": "anthropic", "context": 200000, "cost": "$$", "input": 3, "output": 15},
    "claude-sonnet-4": {"provider": "anthropic", "context": 200000, "cost": "$$", "input": 3, "output": 15},
    "claude-haiku-4-5": {"provider": "anthropic", "context": 200000, "cost": "$", "input": 1, "output": 5},
    "claude-haiku-3-5": {"provider": "anthropic", "context": 200000, "cost": "$", "input": 0.8, "output": 4},

    # DeepSeek
    "deepseek-chat": {"provider": "deepseek", "context": 64000, "cost": "$"},
    "deepseek-reasoner": {"provider": "deepseek", "context": 64000, "cost": "$"},

    # Google Gemini
    "gemini-3-flash": {"provider": "google", "context": 1000000, "cost": "$", "desc": "默认模型"},
    "gemini-3-pro": {"provider": "google", "context": 1000000, "cost": "$$", "desc": "推理优化"},
    "gemini-2.5-pro": {"provider": "google", "context": 1000000, "cost": "$$"},
    "gemini-2.5-flash": {"provider": "google", "context": 1000000, "cost": "$"},
    "gemini-2.5-flash-lite": {"provider": "google", "context": 1000000, "cost": "$", "desc": "低成本"},

    # ZhipuAI
    "glm-4.7": {"provider": "zhipu", "context": 200000, "max_output": 128000, "cost": "$", "desc": "高智能旗舰"},
    "glm-4.6": {"provider": "zhipu", "context": 200000, "max_output": 128000, "cost": "$", "desc": "超强性能"},

    # DashScope (阿里云)
    "qwen-max": {"provider": "dashscope", "context": 32000, "cost": "$"},
    "qwen-plus": {"provider": "dashscope", "context": 131072, "cost": "$"},
    "deepseek-v3.2": {"provider": "dashscope", "context": 64000, "cost": "$"},
}


def get_model_info(model: str) -> Optional[Dict]:
    """获取模型信息"""
    return MODEL_INFO.get(model)