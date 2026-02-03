"""
Multi-Agent Security Audit System

基于 LLM-SmartAudit 架构的多Agent智能合约安全审计系统。

Agent 架构 (v2.5.3):
支持两种架构，通过 AuditConfig.use_simplified_architecture 切换:

## 精简 3 Agent 架构 (默认，节省 ~68% Token)
- Auditor: Phase 2 漏洞扫描
- Verifier: Phase 3 多视角验证 (合并原 Auditor+Expert+Analyst)
- Manager: Phase 3 低置信度时介入
- WhiteHat: Phase 4 利用链验证

## 原 5 Agent 架构
- ManagerAgent: 项目管理，任务分配，报告生成
- AnalystAgent: 合约分析，调用图构建，依赖解析
- AuditorAgent: 漏洞检测，风险评估
- MoveExpertAgent: Move专家验证，修复建议
- WhiteHatAgent: 白帽黑客，漏洞利用链验证

工具系统:
- AgentToolkit: 为 Agent 提供代码上下文检索能力
- ToolResult: 工具调用结果
"""

import logging
import os

# 配置 agents 模块的日志
# 默认 INFO 级别，可通过环境变量 AGENTS_LOG_LEVEL 覆盖
_log_level = os.environ.get("AGENTS_LOG_LEVEL", "INFO").upper()
_log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# 配置 agents 命名空间下的所有 logger
_agents_logger = logging.getLogger("src.agents")
if not _agents_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(_log_format, datefmt="%H:%M:%S"))
    _agents_logger.addHandler(_handler)
    _agents_logger.setLevel(getattr(logging, _log_level, logging.INFO))

from .base_agent import BaseAgent, AgentRole, AgentMessage, AgentConfig
from .manager_agent import ManagerAgent
from .analyst_agent import AnalystAgent
from .auditor_agent import AuditorAgent
from .expert_agent import MoveExpertAgent
from .white_hat_agent import WhiteHatAgent, ExploitVerificationReport, VerificationStatus as ExploitVerificationStatus
from .engine import SecurityAuditEngine, AuditConfig, AuditResult, run_audit
from .tools import AgentToolkit, ToolResult, ToolDefinition

# 🔥 v2.5.11: 统一使用 3-Agent 架构 (role_swap.py 已移至 backup/)
from .verifier_agent import VerifierAgent
from .role_swap_v2 import RoleSwapMechanismV2, VerifiedFinding, VerificationStatus
# 兼容旧代码的别名
RoleSwapMechanism = RoleSwapMechanismV2

__all__ = [
    # Base
    "BaseAgent",
    "AgentRole",
    "AgentMessage",
    "AgentConfig",
    # Agents
    "ManagerAgent",
    "AnalystAgent",
    "AuditorAgent",
    "MoveExpertAgent",
    "WhiteHatAgent",
    "VerifierAgent",
    # Exploit Verification
    "ExploitVerificationReport",
    "ExploitVerificationStatus",
    # Role Swap Verification (3-Agent 架构)
    "RoleSwapMechanism",      # 兼容别名，指向 RoleSwapMechanismV2
    "RoleSwapMechanismV2",
    "VerifiedFinding",
    "VerificationStatus",
    # Engine
    "SecurityAuditEngine",
    "AuditConfig",
    "AuditResult",
    "run_audit",
    # Tools
    "AgentToolkit",
    "ToolResult",
    "ToolDefinition",
]
