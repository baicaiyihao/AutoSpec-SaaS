"""
SecurityAuditEngine - 安全审计主引擎

协调所有Agent完成完整的安全审计流程:
1. Manager制定审计计划
2. Analyst分析合约结构 (使用精准的调用图)
3. Auditor进行漏洞扫描 (BA + TA模式)
4. Expert验证发现
5. RoleSwap多轮验证减少误报
6. 生成最终报告

新增上下文系统:
- MoveProjectIndexer: 项目索引 (精准调用图 + 依赖解析)
- AgentToolkit: 统一工具箱 (代码检索、漏洞模式等)
- AgentToolkit: Agent 工具调用接口
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

logger = logging.getLogger(__name__)

from .base_agent import AgentConfig
from .manager_agent import ManagerAgent
from .analyst_agent import AnalystAgent
from .auditor_agent import AuditorAgent
from .expert_agent import MoveExpertAgent
from .white_hat_agent import WhiteHatAgent
from .tools import AgentToolkit, ToolResult
from src.utils.cache import analysis_cache, cache_key_for_code
from src.security.exclusion_rules import apply_exclusion_rules

# 🔥 v2.5.11: 统一使用 3-Agent 架构 (role_swap.py 已移至 backup/)
from .verifier_agent import VerifierAgent
from .role_swap_v2 import RoleSwapMechanismV2, VerifiedFinding, VerificationStatus

if TYPE_CHECKING:
    from src.context import MoveProjectIndexer


# =============================================================================
# 🔥 v2.6.0: 异常类
# =============================================================================

class AuditCancelledException(Exception):
    """审计被取消异常"""
    pass


@dataclass
class AuditConfig:
    """审计配置"""
    # 扫描模式
    enable_broad_analysis: bool = True      # BA模式
    enable_targeted_analysis: bool = True   # TA模式
    targeted_vuln_types: List[str] = field(default_factory=lambda: [
        # 核心漏洞类型
        "overflow", "access_control", "flash_loan",
        "price_manipulation", "slippage", "reentrancy",
        # DeFi 特定
        "first_deposit", "donation_attack", "rounding",
        # Move/Sui 特定
        "object_safety", "capability_leak", "witness_abuse"
    ])

    # 验证配置
    enable_role_swap: bool = True           # 启用角色交换验证
    enable_exploit_verification: bool = True  # 启用 WhiteHat 利用链验证
    min_confidence_threshold: int = 30      # 最低置信度阈值 (Phase 3 会过滤误报)

    # 并发配置 - 从 src/config.py 的 AUDIT_CONCURRENCY 读取默认值
    # 修改并发参数请编辑 src/config.py
    max_concurrent_scan: int = None         # Phase 2 扫描并发数
    max_concurrent_verify: int = None       # Phase 3 验证并发数
    max_concurrent_exploit: int = None      # Phase 4 利用链验证并发数
    batch_size: int = None                  # 分批大小
    batch_cooldown: float = None            # 批次间冷却秒数

    def __post_init__(self):
        """从 config.py 加载默认并发配置"""
        from src.config import AUDIT_CONCURRENCY
        if self.max_concurrent_scan is None:
            self.max_concurrent_scan = AUDIT_CONCURRENCY["max_concurrent_scan"]
        if self.max_concurrent_verify is None:
            self.max_concurrent_verify = AUDIT_CONCURRENCY["max_concurrent_verify"]
        if self.max_concurrent_exploit is None:
            self.max_concurrent_exploit = AUDIT_CONCURRENCY["max_concurrent_exploit"]
        if self.batch_size is None:
            self.batch_size = AUDIT_CONCURRENCY["batch_size"]
        if self.batch_cooldown is None:
            self.batch_cooldown = AUDIT_CONCURRENCY["batch_cooldown"]

    # 输出配置
    output_dir: str = "reports/security_audits"
    generate_markdown: bool = True
    generate_json: bool = True

    # 模型预设 (新增)
    # 可选: "auto", "claude", "deepseek", "hybrid", "china", "local", "qwen"
    model_preset: str = "qwen"

    # 上下文系统配置 (新增)
    enable_context_system: bool = True      # 启用精准上下文检索
    callgraph_cache_dir: Optional[str] = None  # 调用图缓存目录
    max_context_tokens: int = 100000        # 最大上下文 token 数 (适配 128K 模型)

    # 🔥 v2.5.11: 已统一为 3-Agent 架构，此配置已废弃 (保留以兼容旧代码)
    # 原 5-Agent 架构 (role_swap.py) 已移至 backup/ 目录
    use_simplified_architecture: bool = True  # 已废弃，始终使用 3-Agent

    # 🔥 v2.5.8: Phase 2 批量扫描配置
    scan_batch_size: int = 5  # 每批扫描的函数数量


# =============================================================================
# 🔥 v2.5.8: Phase 2 批量扫描数据结构
# =============================================================================

@dataclass
class BatchScanResult:
    """单批次扫描结果"""
    batch_id: int
    module_name: str
    functions: List[str]                      # 该批次的函数名列表
    function_contexts: Dict[str, Dict]        # {func_name: context}
    findings: List[Dict[str, Any]]            # 发现的漏洞
    cross_function_issues: List[Dict[str, Any]]  # 跨函数漏洞链
    safe_functions: List[str]                 # 安全的函数列表

    def get_functions_with_findings(self) -> List[str]:
        """获取有漏洞的函数列表"""
        funcs_with_findings = set()
        for f in self.findings:
            loc = f.get("location", {})
            func = loc.get("function", "")
            if func:
                funcs_with_findings.add(func)
        return list(funcs_with_findings)


@dataclass
class ModuleScanResult:
    """模块扫描结果"""
    module_name: str
    total_functions: int
    batches: List[BatchScanResult]

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """获取该模块所有漏洞"""
        all_findings = []
        for batch in self.batches:
            all_findings.extend(batch.findings)
            all_findings.extend(batch.cross_function_issues)
        return all_findings

    def get_functions_with_findings(self) -> Dict[str, List[Dict]]:
        """获取有漏洞的函数及其上下文 {func_name: [findings]}"""
        result = {}
        for batch in self.batches:
            for finding in batch.findings:
                loc = finding.get("location", {})
                func = loc.get("function", "")
                if func:
                    if func not in result:
                        result[func] = []
                    # 附加上下文信息
                    finding["_batch_context"] = batch.function_contexts.get(func, {})
                    result[func].append(finding)
        return result


@dataclass
class Phase2Result:
    """Phase 2 完整结果 (供 Phase 3 使用)"""
    modules: Dict[str, ModuleScanResult]      # {module_name: ModuleScanResult}
    total_findings: int
    total_functions_scanned: int
    functions_with_findings: int

    def get_findings_for_phase3(self) -> List[Dict[str, Any]]:
        """
        获取 Phase 3 需要验证的漏洞列表

        返回格式: 每个 finding 包含:
        - 原始漏洞信息
        - _phase2_context: 函数代码上下文
        - _module_name: 所属模块
        - _batch_id: 所属批次
        """
        findings = []
        for module_name, module_result in self.modules.items():
            for batch in module_result.batches:
                for finding in batch.findings:
                    finding["_module_name"] = module_name
                    finding["_batch_id"] = batch.batch_id
                    # 附加函数上下文
                    func = finding.get("location", {}).get("function", "")
                    if func and func in batch.function_contexts:
                        ctx = batch.function_contexts[func]
                        finding["_phase2_context"] = self._serialize_context(ctx)
                    findings.append(finding)
                # 也包含跨函数漏洞
                for issue in batch.cross_function_issues:
                    issue["_module_name"] = module_name
                    issue["_batch_id"] = batch.batch_id
                    issue["_is_cross_function"] = True
                    findings.append(issue)
        return findings

    def _serialize_context(self, ctx: Dict) -> str:
        """序列化函数上下文为字符串"""
        parts = []
        if ctx.get("function_code"):
            parts.append(f"// 函数实现:\n{ctx['function_code']}")
        if ctx.get("callers"):
            parts.append(f"// 调用者: {', '.join(ctx['callers'][:3])}")
        if ctx.get("callees"):
            parts.append(f"// 调用: {', '.join(ctx['callees'][:3])}")
        return "\n".join(parts) if parts else ""


@dataclass
class AuditResult:
    """审计结果"""
    project_name: str
    audit_timestamp: str

    # 分析结果
    contract_analysis: Dict[str, Any]
    callgraph: Dict[str, Any]

    # 发现
    raw_findings: List[Dict[str, Any]]
    verified_findings: List[VerifiedFinding]

    # WhiteHat 利用链验证结果
    exploit_verifications: List[Dict[str, Any]] = field(default_factory=list)

    # 统计
    statistics: Dict[str, Any] = field(default_factory=dict)

    # 报告
    final_report: Dict[str, Any] = field(default_factory=dict)
    report_dir: Optional[str] = None  # 报告输出目录路径

    # 元数据
    audit_config: Optional[AuditConfig] = None
    duration_seconds: float = 0.0


class SecurityAuditEngine:
    """
    安全审计主引擎

    协调多个Agent完成智能合约安全审计。

    使用示例:
    ```python
    # 方式1: 使用预设
    config = AuditConfig(model_preset="china")  # 国内方案
    engine = SecurityAuditEngine(config=config)

    # 方式2: 自定义每个Agent的模型
    agent_configs = {
        "manager": AgentConfig(provider="dashscope", model="qwen-max"),
        "analyst": AgentConfig(provider="dashscope", model="qwen-max"),
        "auditor": AgentConfig(provider="deepseek", model="deepseek-chat"),
        "expert": AgentConfig(provider="anthropic", model="claude-sonnet-4-20250514"),
    }
    engine = SecurityAuditEngine(agent_configs=agent_configs)
    ```
    """

    def __init__(
        self,
        config: Optional[AuditConfig] = None,
        agent_configs: Optional[Dict[str, AgentConfig]] = None,
        agent_config: Optional[AgentConfig] = None,  # 向后兼容
        project_path: Optional[str] = None,  # 项目路径
        progress_callback: Optional[Callable[[int, float, str], None]] = None,  # 🔥 v2.6.0: 进度回调
        api_keys: Optional[Dict[str, str]] = None  # 🔥 用户自定义 API Keys
    ):
        self.config = config or AuditConfig()
        self.project_path = project_path
        self.api_keys = api_keys  # 保存 API Keys 供后续使用

        # 🔥 v2.6.0: 进度回调和取消机制 (Web API 支持)
        self.progress_callback = progress_callback
        self._cancelled = False
        self._current_phase = 0
        self._total_phases = 6  # Phase 0-5

        # 获取Agent配置
        configs = self._resolve_agent_configs(agent_configs, agent_config)

        # 🔥 v2.5.11: 统一使用 3-Agent 架构 (role_swap.py 已移至 backup/)
        print("  🔥 使用精简 3 Agent 架构 (v2.5.3)")

        # 初始化核心 Agents
        self.manager = ManagerAgent(configs.get("manager"))
        self.analyst = AnalystAgent(configs.get("analyst"))
        self.auditor = AuditorAgent(configs.get("auditor"))  # Phase 2 扫描
        self.white_hat = WhiteHatAgent(config=configs.get("white_hat"), use_tools=True)
        self.verifier = VerifierAgent(configs.get("verifier", configs.get("auditor")))
        self.expert = None  # 3-Agent 架构不需要单独的 Expert

        # 初始化角色交换机制 (Phase 3)
        self.role_swap = RoleSwapMechanismV2(
            verifier=self.verifier,
            manager=self.manager,
            use_tools=True
        )

        # 上下文系统 (延迟初始化)
        self.indexer: Optional["MoveProjectIndexer"] = None
        self.toolkit: Optional[AgentToolkit] = None

        # 安全扫描器 (延迟初始化)
        self.security_scanner = None

    # =========================================================================
    # 🔥 v2.6.0: 进度控制和取消机制 (Web API 支持)
    # =========================================================================

    def cancel(self):
        """
        请求取消审计

        调用后，审计将在当前 Phase 完成后终止。
        """
        self._cancelled = True
        print("⚠️ 收到取消请求，将在当前阶段完成后终止...")

    def is_cancelled(self) -> bool:
        """检查是否已请求取消"""
        return self._cancelled

    def _report_progress(self, phase: int, percent: float, message: str):
        """
        报告进度

        Args:
            phase: 当前阶段 (0-5)
            percent: 总进度百分比 (0-100)
            message: 进度消息
        """
        self._current_phase = phase
        if self.progress_callback:
            try:
                self.progress_callback(phase, percent, message)
            except Exception as e:
                print(f"⚠️ 进度回调失败: {e}")

    def _check_cancelled(self):
        """
        检查是否已取消，如果是则抛出异常

        Raises:
            AuditCancelledException: 如果审计已被取消
        """
        if self._cancelled:
            raise AuditCancelledException("审计已被用户取消")

    def _init_security_scanner(self) -> bool:
        """初始化安全扫描器 (向量库)"""
        try:
            from src.security.pattern_scan import SecurityScanner
            print("  🔍 初始化安全扫描器...")
            self.security_scanner = SecurityScanner(use_vector_db=True)
            return True
        except Exception as e:
            print(f"    ⚠️ 安全扫描器初始化失败: {e}")
            return False

    def _init_context_system(self, project_path: str) -> bool:
        """
        初始化上下文系统

        Args:
            project_path: Move 项目路径

        Returns:
            是否初始化成功
        """
        if not self.config.enable_context_system:
            return False

        try:
            from src.context import MoveProjectIndexer

            print("  📚 初始化上下文系统...")

            # 创建索引器
            self.indexer = MoveProjectIndexer(
                project_path,
                callgraph_cache_dir=self.config.callgraph_cache_dir
            )
            self.indexer.index_project(build_callgraph=True)

            # 初始化安全扫描器 (如果还没初始化)
            if not self.security_scanner:
                self._init_security_scanner()

            # 创建统一工具箱 (整合代码索引 + 安全向量库)
            self.toolkit = AgentToolkit(
                self.indexer,
                security_scanner=self.security_scanner
            )

            print(f"    ✓ 索引完成: {len(self.indexer.modules)} 模块, {len(self.indexer.chunks)} 函数")

            # 🔥 打印详细的模块和函数列表
            print(f"\n    📋 索引详情:")
            for module_name, module_info in self.indexer.modules.items():
                func_count = len(module_info.functions)
                print(f"      📦 {module_name} ({func_count} 函数)")
                for func in module_info.functions:
                    func_name = func.get("name", "unknown")
                    visibility = func.get("visibility", "private")
                    vis_icon = "🔓" if "public" in visibility else "🔒"
                    print(f"        {vis_icon} {func_name} [{visibility}]")

            # 🔥 打印跨模块调用边 (帮助理解漏洞传播路径)
            if self.indexer.callgraph:
                edges = self.indexer.callgraph.get("edges", [])
                cross_module_edges = []
                for edge in edges:
                    from_func = edge.get("from", "")
                    to_func = edge.get("to", "")
                    # 提取模块名
                    from_module = from_func.split("::")[1] if "::" in from_func else ""
                    to_module = to_func.split("::")[1] if "::" in to_func else ""
                    # 检查是否跨模块
                    if from_module and to_module and from_module != to_module:
                        cross_module_edges.append((from_func, to_func))

                if cross_module_edges:
                    print(f"\n    🔗 跨模块调用 ({len(cross_module_edges)} 条):")
                    for from_f, to_f in cross_module_edges:
                        print(f"      {from_f} → {to_f}")
                elif edges:
                    print(f"\n    📈 模块内调用: {len(edges)} 条边")

            if self.security_scanner:
                print(f"    ✓ 安全向量库已整合")
            return True

        except Exception as e:
            print(f"    ⚠️ 上下文系统初始化失败: {e}")
            return False

    def _resolve_agent_configs(
        self,
        agent_configs: Optional[Dict[str, AgentConfig]],
        agent_config: Optional[AgentConfig]
    ) -> Dict[str, AgentConfig]:
        """
        解析Agent配置

        优先级:
        1. agent_configs (每个Agent单独配置)
        2. model_preset (预设方案)
        3. agent_config (统一配置，向后兼容)
        4. 默认配置
        """
        # 如果提供了每个Agent的配置，直接使用
        if agent_configs:
            return agent_configs

        # 尝试使用预设方案
        preset = self.config.model_preset
        if preset and preset != "auto":
            try:
                from src.config import get_agent_configs
                return get_agent_configs(preset, api_keys=self.api_keys)
            except ImportError:
                print(f"[Warning] 无法加载预设 '{preset}'，使用默认配置")

        # auto模式: 尝试自动检测
        if preset == "auto":
            try:
                from src.config import get_agent_configs
                return get_agent_configs("auto", api_keys=self.api_keys)
            except ImportError:
                pass

        # 向后兼容: 统一配置
        if agent_config:
            return {
                "manager": agent_config,
                "analyst": agent_config,
                "auditor": agent_config,
                "expert": agent_config,
            }

        # 默认: 空配置 (各Agent使用自己的默认值)
        return {}

    async def audit(
        self,
        code: str,
        project_name: str = "Unknown",
        context: Optional[Dict[str, Any]] = None,
        project_path: Optional[str] = None  # 新增：项目路径
    ) -> AuditResult:
        """
        执行完整的安全审计

        Args:
            code: Move源代码
            project_name: 项目名称
            context: 额外上下文信息
            project_path: Move 项目路径 (用于精准上下文检索)

        Returns:
            审计结果
        """
        start_time = datetime.now()

        # 🔥 v2.5.3: 启动日志捕获
        self._start_log_capture()

        # 🔥 v2.6.0: 重置取消标志
        self._cancelled = False

        print(f"\n{'='*60}")
        print(f"🔐 开始安全审计: {project_name}")
        print(f"{'='*60}")

        # Phase 0: 初始化系统
        self._check_cancelled()
        self._report_progress(0, 5, "Phase 0: 初始化系统")
        print("\n📦 Phase 0: 初始化系统")

        # 初始化安全扫描器 (向量库)
        if not self.security_scanner:
            self._init_security_scanner()

        # 初始化上下文系统 (如果提供了项目路径)
        effective_project_path = project_path or self.project_path
        if effective_project_path and self.config.enable_context_system:
            self._init_context_system(effective_project_path)
            # 🔥 将 toolkit 传给 role_swap，用于 Phase 3 智能上下文提取
            if self.toolkit:
                self.role_swap.toolkit = self.toolkit
                print("  ✓ Phase 3 将使用统一工具箱进行上下文检索")

        # Phase 1: 合约分析
        self._check_cancelled()
        self._report_progress(1, 15, "Phase 1: 合约结构分析")
        print("\n📊 Phase 1: 合约结构分析")
        contract_analysis = await self._analyze_contract(code, context)

        # Phase 1.5: 🔥 智能预分析 - 提取关键信息指导后续分析
        self._check_cancelled()
        self._report_progress(1, 25, "Phase 1.5: 智能预分析")
        print("\n🧠 Phase 1.5: 智能预分析 (提取关键信息)")
        analysis_hints = await self._extract_analysis_hints(code)
        if analysis_hints:
            # 保存到 contract_analysis 中，供后续 Agent 使用
            contract_analysis["analysis_hints"] = analysis_hints
            # 打印摘要
            self._print_hints_summary(analysis_hints)

        # 使用精准调用图 (如果上下文系统可用)
        if self.indexer and self.indexer.callgraph:
            callgraph = self.indexer.callgraph
            mode = callgraph.get("meta", {}).get("mode", "unknown")
            print(f"  使用精准调用图 ({mode})")

            # 🔥 打印调用图摘要
            nodes = callgraph.get("nodes", [])
            edges = callgraph.get("edges", [])
            print(f"\n  📈 调用图摘要: {len(nodes)} 节点, {len(edges)} 边")

            # 按模块分组显示调用关系
            module_calls = {}
            for node in nodes:
                module = node.get("module_name", "unknown")
                func = node.get("name", "unknown")
                calls = node.get("calls", [])
                called_by = node.get("called_by", [])

                if module not in module_calls:
                    module_calls[module] = []
                module_calls[module].append({
                    "name": func,
                    "calls": calls,
                    "called_by": called_by
                })

            for module, funcs in module_calls.items():
                print(f"    📦 {module}:")
                for f in funcs:
                    calls_str = ", ".join(f["calls"][:3]) if f["calls"] else "无"
                    if len(f["calls"]) > 3:
                        calls_str += f" (+{len(f['calls'])-3})"
                    print(f"      → {f['name']} 调用: [{calls_str}]")
        else:
            print("  使用 LLM 生成调用图 (fallback)")
            callgraph = await self._build_callgraph(code)

        # Phase 1.6: 函数功能分析 (让 Agent 描述每个函数的功能)
        self._check_cancelled()
        self._report_progress(1, 35, "Phase 1.6: 函数功能分析")
        if self.indexer and self.indexer.callgraph:
            nodes = self.indexer.callgraph.get("nodes", [])
            if nodes:
                print("\n📋 Phase 1.6: 函数功能分析")
                functions = [
                    {"id": n.get("id", n.get("name")), "name": n.get("name"), "signature": n.get("signature", n.get("name"))}
                    for n in nodes
                ]
                function_purposes = await self.analyst.analyze_function_purposes(functions, code)
                if function_purposes:
                    contract_analysis["function_purposes"] = function_purposes
                    print(f"  ✓ 分析了 {len(function_purposes)} 个函数的功能")
                    # 打印前 5 个示例
                    for i, (func_id, desc) in enumerate(list(function_purposes.items())[:5]):
                        print(f"    • {func_id}: {desc[:50]}..." if len(desc) > 50 else f"    • {func_id}: {desc}")
                    if len(function_purposes) > 5:
                        print(f"    ... 还有 {len(function_purposes) - 5} 个函数")

        # 🔥 Phase 1 完成后，更新 toolkit 的 contract_analysis
        if self.toolkit:
            self.toolkit.set_contract_analysis(contract_analysis)
            print("  ✓ 分析数据已同步到工具箱，后续 Agent 可自主检索")

            # 🔥 v2.5.3: 为各 Agent 注入 toolkit (根据架构选择)
            self.auditor.set_toolkit(self.toolkit)  # Phase 2 扫描需要
            self.analyst.set_toolkit(self.toolkit)
            self.white_hat.set_toolkit(self.toolkit)
            self.verifier.set_toolkit(self.toolkit)  # Phase 3 验证需要

        # Phase 2: 漏洞扫描
        self._check_cancelled()
        self._report_progress(2, 45, "Phase 2: 漏洞扫描")
        print("\n🔍 Phase 2: 漏洞扫描")
        raw_findings = await self._scan_vulnerabilities(code, contract_analysis)
        print(f"  发现 {len(raw_findings)} 个潜在问题")

        # Phase 3: 验证发现 (使用角色交换)
        self._check_cancelled()
        self._report_progress(3, 55, "Phase 3: 多Agent验证")
        verified_findings = []
        early_filtered = []
        if raw_findings:
            # 🔥 早期过滤明显的 Sui Move 误报
            to_verify, early_filtered = self._filter_obvious_false_positives(raw_findings)

            if self.config.enable_role_swap and to_verify:
                print(f"\n✅ Phase 3: 多Agent验证 ({len(to_verify)} 待验证, {len(early_filtered)} 已过滤)")
                verified_findings = await self.role_swap.batch_verify(
                    to_verify, code,
                    max_concurrent=self.config.max_concurrent_verify,
                    batch_size=self.config.batch_size,
                    batch_cooldown=self.config.batch_cooldown
                )
            elif to_verify:
                print(f"\n✅ Phase 3: 快速验证 ({len(to_verify)} 待验证)")
                verified_findings = await self._quick_verify(to_verify, code)

            # 将早期过滤的结果转换为 VerifiedFinding 并合并
            for f in early_filtered:
                # 🔥 v2.5.6: 使用实际的规则原因，而非硬编码
                early_filter_info = f.get("early_filter", {})
                filter_reason = early_filter_info.get("reason", "Sui Move 语言层面保护")
                rule_name = early_filter_info.get("rule_name", "unknown")

                verified_findings.append(VerifiedFinding(
                    original_finding=f,
                    verification_status=VerificationStatus.FALSE_POSITIVE,
                    swap_rounds=[],
                    final_severity=f.get("severity", "low"),
                    final_confidence=95,
                    verifier_result={"early_filtered": True, "reason": filter_reason, "rule": rule_name},
                    manager_verdict={"decision": "false_positive", "reason": filter_reason}
                ))

        # Phase 4: WhiteHat 利用链验证
        self._check_cancelled()
        self._report_progress(4, 75, "Phase 4: WhiteHat 利用链验证")
        exploit_verifications = []
        if verified_findings and self.config.enable_exploit_verification:
            print("\n🎩 Phase 4: WhiteHat 利用链验证")
            # 🔥 传递 contract_analysis，让 WhiteHat 使用 Phase 1.5 的预分析结果
            exploit_verifications = await self._verify_exploits(verified_findings, code, contract_analysis)

        # Phase 5: 生成报告
        self._check_cancelled()
        self._report_progress(5, 90, "Phase 5: 生成报告")
        print("\n📝 Phase 5: 生成报告")
        statistics = self._calculate_statistics(verified_findings, exploit_verifications)
        final_report = self._generate_report(verified_findings, contract_analysis, exploit_verifications)

        # 计算耗时
        duration = (datetime.now() - start_time).total_seconds()

        result = AuditResult(
            project_name=project_name,
            audit_timestamp=start_time.isoformat(),
            contract_analysis=contract_analysis,
            callgraph=callgraph,
            raw_findings=raw_findings,
            verified_findings=verified_findings,
            exploit_verifications=exploit_verifications,
            statistics=statistics,
            final_report=final_report,
            audit_config=self.config,
            duration_seconds=duration
        )

        # 🔥 v2.6.0: 审计完成进度回调
        self._report_progress(5, 100, f"审计完成，耗时 {duration:.1f}s")

        # 🔥 v2.5.8: 先打印摘要 (包含 token 统计)，这样会被日志捕获
        self._print_summary(result)

        # 保存报告
        if self.config.generate_markdown or self.config.generate_json:
            await self._save_reports(result)

        return result

    async def _analyze_contract(
        self,
        code: str,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """分析合约结构"""
        print("  分析合约结构...")
        analysis = await self.analyst.analyze_contract(code)
        return analysis

    async def _extract_analysis_hints(self, code: str) -> Optional[Dict[str, Any]]:
        """
        🔥 智能预分析：提取关键信息指导后续漏洞分析（带缓存）

        如果上下文系统可用，利用已有的调用图信息进行更准确的分析。

        调用 AnalystAgent.extract_analysis_hints() 自动提取：
        - 关键状态变量
        - 条件阈值
        - 跨函数数据流
        - 权限/状态变更点
        - 潜在漏洞链

        Returns:
            analysis_hints: 分析提示，供后续 Agent 使用
        """
        # 🔥 检查缓存
        cache_key = cache_key_for_code(code, "analysis_hints")
        cached = analysis_cache.get(cache_key)
        if cached:
            print("  📦 使用缓存的预分析结果")
            return cached

        try:
            # 🔥 如果上下文系统可用，利用调用图信息增强分析
            callgraph_context = None
            if self.indexer and self.indexer.callgraph:
                callgraph = self.indexer.callgraph
                nodes = callgraph.get("nodes", [])

                # 提取关键信息：高风险函数、调用关系
                high_risk_funcs = []
                fund_related_funcs = []
                state_modifying_funcs = []

                for node in nodes:
                    name = node.get("name", "")
                    risk_score = node.get("risk_score", 0)
                    indicators = node.get("risk_indicators", {})

                    if risk_score >= 5:
                        high_risk_funcs.append({
                            "name": f"{node.get('module_name', '')}::{name}",
                            "risk_score": risk_score,
                            "indicators": indicators
                        })

                    # 识别资金相关函数
                    if any(k in indicators for k in ["handles_coin", "handles_balance", "transfer"]):
                        fund_related_funcs.append(name)

                    # 识别状态修改函数
                    if indicators.get("modifies_shared_state"):
                        state_modifying_funcs.append(name)

                callgraph_context = f"""
## 已分析的调用图信息 (请基于此进行更深入分析)

### 高风险函数 ({len(high_risk_funcs)} 个):
{chr(10).join([f"- {f['name']} (风险分: {f['risk_score']}, 指标: {f['indicators']})" for f in high_risk_funcs[:10]])}

### 资金相关函数:
{', '.join(fund_related_funcs[:10]) if fund_related_funcs else '无'}

### 状态修改函数:
{', '.join(state_modifying_funcs[:10]) if state_modifying_funcs else '无'}
"""
                print("  使用上下文系统的调用图信息增强预分析...")
            else:
                print("  提取关键状态变量、条件阈值、数据流...")

            hints = await self.analyst.extract_analysis_hints(code, callgraph_context)
            if hints and not hints.get("error"):
                # 🔥 缓存结果
                analysis_cache.set(cache_key, hints)
                return hints
            else:
                print("  ⚠️ 预分析未返回有效结果，继续使用默认分析")
                return None
        except Exception as e:
            print(f"  ⚠️ 预分析失败: {e}，继续使用默认分析")
            return None

    def _print_hints_summary(self, hints: Dict[str, Any]):
        """打印预分析结果摘要"""
        print("  ✓ 预分析完成:")

        # 关键状态变量
        state_vars = hints.get("key_state_variables", [])
        if state_vars:
            print(f"    📌 关键状态变量: {len(state_vars)} 个")
            for v in state_vars[:3]:
                print(f"       - {v.get('name', '?')} ({v.get('type', '?')}): {v.get('security_relevance', '')[:50]}")
            if len(state_vars) > 3:
                print(f"       ... 还有 {len(state_vars) - 3} 个")

        # 条件阈值
        thresholds = hints.get("condition_thresholds", [])
        if thresholds:
            print(f"    📌 条件阈值: {len(thresholds)} 个")
            for t in thresholds[:2]:
                cond = t.get('condition', '?')[:40]
                print(f"       - {cond}...")

        # 跨函数数据流
        dataflows = hints.get("cross_function_dataflow", [])
        if dataflows:
            print(f"    📌 跨函数数据流: {len(dataflows)} 条")
            for df in dataflows[:2]:
                flow = df.get('flow', '?')[:50]
                print(f"       - {flow}")

        # 状态变更点
        state_changes = hints.get("state_change_points", [])
        if state_changes:
            print(f"    📌 状态变更点: {len(state_changes)} 个")

        # 潜在漏洞链
        vuln_chains = hints.get("potential_vuln_chains", [])
        if vuln_chains:
            print(f"    📌 潜在漏洞链: {len(vuln_chains)} 条")
            for vc in vuln_chains[:2]:
                chain = vc.get('chain', '?')[:60]
                print(f"       - {chain}")

        # 分析总结
        summary = hints.get("analysis_summary", "")
        if summary:
            print(f"    📝 总结: {summary[:100]}...")

    async def _build_callgraph(self, code: str) -> Dict[str, Any]:
        """构建调用图"""
        print("  构建调用图...")
        callgraph = await self.analyst.build_callgraph(code)
        return callgraph

    async def _scan_vulnerabilities(
        self,
        code: str,
        contract_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        扫描漏洞

        🔥 优先使用上下文系统进行函数级精准分析
        如果上下文系统不可用，则回退到 BA + TA 模式
        """
        # 🔥 如果有上下文系统，使用函数级精准分析
        if self.toolkit and self.indexer and self.indexer.callgraph:
            print("  📌 使用上下文系统进行函数级精准分析")
            return await self._scan_with_context()

        # 回退到传统的 BA + TA 模式
        print("  📌 使用传统 BA + TA 模式 (无上下文系统)")
        return await self._scan_legacy(code, contract_analysis)

    async def _scan_with_context(self) -> List[Dict[str, Any]]:
        """
        🔥 v2.5.8: 基于上下文系统的批量漏洞扫描

        优化: 按模块分批扫描，每批 N 个函数一次 LLM 调用
        - 原: 339 函数 = 339 次 LLM 调用
        - 新: 339 函数 ÷ 5 = 68 次 LLM 调用 (节省 ~80%)

        流程:
        1. 按模块分组函数
        2. 每个模块按批次调用 auditor.analyze_functions_batch()
        3. 构建 Phase2Result 供 Phase 3 使用
        """
        callgraph = self.indexer.callgraph
        nodes = callgraph.get("nodes", [])
        batch_size = self.config.scan_batch_size  # 默认 5

        # ============================================================
        # Step 1: 按模块分组并过滤
        # ============================================================
        modules = {}
        for node in nodes:
            module_name = node.get("module_name", "unknown")
            if module_name not in modules:
                modules[module_name] = []
            modules[module_name].append(node)

        # 按风险分数排序
        for module_name in modules:
            modules[module_name].sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        total_functions = sum(len(funcs) for funcs in modules.values())
        print(f"\n  📊 共 {len(modules)} 个模块, {total_functions} 个函数")

        # 过滤并准备函数上下文
        module_contexts = {}  # {module: [(func_name, func_context, func_node)]}
        skipped_test = 0
        skipped_low_risk = 0

        for module_name, funcs in modules.items():
            module_contexts[module_name] = []
            for func_node in funcs:
                func_name = func_node.get("name", "unknown")
                visibility = func_node.get("visibility", "private")
                risk_score = func_node.get("risk_score", 0)

                # 跳过测试函数
                if func_name.startswith("test_") or func_name.endswith("_test") or func_name.endswith("_for_test"):
                    skipped_test += 1
                    continue
                uses = func_node.get("uses", [])
                if any("test_only" in u or "#[test" in str(u) for u in uses):
                    skipped_test += 1
                    continue
                module_path = func_node.get("module_path", "")
                if "/tests/" in module_path or module_path.endswith("_tests.move"):
                    skipped_test += 1
                    continue

                # 🔥 v2.5.10: 不再跳过私有函数，因为私有函数也可能有漏洞
                # 例如 math_utils::check 是私有的但包含关键逻辑漏洞
                # if "private" in visibility and risk_score < 10:
                #     skipped_low_risk += 1
                #     continue

                # 构建函数上下文
                func_context = self._build_function_context(module_name, func_node)
                module_contexts[module_name].append((func_name, func_context, func_node))

        # 统计
        total_to_scan = sum(len(funcs) for funcs in module_contexts.values())
        if skipped_test > 0:
            print(f"  ⏭️ 跳过 {skipped_test} 个测试函数")
        if skipped_low_risk > 0:
            print(f"  ⏭️ 跳过 {skipped_low_risk} 个私有低风险函数")

        # ============================================================
        # Step 2: 按模块分批扫描
        # ============================================================
        total_batches = sum(
            (len(funcs) + batch_size - 1) // batch_size
            for funcs in module_contexts.values() if funcs
        )
        print(f"\n  🔍 开始批量扫描: {total_to_scan} 函数, {total_batches} 批次 (每批 {batch_size} 函数)")

        all_findings = []
        phase2_modules = {}  # 构建 Phase2Result
        completed_batches = 0

        max_concurrent = self.config.max_concurrent_scan
        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_batch(module_name: str, batch_id: int, batch_funcs: List[Tuple]) -> BatchScanResult:
            """扫描单个批次"""
            nonlocal completed_batches

            func_contexts = []
            context_map = {}

            for func_name, func_context, func_node in batch_funcs:
                func_contexts.append(func_context)
                context_map[func_name] = func_context

            async with semaphore:
                try:
                    # 调用批量分析
                    result = await self.auditor.analyze_functions_batch(func_contexts, batch_id)

                    # 解析结果
                    findings = []
                    results_map = result.get("results", {})
                    for func_id, func_findings in results_map.items():
                        for finding in func_findings:
                            # 附加模块和上下文信息
                            finding["_module_name"] = module_name
                            finding["_batch_id"] = batch_id
                            func_name = finding.get("location", {}).get("function", "")
                            if func_name and func_name in context_map:
                                finding["_phase2_context"] = self._serialize_func_context(context_map[func_name])
                                finding["_phase2_func_context"] = context_map[func_name]
                            findings.append(finding)

                    cross_issues = result.get("cross_function_issues", [])
                    for issue in cross_issues:
                        issue["_module_name"] = module_name
                        issue["_batch_id"] = batch_id
                        issue["_is_cross_function"] = True

                    safe_funcs = result.get("safe_functions", [])

                    completed_batches += 1
                    func_names = [f[0] for f in batch_funcs]
                    finding_count = len(findings) + len(cross_issues)

                    if finding_count > 0:
                        print(f"  🔴 [{completed_batches}/{total_batches}] {module_name} 批次{batch_id}: {finding_count} 个发现 ({func_names})")
                    else:
                        print(f"  ✓ [{completed_batches}/{total_batches}] {module_name} 批次{batch_id}: 安全 ({func_names})")

                    return BatchScanResult(
                        batch_id=batch_id,
                        module_name=module_name,
                        functions=[f[0] for f in batch_funcs],
                        function_contexts=context_map,
                        findings=findings,
                        cross_function_issues=cross_issues,
                        safe_functions=safe_funcs
                    )
                except Exception as e:
                    completed_batches += 1
                    print(f"  ⚠️ [{completed_batches}/{total_batches}] {module_name} 批次{batch_id}: 失败 - {e}")
                    return BatchScanResult(
                        batch_id=batch_id,
                        module_name=module_name,
                        functions=[f[0] for f in batch_funcs],
                        function_contexts=context_map,
                        findings=[],
                        cross_function_issues=[],
                        safe_functions=[]
                    )

        # 创建所有批次任务
        batch_tasks = []
        for module_name, funcs in module_contexts.items():
            if not funcs:
                continue

            print(f"\n  📦 模块: {module_name} ({len(funcs)} 函数)")

            # 分批
            num_batches = (len(funcs) + batch_size - 1) // batch_size
            for batch_id in range(num_batches):
                start_idx = batch_id * batch_size
                end_idx = min(start_idx + batch_size, len(funcs))
                batch_funcs = funcs[start_idx:end_idx]
                batch_tasks.append((module_name, batch_id + 1, batch_funcs))

        # 并发执行所有批次
        print(f"\n  ⚡ 并发扫描: {len(batch_tasks)} 批次, 最大并发 {max_concurrent}")

        tasks = [scan_batch(m, bid, bf) for m, bid, bf in batch_tasks]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        # ============================================================
        # Step 3: 收集结果，构建 Phase2Result
        # ============================================================
        for result in batch_results:
            if isinstance(result, Exception):
                print(f"  ⚠️ 批次异常: {result}")
                continue

            if isinstance(result, BatchScanResult):
                module_name = result.module_name

                # 添加到模块结果
                if module_name not in phase2_modules:
                    phase2_modules[module_name] = ModuleScanResult(
                        module_name=module_name,
                        total_functions=len(module_contexts.get(module_name, [])),
                        batches=[]
                    )
                phase2_modules[module_name].batches.append(result)

                # 收集所有发现
                all_findings.extend(result.findings)
                all_findings.extend(result.cross_function_issues)

        # 构建 Phase2Result (供后续使用)
        self._phase2_result = Phase2Result(
            modules=phase2_modules,
            total_findings=len(all_findings),
            total_functions_scanned=total_to_scan,
            functions_with_findings=len(set(
                f.get("location", {}).get("function", "")
                for f in all_findings if f.get("location", {}).get("function")
            ))
        )

        # 去重和过滤
        unique_findings = self._deduplicate_findings(all_findings)
        filtered = [
            f for f in unique_findings
            if f.get("confidence", 0) >= self.config.min_confidence_threshold
        ]

        print(f"\n  📊 Phase 2 完成: {len(filtered)} 个发现 (原始 {len(all_findings)}, 去重后 {len(unique_findings)})")
        return filtered

    def _extract_type_names(self, signature: str, function_code: str) -> List[str]:
        """
        🔥 从函数签名和代码中动态提取类型名称

        提取规则:
        1. 大写字母开头的标识符 (如 Pool, Position, Coin)
        2. 排除 Move 内置类型 (u8, u64, bool, vector, address 等)
        3. 排除模块前缀 (如 coin::Coin 中的 coin)
        4. 排除全大写常量 (如 PERMISSION_PAIR_MANAGER_KEY)
        5. 排除注释中的词
        6. 按出现频率排序

        Args:
            signature: 函数签名
            function_code: 函数实现代码

        Returns:
            提取的类型名称列表 (按频率降序)
        """
        import re
        from collections import Counter

        # 合并签名和代码
        combined = f"{signature}\n{function_code}"

        # 🔥 移除注释 (避免提取注释中的词)
        # 移除单行注释 // ...
        combined = re.sub(r'//[^\n]*', '', combined)
        # 移除多行注释 /* ... */
        combined = re.sub(r'/\*[\s\S]*?\*/', '', combined)

        # 提取大写开头的标识符 (支持泛型如 Coin<T>)
        # 匹配: Pool, Position, Coin, Balance, AdminCap 等
        pattern = r'\b([A-Z][a-zA-Z0-9_]*)\b'
        matches = re.findall(pattern, combined)

        # 排除 Move 内置类型和常见关键字
        builtin_types = {
            # 基本类型
            "Self", "T", "U", "V", "W", "X", "Y", "Z",
            # 泛型占位符
            "CoinType", "CoinTypeA", "CoinTypeB", "Type", "Key", "Store",
            # Move 内置
            "ID", "UID", "TxContext", "Option", "String", "ASCII",
            # 太通用的名称
            "E", "R", "S", "A", "B", "C", "N", "M",
            # 🔥 常见注释词 (防止漏掉的注释)
            "TODO", "FIXME", "NOTE", "HACK", "XXX", "BUG",
            "Check", "If", "The", "This", "We", "It", "Is", "Not", "For",
            "Args", "Returns", "Return", "Param", "See", "Example",
        }

        def is_valid_type(name: str) -> bool:
            """检查是否为有效的类型名称"""
            if name in builtin_types:
                return False
            if len(name) <= 1:
                return False
            # 🔥 排除全大写标识符 (常量，如 PERMISSION_PAIR_MANAGER_KEY)
            if name.isupper():
                return False
            # 🔥 排除下划线开头或结尾的标识符 (通常是常量或特殊标识)
            if name.startswith('_') or name.endswith('_'):
                return False
            # 🔥 排除过短的全大写开头词 (如 OK, NO 等)
            if len(name) <= 2 and name[0].isupper():
                return False
            # 🔥 排除泛型类型参数模式 (CoinTypeA, CoinTypeB, CoinTypeC, TypeA, TypeB 等)
            if re.match(r'^(Coin)?Type[A-Z]$', name):
                return False
            # 🔥 排除常见泛型参数命名模式 (如 AssetT, TokenT, CoinT)
            if re.match(r'^[A-Z][a-z]+[A-Z]$', name) and name.endswith(('T', 'K', 'V')):
                return False
            return True

        # 过滤并计数
        filtered = [m for m in matches if is_valid_type(m)]
        type_counts = Counter(filtered)

        # 按频率降序返回
        return [t for t, _ in type_counts.most_common()]

    def _build_function_context(self, module_name: str, func_node: Dict) -> Dict[str, Any]:
        """
        为函数构建精准的分析上下文

        Args:
            module_name: 模块名
            func_node: 调用图中的函数节点

        Returns:
            函数上下文字典
        """
        func_name = func_node.get("name", "unknown")
        func_id = func_node.get("id", f"{module_name}::{func_name}")
        caller_tag = "Engine"

        # 1. 获取函数实现代码
        function_code = ""
        if self.toolkit:
            func_result = self.toolkit.call_tool("get_function_code", {
                "module": module_name,
                "function": func_name
            }, caller=caller_tag)
            if func_result.success:
                function_code = func_result.data.get("body", "")

        if not function_code:
            # 尝试从调用图节点获取
            span = func_node.get("span", {})
            module_path = func_node.get("module_path", "")
            if span and module_path:
                try:
                    with open(module_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    start = span.get("start", 1) - 1
                    end = span.get("end", len(lines))
                    function_code = "".join(lines[start:end])
                except:
                    function_code = ""

        # 2. 获取调用者和被调用者
        callers = func_node.get("called_by", [])
        callees = func_node.get("calls", [])

        # 2.5 🔥 获取调用者的签名 (用于判断分层设计权限控制)
        caller_signatures = []
        if self.toolkit and callers:
            for caller in callers[:5]:  # 最多 5 个调用者
                parts = caller.split("::")
                if len(parts) >= 2:
                    caller_module = parts[-2] if len(parts) > 2 else parts[0]
                    caller_func = parts[-1]
                    caller_result = self.toolkit.call_tool("get_function_code", {
                        "module": caller_module,
                        "function": caller_func
                    }, caller=caller_tag)
                    if caller_result.success:
                        # 只保留签名部分 (第一行)
                        body = caller_result.data.get("body", "")
                        if body:
                            first_line = body.split('\n')[0].strip()
                            if first_line:
                                caller_signatures.append(f"{caller}: {first_line}")

        # 3. 获取被调用函数的实现 (用于理解数据流)
        callee_implementations = []
        if self.toolkit:
            for callee in callees[:5]:  # 最多 5 个
                # 解析 callee 格式: module::function 或 address::module::function
                parts = callee.split("::")
                if len(parts) >= 2:
                    callee_module = parts[-2] if len(parts) > 2 else parts[0]
                    callee_func = parts[-1]
                    callee_result = self.toolkit.call_tool("get_function_code", {
                        "module": callee_module,
                        "function": callee_func
                    }, caller=caller_tag)
                    if callee_result.success:
                        impl = callee_result.data.get("body", "")
                        callee_implementations.append(f"// {callee}\n{impl}")

        # 4. 获取相关类型定义
        type_definitions = []
        signature = func_node.get("signature", "")
        if self.toolkit:
            # 🔥 动态提取类型名称，而不是使用固定列表
            # 从签名和函数代码中提取所有大写开头的类型名
            extracted_types = self._extract_type_names(signature, function_code or "")

            # 去重并限制数量（避免过多工具调用）
            seen_types = set()
            for type_name in extracted_types[:10]:  # 最多10个类型
                if type_name in seen_types:
                    continue
                seen_types.add(type_name)

                type_result = self.toolkit.call_tool("get_type_definition", {
                    "type_name": type_name
                }, caller=caller_tag)
                if type_result.success:
                    type_def = type_result.data.get("body", "")
                    if type_def:  # 只添加非空的类型定义
                        type_definitions.append(f"// {type_name}\n{type_def}")

        return {
            "module_name": module_name,
            "function_name": func_name,
            "function_code": function_code or "// 无法获取函数代码",
            "signature": signature,
            "visibility": func_node.get("visibility", "private"),
            "risk_score": func_node.get("risk_score", 0),
            "risk_indicators": func_node.get("risk_indicators", {}),
            "callers": callers,
            "callees": callees,
            "caller_signatures": caller_signatures,  # 🔥 调用者签名 (用于判断分层设计)
            "callee_implementations": "\n\n".join(callee_implementations) if callee_implementations else "",
            "type_definitions": "\n\n".join(type_definitions) if type_definitions else "",
        }

    def _serialize_func_context(self, ctx: Dict[str, Any]) -> str:
        """
        🔥 将 Phase 2 构建的 func_context 序列化为字符串

        供 Phase 3 的 Agent 直接使用，避免重新提取

        Args:
            ctx: _build_function_context 返回的字典

        Returns:
            格式化的上下文字符串
        """
        parts = []

        module_name = ctx.get("module_name", "unknown")
        func_name = ctx.get("function_name", "unknown")
        signature = ctx.get("signature", "")
        visibility = ctx.get("visibility", "private")
        risk_score = ctx.get("risk_score", 0)

        parts.append(f"## 🎯 目标函数: {module_name}::{func_name}")
        parts.append(f"- 签名: `{signature}`")
        parts.append(f"- 可见性: {visibility}")
        parts.append(f"- 风险评分: {risk_score}")

        # 风险指标
        risk_indicators = ctx.get("risk_indicators", {})
        if risk_indicators:
            risk_hints = []
            if risk_indicators.get("overflow", 0) > 0:
                risk_hints.append(f"溢出风险: {risk_indicators['overflow']} 处")
            if risk_indicators.get("access_control", 0) > 0:
                risk_hints.append("访问控制检查")
            if risk_indicators.get("state_modification", 0) > 0:
                risk_hints.append(f"状态修改: {risk_indicators['state_modification']} 处")
            if risk_indicators.get("division", 0) > 0:
                risk_hints.append(f"除法运算: {risk_indicators['division']} 处")
            if risk_hints:
                parts.append(f"- 风险指标: {', '.join(risk_hints)}")

        # 调用关系
        callers = ctx.get("callers", [])
        callees = ctx.get("callees", [])
        if callers:
            parts.append(f"\n### 调用者 (可能的攻击入口)")
            parts.append(f"- {', '.join(callers[:8])}")
        if callees:
            parts.append(f"\n### 被调用函数")
            parts.append(f"- {', '.join(callees[:8])}")

        # 函数实现
        function_code = ctx.get("function_code", "")
        if function_code and function_code != "// 无法获取函数代码":
            parts.append(f"\n### 函数实现")
            parts.append(f"```move\n{function_code}\n```")

        # 被调用函数实现
        callee_implementations = ctx.get("callee_implementations", "")
        if callee_implementations:
            parts.append(f"\n### 被调用函数实现 (数据流分析)")
            parts.append(callee_implementations)

        # 类型定义
        type_definitions = ctx.get("type_definitions", "")
        if type_definitions:
            parts.append(f"\n### 相关类型定义")
            parts.append(type_definitions)

        return "\n".join(parts)

    def _extract_exploit_context(self, finding: VerifiedFinding) -> Optional[Dict[str, Any]]:
        """
        🔥 为 Phase 4 WhiteHat 验证提取精准的漏洞上下文

        从 finding 中提取函数名和模块名，然后使用 toolkit 获取：
        1. 目标函数实现
        2. 调用者函数 (用于构造攻击入口)
        3. 被调用函数 (用于理解数据流)
        4. 相关类型定义

        Args:
            finding: Phase 3 验证后的漏洞发现

        Returns:
            包含 code, function, module, callers, callees 的字典，失败时返回 None
        """
        if not self.toolkit:
            return None

        orig = finding.original_finding
        location = orig.get("location", {})

        # 提取函数名和模块名
        func_name = location.get("function", "") if isinstance(location, dict) else ""
        module_name = location.get("module", "") if isinstance(location, dict) else ""

        # 如果 location 中没有，尝试从 title 提取
        if not func_name:
            title = orig.get("title", "")
            import re
            match = re.search(r'`(\w+)`|(\w+)\s*\(|(\w+)\s+函数', title)
            if match:
                func_name = match.group(1) or match.group(2) or match.group(3)

        if not func_name:
            return None

        try:
            context_parts = []
            caller_tag = "WhiteHat"
            func_impl = None
            callers = []
            callees = []

            # 1. 获取目标函数实现
            func_result = self.toolkit.call_tool("get_function_code", {
                "module": module_name,
                "function": func_name
            }, caller=caller_tag)
            if func_result.success:
                func_impl = func_result.data.get("body", "")
                context_parts.append(f"// 🎯 漏洞函数: {module_name}::{func_name}")
                context_parts.append(f"```move\n{func_impl}\n```")

            # 2. 获取调用者 (攻击入口)
            callers_result = self.toolkit.call_tool("get_callers", {
                "module": module_name,
                "function": func_name,
                "depth": 2
            }, caller=caller_tag)
            if callers_result.success:
                callers_data = callers_result.data.get("callers", [])
                callers = [c.get("id", c) if isinstance(c, dict) else c for c in callers_data]
                caller_code = []
                for caller_id in callers[:5]:  # 最多 5 个
                    parts = caller_id.split('::')
                    if len(parts) >= 2:
                        c_module = parts[-2] if len(parts) > 2 else parts[0]
                        c_func = parts[-1]
                        c_result = self.toolkit.call_tool("get_function_code", {
                            "module": c_module,
                            "function": c_func
                        }, caller=caller_tag)
                        if c_result.success:
                            c_impl = c_result.data.get("body", "")
                            caller_code.append(f"// Caller: {caller_id}\n{c_impl}")
                if caller_code:
                    context_parts.append("\n// 📥 调用者 (可作为攻击入口):")
                    context_parts.extend(caller_code)

            # 3. 获取被调用函数 (数据流)
            callees_result = self.toolkit.call_tool("get_callees", {
                "module": module_name,
                "function": func_name,
                "depth": 2
            }, caller=caller_tag)
            if callees_result.success:
                callees_data = callees_result.data.get("callees", [])
                callees = [c.get("id", c) if isinstance(c, dict) else c for c in callees_data]
                callee_code = []
                for callee_id in callees[:5]:  # 最多 5 个
                    parts = callee_id.split('::')
                    if len(parts) >= 2:
                        c_module = parts[-2] if len(parts) > 2 else parts[0]
                        c_func = parts[-1]
                        c_result = self.toolkit.call_tool("get_function_code", {
                            "module": c_module,
                            "function": c_func
                        }, caller=caller_tag)
                        if c_result.success:
                            c_impl = c_result.data.get("body", "")
                            callee_code.append(f"// Callee: {callee_id}\n{c_impl}")
                if callee_code:
                    context_parts.append("\n// 📤 被调用函数 (数据流分析):")
                    context_parts.extend(callee_code)

            # 4. 获取相关类型定义
            type_defs = []
            for type_name in ["Pool", "Position", "Coin", "Balance", "Vault", "Config", "AdminCap", "OwnerCap", "Receipt"]:
                if type_name in (func_impl or ""):
                    type_result = self.toolkit.call_tool("get_type_definition", {
                        "type_name": type_name
                    }, caller=caller_tag)
                    if type_result.success:
                        type_def = type_result.data.get("body", "")
                        type_defs.append(f"// Type: {type_name}\n{type_def}")
            if type_defs:
                context_parts.append("\n// 📦 相关类型定义:")
                context_parts.extend(type_defs)

            if context_parts:
                return {
                    "code": "\n\n".join(context_parts),
                    "function": func_name,
                    "module": module_name,
                    "callers": callers,
                    "callees": callees,
                }

        except Exception as e:
            logger.warning(f"[Phase 4] 上下文提取失败: {e}")

        return None

    async def _scan_legacy(
        self,
        code: str,
        contract_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        传统扫描模式 (BA + TA 分批并行执行)

        结合BA模式和TA模式进行全面扫描。
        使用分批 + Semaphore 控制，避免 API 限流。
        """
        all_findings = []
        scan_items = []  # (label, coroutine_func, args)

        # 准备BA任务
        if self.config.enable_broad_analysis:
            ba_context = {
                "module_name": contract_analysis.get("modules", [{}])[0].get("name", "Unknown"),
                "callgraph": contract_analysis.get("callgraph", {}),
                "dependencies": contract_analysis.get("external_dependencies", []),
                # 🔥 传递预分析提示
                "analysis_hints": contract_analysis.get("analysis_hints")
            }
            scan_items.append(("BA", self.auditor.broad_analysis, (code, ba_context)))

        # 准备TA任务
        if self.config.enable_targeted_analysis:
            for vuln_type in self.config.targeted_vuln_types:
                scan_items.append((f"TA:{vuln_type}", self.auditor.targeted_analysis, (code, vuln_type)))

        if not scan_items:
            return []

        # 🔥 分批处理配置 (使用 AuditConfig 配置)
        max_concurrent = self.config.max_concurrent_scan
        batch_size = self.config.batch_size
        batch_cooldown = self.config.batch_cooldown
        total = len(scan_items)
        num_batches = (total + batch_size - 1) // batch_size

        logger.info(f"扫描 {total} 项检查 (分 {num_batches} 批, 每批 {batch_size} 个, 并发={max_concurrent})")

        # 🔥 分批执行
        for batch_idx in range(num_batches):
            start_idx = batch_idx * batch_size
            end_idx = min(start_idx + batch_size, total)
            batch_items = scan_items[start_idx:end_idx]

            print(f"\n  ━━━ 批次 {batch_idx + 1}/{num_batches} [{start_idx + 1}-{end_idx}/{total}] ━━━")

            # 当前批次使用 Semaphore 控制并发
            semaphore = asyncio.Semaphore(max_concurrent)

            async def run_with_semaphore(idx: int, label: str, func, args):
                async with semaphore:
                    print(f"  🔄 [{idx}/{total}] {label}...")
                    try:
                        result = await func(*args)
                        # 🔥 实时显示完成状态
                        if isinstance(result, dict) and result.get("findings"):
                            count = len(result["findings"])
                            print(f"  ✓ [{idx}/{total}] {label}: {count} 个发现")
                        else:
                            print(f"  ○ [{idx}/{total}] {label}: 0 个发现")
                        return label, result
                    except Exception as e:
                        print(f"  ⚠️ [{idx}/{total}] {label}: 失败 - {e}")
                        return label, e

            # 并行执行当前批次
            tasks = [
                run_with_semaphore(start_idx + i + 1, label, func, args)
                for i, (label, func, args) in enumerate(batch_items)
            ]
            completed = await asyncio.gather(*tasks, return_exceptions=True)

            # 收集当前批次结果
            for item in completed:
                if isinstance(item, Exception):
                    continue
                label, result = item
                if isinstance(result, dict) and result.get("findings"):
                    all_findings.extend(result["findings"])

            # 🔥 批次间冷却 (最后一批不需要)
            if batch_idx < num_batches - 1:
                logger.info(f"冷却 {batch_cooldown}s...")
                await asyncio.sleep(batch_cooldown)

        # 去重 (基于位置和类型)
        unique_findings = self._deduplicate_findings(all_findings)

        # 过滤低置信度
        filtered = [
            f for f in unique_findings
            if f.get("confidence", 0) >= self.config.min_confidence_threshold
        ]

        return filtered

    def _filter_obvious_false_positives(
        self,
        findings: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        早期过滤明显的 Sui Move 误报，减少 Phase 3 LLM 调用

        🔥 v2.5.0: 规则已提取到 src/security/exclusion_rules.py 独立管理

        Returns:
            (需要验证的发现, 已过滤的误报)
        """
        return apply_exclusion_rules(findings, enabled_rules=None, verbose=True)

    async def _quick_verify(
        self,
        findings: List[Dict[str, Any]],
        code: str
    ) -> List[VerifiedFinding]:
        """
        快速验证模式 (并行验证，不使用完整的角色交换)
        """
        if not findings:
            return []

        print(f"    并行验证 {len(findings)} 个发现...")

        # 并行执行所有验证
        verify_tasks = [
            self.expert.verify_vulnerability(finding, {"code_snippet": code})
            for finding in findings
        ]
        expert_results = await asyncio.gather(*verify_tasks, return_exceptions=True)

        # 收集结果
        verified = []
        for finding, expert_result in zip(findings, expert_results):
            if isinstance(expert_result, Exception):
                print(f"    ⚠️ 验证失败: {finding.get('title', 'Unknown')}")
                status = VerificationStatus.NEEDS_REVIEW
                expert_result = {}
            else:
                # 简单判定
                status = VerificationStatus.CONFIRMED
                if expert_result.get("verification", {}).get("status") == "false_positive":
                    status = VerificationStatus.FALSE_POSITIVE
                elif expert_result.get("verification", {}).get("status") == "needs_context":
                    status = VerificationStatus.NEEDS_REVIEW

            verified.append(VerifiedFinding(
                original_finding=finding,
                verification_status=status,
                swap_rounds=[],
                final_severity=finding.get("severity", "medium"),
                final_confidence=expert_result.get("verification", {}).get("confidence", 50) if expert_result else 50,
                verifier_result=expert_result if expert_result else {},
                manager_verdict={},
                recommendations=[finding.get("recommendation", "")]
            ))

        return verified

    async def _check_caller_affected(
        self,
        vuln_function: str,
        vuln_description: str,
        caller_id: str,
        caller_code: str
    ) -> Optional[Dict[str, Any]]:
        """
        分析调用方是否受漏洞函数影响

        Args:
            vuln_function: 漏洞函数名
            vuln_description: 漏洞描述
            caller_id: 调用方函数 ID
            caller_code: 调用方代码

        Returns:
            {"affected": bool, "impact": str, "severity": str, "recommendation": str}
        """
        prompt = f"""## 漏洞影响传播分析

### 已知漏洞
函数 `{vuln_function}` 存在以下问题：
{vuln_description}

### 调用方代码
函数 `{caller_id}` 调用了上述漏洞函数：
```move
{caller_code}
```

### 分析任务
1. 分析 `{caller_id}` 如何使用 `{vuln_function}` 的返回值
2. 判断漏洞是否会传播到 `{caller_id}`，导致安全问题
3. 如果受影响，描述具体的安全影响

### 输出格式 (JSON)
```json
{{
  "affected": true/false,
  "impact": "具体的安全影响描述",
  "severity": "critical/high/medium/low",
  "recommendation": "修复建议"
}}
```

只输出 JSON，不要其他内容。
"""

        try:
            # 🔥 v2.5.11: 使用 auditor 的 call_llm 方法 (异步)
            content = await self.auditor.call_llm(
                prompt=prompt,
                json_mode=True,
                stateless=True  # 并行友好
            )

            # 解析 JSON
            import json
            import re
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())

        except Exception as e:
            logger.warning(f"漏洞传播分析失败: {e}")

        return None

    async def _verify_exploits(
        self,
        verified_findings: List[VerifiedFinding],
        code: str,
        contract_analysis: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        WhiteHat 利用链验证 (两阶段)

        Phase 1: 并行验证单个漏洞
        Phase 2: 漏洞传播链分析 (A 有漏洞 → B 调用 A → B 也有漏洞)

        🔥 v2.5.11: Phase 2 从"组合利用链"改为"传播链分析"
        - 传播链: 确定性因果关系，A 的漏洞通过调用传播到 B
        - 组合链: 推测性，多个独立漏洞组合攻击 (已移除)

        Args:
            verified_findings: 已验证的漏洞列表
            code: 源代码
            contract_analysis: Phase 1/1.5 的合约分析结果 (含 analysis_hints)
        """
        # 🔥 v2.4.11: 改进漏洞筛选逻辑
        # - CONFIRMED: 验证 critical/high 严重性
        # - NEEDS_REVIEW: 也验证 medium 严重性（因为这些是不确定的，需要 WhiteHat 帮助判断）
        high_risk = []
        for f in verified_findings:
            severity = f.final_severity.lower()
            status = f.verification_status

            if status == VerificationStatus.CONFIRMED:
                # CONFIRMED 只验证高危
                if severity in ["critical", "high"]:
                    high_risk.append(f)
            elif status == VerificationStatus.NEEDS_REVIEW:
                # NEEDS_REVIEW 降低门槛，包括 medium（让 WhiteHat 帮助判断）
                if severity in ["critical", "high", "medium"]:
                    high_risk.append(f)

        if not high_risk:
            print("  无需验证的漏洞")
            return []

        # 🔥 去重：使用精细 key 避免漏掉关键漏洞
        # Key: (模块名, 函数名, 行号区间, 漏洞类型) - 与 Phase 2 保持一致
        seen_keys = set()
        unique_findings = []
        for f in high_risk:
            location = f.original_finding.get("location", {})

            # 提取模块名
            module = ""
            if isinstance(location, dict):
                module = location.get("module", "") or location.get("file", "")

            # 提取函数名
            func_name = location.get("function", "") if isinstance(location, dict) else ""
            if not func_name:
                title = f.original_finding.get("title", "")
                import re
                match = re.search(r'`(\w+)`|(\w+)\s*\(', title)
                if match:
                    func_name = match.group(1) or match.group(2)

            # 提取行号区间 (用于区分同函数不同位置的漏洞)
            line_start = ""
            if isinstance(location, dict):
                line = location.get("line", location.get("start_line", ""))
                line_start = self._normalize_line_range(line)

            # 🔥 精细 key: (模块, 函数, 行号, 漏洞类型)
            vuln_type = self._normalize_vuln_type(f.original_finding)
            key = (module, func_name, line_start, vuln_type)

            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)
            else:
                print(f"    ⏭️ 跳过重复: {f.original_finding.get('title', '')[:40]}...")

        print(f"  去重后: {len(high_risk)} → {len(unique_findings)} 个唯一漏洞")

        # 所有漏洞都验证，用 semaphore 控制并发
        to_verify = unique_findings
        total = len(to_verify)

        # ========== Phase 1: 并行验证单个漏洞 ==========
        print(f"  [Phase 1] 分析 {total} 个高危漏洞的利用链 (并发={self.config.max_concurrent_exploit})...")

        # 🔥 如果有上下文系统，提示使用智能上下文
        use_context = self.toolkit is not None
        if use_context:
            print(f"  📌 使用统一工具箱提取精准漏洞上下文")

        # 用 Semaphore 控制并发数
        semaphore = asyncio.Semaphore(self.config.max_concurrent_exploit)

        async def verify_single(idx: int, finding: VerifiedFinding):
            async with semaphore:
                vuln_info = {
                    "id": finding.original_finding.get("id", "UNKNOWN"),
                    "pattern_id": finding.original_finding.get("pattern_id", ""),
                    "title": finding.original_finding.get("title", ""),
                    "category": finding.original_finding.get("category", ""),
                    "severity": finding.final_severity,
                    "description": finding.original_finding.get("description", ""),
                    "recommendation": finding.original_finding.get("recommendation", ""),
                    "location": finding.original_finding.get("location", {}),
                }
                title = vuln_info['title'][:40]
                print(f"    🔄 [{idx+1}/{total}] {title}...")

                # 🔥 优先使用 Phase 3 保存的代码上下文
                source_context = code  # 默认使用完整代码
                context_info = {"verified_by_agents": True}

                # 1. 优先使用 Phase 3 保存的 code_context
                if finding.code_context and len(finding.code_context) > 100:
                    source_context = finding.code_context
                    context_info["context_type"] = "phase3_inherited"
                    context_info["context_length"] = len(finding.code_context)
                elif use_context:
                    # 2. 回退: 重新提取 (仅当 Phase 3 没有保存时)
                    focused_context = self._extract_exploit_context(finding)
                    if focused_context:
                        source_context = focused_context["code"]
                        context_info.update({
                            "context_type": "focused",
                            "target_function": focused_context.get("function"),
                            "target_module": focused_context.get("module"),
                            "callers": focused_context.get("callers", []),
                            "callees": focused_context.get("callees", []),
                        })

                # 🔥 传递 Phase 3 的分析结果给 WhiteHat
                # 🔥 v2.5.3 兼容：role_swap_v2 的 agent_role 是 str，role_swap 是 enum
                def safe_value(x):
                    """安全获取 enum.value 或直接返回 str"""
                    return x.value if hasattr(x, 'value') else x

                context_info["phase3_analysis"] = {
                    "expert_review": finding.expert_review,
                    "analyst_assessment": finding.analyst_assessment,
                    "verification_status": safe_value(finding.verification_status),
                    "final_confidence": finding.final_confidence,
                    # 提取各轮次的关键推理
                    "verification_reasoning": [
                        {
                            "agent": safe_value(r.agent_role),
                            "verdict": r.verdict,
                            "confidence": r.confidence,
                            "notes": r.notes[:200] if r.notes else ""
                        }
                        for r in finding.swap_rounds
                    ] if finding.swap_rounds else []
                }

                try:
                    # verify_vulnerability 是同步方法，用 to_thread 包装
                    report = await asyncio.to_thread(
                        self.white_hat.verify_vulnerability,
                        vulnerability=vuln_info,
                        source_code=source_context,
                        context=context_info
                    )

                    result = {
                        "vulnerability_id": vuln_info.get("id") or vuln_info.get("pattern_id"),
                        "title": vuln_info.get("title"),
                        "severity": vuln_info.get("severity"),
                        "status": report.status.value,
                        "exploitability_score": report.exploitability_score,
                        "confidence_score": report.confidence_score,

                        # 漏洞验证核心字段
                        "advisory": report.advisory,
                        "vulnerability_summary": report.vulnerability_summary,
                        "technical_details": report.technical_details,
                        "attack_scenario": report.attack_scenario,
                        "poc_code": report.poc_code,
                        "impact_assessment": report.impact_assessment,
                        "recommended_mitigation": report.recommended_mitigation,
                        "blocking_factors": report.blocking_factors,

                        # 利用链分析
                        "entry_point": report.entry_point,
                        "attack_path": report.attack_path,
                        "preconditions": report.preconditions,
                        "impact": report.impact,

                        # 结论
                        "why_exploitable": report.why_exploitable,
                        "why_not_exploitable": report.why_not_exploitable,

                        # 🔥 完整的 exploit 代码和思路
                        "exploit_module_code": report.exploit_module_code,
                        "exploit_reasoning": report.exploit_reasoning,

                        # 原始分析
                        "analysis_reasoning": report.analysis_reasoning,
                    }

                    status_icon = "✓" if report.status.value in ["verified", "likely"] else "○"
                    print(f"    {status_icon} [{idx+1}/{total}] {title}... → {report.status.value}")
                    return idx, result

                except Exception as e:
                    print(f"    ⚠️ [{idx+1}/{total}] {title}... → 失败: {e}")
                    return idx, {
                        "vulnerability_id": vuln_info.get("id", "UNKNOWN"),
                        "title": vuln_info.get("title", ""),
                        "status": "error",
                        "error": str(e)
                    }

        # 并行执行所有验证任务 (semaphore 控制同时运行数量)
        tasks = [verify_single(i, f) for i, f in enumerate(to_verify)]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        # 收集结果 (保持顺序)
        all_results = [None] * total
        for item in completed:
            if isinstance(item, Exception):
                print(f"    ⚠️ 任务异常: {item}")
                continue
            idx, result = item
            all_results[idx] = result

        # 过滤掉 None
        individual_results = [r for r in all_results if r is not None]

        # ========== Phase 2: 漏洞传播链分析 (替代组合链分析) ==========
        # 🔥 v2.5.11: 用传播分析替代组合链分析
        # 传播分析：A 有漏洞 → B 调用 A → B 也有漏洞 (确定性因果关系)
        # 组合链分析：A+B 组合攻击 (推测性，已移除)
        if len(to_verify) >= 1:
            print(f"\n  [Phase 2] 漏洞传播链分析...")

            # 将 VerifiedFinding 转换为需要的格式
            confirmed_vulns = [f for f in to_verify
                              if f.verification_status == VerificationStatus.CONFIRMED]

            if confirmed_vulns:
                propagated = await self._analyze_vulnerability_propagation_in_phase4(
                    confirmed_vulns, code, individual_results
                )
                if propagated:
                    individual_results.extend(propagated)
                    print(f"    ✅ 传播分析发现 {len(propagated)} 个受影响函数")

        return individual_results

    async def _analyze_vulnerability_propagation_in_phase4(
        self,
        confirmed_vulns: List[VerifiedFinding],
        code: str,
        individual_results: List[Dict[str, Any]],
        max_depth: int = 3
    ) -> List[Dict[str, Any]]:
        """
        🔥 v2.5.11: Phase 4 内的漏洞传播链分析

        分析已确认漏洞的传播影响：
        - A 有漏洞 → B 调用 A → B 也有漏洞
        - 递归分析直到达到最大深度

        Args:
            confirmed_vulns: 已确认的漏洞列表 (VerifiedFinding)
            code: 源代码
            individual_results: Phase 1 的验证结果 (用于标记传播来源)
            max_depth: 最大递归深度

        Returns:
            传播链漏洞的验证结果列表 (与 Phase 1 结果格式一致)
        """
        if not self.toolkit:
            print("    ⚠️ 传播分析需要 toolkit 支持，跳过")
            return []

        propagation_results = []
        analyzed_callers = set()  # 全局避免重复分析

        # 当前层待分析的漏洞 (初始为 Phase 1 确认的漏洞)
        current_layer = list(confirmed_vulns)

        for depth in range(1, max_depth + 1):
            if not current_layer:
                break

            print(f"    📊 第 {depth} 层传播分析 ({len(current_layer)} 个漏洞)")

            next_layer = []  # 下一层新发现的漏洞

            for finding in current_layer:
                # 获取漏洞函数的位置
                location = finding.original_finding.get("location", {})
                vuln_module = location.get("module", "")
                vuln_function = location.get("function", "")

                if not vuln_function:
                    continue

                vuln_id = f"{vuln_module}::{vuln_function}"
                vuln_title = finding.original_finding.get("title", "")

                # 获取调用这个漏洞函数的所有 callers
                callers = []
                try:
                    result = self.toolkit.call_tool("get_callers", {
                        "module": vuln_module,
                        "function": vuln_function
                    }, caller="PropagationAnalysis")
                    if result.success:
                        callers = result.data.get("callers", [])
                except Exception as e:
                    logger.warning(f"获取 callers 失败: {e}")

                if not callers:
                    continue

                print(f"      🔗 {vuln_function} 被 {len(callers)} 个函数调用")

                # 分析每个 caller 是否受影响
                for caller_info in callers[:5]:  # 每层最多分析 5 个
                    caller_id = caller_info.get("id", caller_info) if isinstance(caller_info, dict) else str(caller_info)

                    if caller_id in analyzed_callers:
                        continue
                    analyzed_callers.add(caller_id)

                    # 获取 caller 的代码
                    caller_code = ""
                    caller_module = ""
                    caller_func = ""
                    if "::" in caller_id:
                        parts = caller_id.split("::")
                        caller_module = "::".join(parts[:-1])
                        caller_func = parts[-1]
                    else:
                        caller_func = caller_id

                    try:
                        result = self.toolkit.call_tool("get_function_code", {
                            "module": caller_module if caller_module else vuln_module,
                            "function": caller_func
                        }, caller="PropagationAnalysis")
                        if result.success:
                            caller_code = result.data.get("body", "") or result.data.get("code", "")
                    except:
                        pass

                    if not caller_code:
                        continue

                    # 让 LLM 分析 caller 是否受漏洞影响
                    propagation_result = await self._check_caller_affected(
                        vuln_function=vuln_function,
                        vuln_description=finding.original_finding.get("description", ""),
                        caller_id=caller_id,
                        caller_code=caller_code
                    )

                    if propagation_result and propagation_result.get("affected"):
                        impact = propagation_result.get('impact', '')
                        severity = propagation_result.get("severity", "high")
                        print(f"        ⚠️ [深度{depth}] {caller_func} 受影响: {impact[:50]}...")

                        # 创建与 Phase 1 一致的结果格式
                        prop_result = {
                            "vulnerability_id": f"PROPAGATION-{caller_id}",
                            "title": f"[传播链深度{depth}] {caller_func} ← {vuln_function}",
                            "severity": severity,
                            "status": "verified",
                            "exploitability_score": 7 - depth,  # 深度越深分数越低
                            "confidence_score": max(60, 85 - depth * 10),

                            # 传播链特有字段
                            "is_propagation": True,
                            "propagation_depth": depth,
                            "propagated_from": vuln_id,
                            "propagated_from_title": vuln_title,

                            # 漏洞分析字段
                            "vulnerability_summary": f"函数 {caller_func} 调用了有漏洞的 {vuln_function}，漏洞影响传播到调用方",
                            "technical_details": impact,
                            "attack_scenario": [
                                f"1. 攻击者利用 {vuln_function} 的漏洞",
                                f"2. 该漏洞通过调用链传播到 {caller_func}",
                                f"3. 攻击者可通过 {caller_func} 触发攻击"
                            ],
                            "impact_assessment": impact,
                            "recommended_mitigation": [propagation_result.get("recommendation", f"检查 {caller_func} 对 {vuln_function} 返回值的使用")],

                            # 入口点和路径
                            "entry_point": caller_func,
                            "attack_path": [vuln_function, caller_func],
                        }
                        propagation_results.append(prop_result)

                        # 创建 VerifiedFinding 用于下一层分析
                        new_finding = VerifiedFinding(
                            original_finding={
                                "title": prop_result["title"],
                                "description": impact,
                                "severity": severity,
                                "location": {
                                    "module": caller_module if caller_module else vuln_module,
                                    "function": caller_func,
                                }
                            },
                            verification_status=VerificationStatus.CONFIRMED,
                            swap_rounds=[],
                            final_severity=severity,
                            final_confidence=prop_result["confidence_score"],
                            verifier_result={},
                            manager_verdict={}
                        )
                        next_layer.append(new_finding)

            # 进入下一层
            current_layer = next_layer

            if next_layer:
                print(f"      → 第 {depth} 层发现 {len(next_layer)} 个新漏洞，继续分析...")

        return propagation_results

    # 漏洞类型关键词映射 (用于归一化去重)
    VULN_KEYWORDS = {
        "overflow": ["overflow", "溢出", "乘法", "加法", "arithmetic", "u64", "u128"],
        "access_control": ["access", "权限", "admin", "withdraw", "unauthorized", "permission", "控制"],
        "first_deposit": ["first", "首次", "首存", "depositor", "初始", "empty"],
        "slippage": ["slippage", "滑点", "front-run", "sandwich", "min_amount", "deadline"],
        "flash_loan": ["flash", "闪电贷", "receipt", "hot potato", "repay"],
        "oracle": ["oracle", "预言机", "price manipulation", "twap", "价格操纵"],
        "reentrancy": ["reentrancy", "重入", "callback"],
        "donation": ["donation", "捐赠", "inflate"],
        "rounding": ["rounding", "舍入", "precision", "精度"],
    }

    def _normalize_vuln_type(self, finding: Dict) -> str:
        """
        从 finding 中提取归一化的漏洞类型

        用于去重时统一不同来源 (BA/TA) 的漏洞分类。
        """
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        category = finding.get("category", "").lower()
        text = f"{title} {desc} {category}"

        for vuln_type, keywords in self.VULN_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                return vuln_type
        return category or "other"

    def _normalize_line_range(self, line) -> str:
        """
        归一化行号，防止 '10-15' 和 '10' 被当作不同

        - 整数 10 → "10"
        - 字符串 "10-15" → "10"
        - 空值 → ""
        """
        if isinstance(line, int):
            return str(line)
        if isinstance(line, str):
            if "-" in line:
                return line.split("-")[0].strip()
            return line.strip()
        return ""

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        智能去重: 合并重复发现，保留最详细的版本

        🔥 使用 (模块名, 函数名, 行号区间, 漏洞类型) 作为 key
        修复之前只用 (函数名, 漏洞类型) 导致的误合并问题：
        - 不同模块的同名函数 (amm::swap vs router::swap)
        - 同一函数不同位置的同类漏洞
        """
        grouped: Dict[tuple, List[Dict]] = {}
        for f in findings:
            location = f.get("location", {})
            if isinstance(location, dict):
                module = location.get("module", "")
                func_name = location.get("function", "")
                line = location.get("line", "")
            else:
                module = ""
                func_name = ""
                line = ""

            vuln_type = self._normalize_vuln_type(f)
            line_range = self._normalize_line_range(line)

            # 🔥 更精确的 key: (模块, 函数, 行号起始, 漏洞类型)
            key = (module, func_name, line_range, vuln_type)

            if key not in grouped:
                grouped[key] = []
            grouped[key].append(f)

        # 每组保留 confidence 最高的
        unique = []
        for key, group in grouped.items():
            best = max(group, key=lambda x: x.get("confidence", 0))
            unique.append(best)

        if len(findings) != len(unique):
            logger.info(f"智能去重: {len(findings)} → {len(unique)} 个发现")

        return unique

    def _calculate_statistics(
        self,
        verified_findings: List[VerifiedFinding],
        exploit_verifications: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """计算统计数据"""
        confirmed = [f for f in verified_findings if f.verification_status == VerificationStatus.CONFIRMED]
        false_positives = [f for f in verified_findings if f.verification_status == VerificationStatus.FALSE_POSITIVE]
        needs_review = [f for f in verified_findings if f.verification_status == VerificationStatus.NEEDS_REVIEW]

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in confirmed:
            sev = f.final_severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # WhiteHat 统计
        exploit_stats = {
            "verified": 0,
            "likely": 0,
            "theoretical": 0,
            "false_positive": 0,
            "combined_chains": 0  # 组合利用链
        }
        if exploit_verifications:
            for ev in exploit_verifications:
                # 统计组合利用链
                if ev.get("is_combined_exploit"):
                    exploit_stats["combined_chains"] += 1
                status = ev.get("status", "theoretical")
                if status in exploit_stats:
                    exploit_stats[status] += 1

        return {
            "total_raw_findings": len(verified_findings),
            "confirmed": len(confirmed),
            "false_positives": len(false_positives),
            "needs_review": len(needs_review),
            "false_positive_rate": len(false_positives) / len(verified_findings) if verified_findings else 0,
            "severity_distribution": severity_counts,
            "average_confidence": sum(f.final_confidence for f in verified_findings) / len(verified_findings) if verified_findings else 0,
            "exploit_verification": exploit_stats
        }

    def _generate_report(
        self,
        verified_findings: List[VerifiedFinding],
        contract_analysis: Dict[str, Any],
        exploit_verifications: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """生成最终报告 (纯本地，不调用 LLM)"""
        # 收集确认的发现
        confirmed = [
            {
                **f.original_finding,
                "verification_status": f.verification_status.value,
                "final_severity": f.final_severity,
                "final_confidence": f.final_confidence,
                "recommendations": f.recommendations
            }
            for f in verified_findings
            if f.verification_status == VerificationStatus.CONFIRMED
        ]

        # 🔥 直接构建报告，不调用 LLM
        report = {
            "summary": {
                "total_findings": len(confirmed),
                "recommendations": [f.get("recommendation", "") for f in confirmed if f.get("recommendation")]
            },
            "findings": confirmed,
            "contract_overview": {
                "modules": contract_analysis.get("modules", []),
                "key_functions": contract_analysis.get("key_functions", []),
                "risk_indicators": contract_analysis.get("risk_indicators", [])
            }
        }

        # 添加 WhiteHat 利用链验证结果
        if exploit_verifications:
            verified_exploits = [ev for ev in exploit_verifications if ev.get("status") in ["verified", "likely"]]
            report["exploit_analysis"] = {
                "total_verified": len(exploit_verifications),
                "exploitable": len(verified_exploits),
                "verified_exploits": verified_exploits
            }

        return report

    # ============================================================================
    # 🔥 v2.5.3: 日志捕获系统
    # ============================================================================

    def _start_log_capture(self):
        """启动日志捕获，同时输出到终端和缓冲区"""
        import builtins
        self._log_buffer = []
        self._original_print = builtins.print  # 保存原始 print

        original_print = self._original_print
        def tee_print(*args, **kwargs):
            # 写入缓冲区
            import io
            buffer = io.StringIO()
            kwargs_copy = kwargs.copy()
            kwargs_copy['file'] = buffer
            original_print(*args, **kwargs_copy)
            self._log_buffer.append(buffer.getvalue())
            # 写入终端
            original_print(*args, **kwargs)

        builtins.print = tee_print

    def _stop_log_capture(self):
        """停止日志捕获，恢复原始 print"""
        import builtins
        if hasattr(self, '_original_print') and self._original_print:
            builtins.print = self._original_print
            self._original_print = None

    def _get_captured_log(self) -> str:
        """获取捕获的日志内容"""
        if hasattr(self, '_log_buffer'):
            return ''.join(self._log_buffer)
        return ""

    async def _save_reports(self, result: AuditResult):
        """保存报告到文件"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = result.project_name.replace("/", "_").replace(" ", "_")
        output_dir = Path(self.config.output_dir) / f"{safe_name}_{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)

        # 保存报告目录路径到结果中
        result.report_dir = str(output_dir)

        # 🔥 v2.5.3: 保存终端日志
        self._stop_log_capture()  # 先停止捕获
        log_content = self._get_captured_log()
        if log_content:
            log_path = output_dir / "audit_log.txt"
            log_path.write_text(log_content, encoding="utf-8")
            print(f"  日志已保存: {log_path}")

        if self.config.generate_markdown:
            md_path = output_dir / "security_report.md"
            md_content = self._generate_markdown_report(result)
            md_path.write_text(md_content, encoding="utf-8")
            print(f"  报告已保存: {md_path}")

        if self.config.generate_json:
            import json
            json_path = output_dir / "audit_result.json"

            # 序列化VerifiedFinding
            serializable_findings = []
            for f in result.verified_findings:
                serializable_findings.append({
                    "original_finding": f.original_finding,
                    "verification_status": f.verification_status.value,
                    "final_severity": f.final_severity,
                    "final_confidence": f.final_confidence,
                    "recommendations": f.recommendations
                })

            json_data = {
                "project_name": result.project_name,
                "audit_timestamp": result.audit_timestamp,
                "duration_seconds": result.duration_seconds,
                "statistics": result.statistics,
                "verified_findings": serializable_findings,
                "final_report": result.final_report
            }
            json_path.write_text(json.dumps(json_data, indent=2, ensure_ascii=False), encoding="utf-8")

    # ============================================================================
    # 🔥 报告生成辅助方法
    # ============================================================================

    def _calculate_risk_score(self, stats: Dict[str, Any]) -> float:
        """
        计算总体风险评分 (0-10)

        评分公式:
        - Critical: 4 分/个 (最高 10 分)
        - High: 2 分/个 (最高 6 分)
        - Medium: 1 分/个 (最高 3 分)
        - Low: 0.5 分/个 (最高 1 分)
        """
        severity_dist = stats.get('severity_distribution', {})
        score = 0.0

        # 每种严重性的权重和上限
        score += min(severity_dist.get('critical', 0) * 4.0, 10.0)
        score += min(severity_dist.get('high', 0) * 2.0, 6.0)
        score += min(severity_dist.get('medium', 0) * 1.0, 3.0)
        score += min(severity_dist.get('low', 0) * 0.5, 1.0)

        # 限制在 0-10 范围
        return min(round(score, 1), 10.0)

    def _get_risk_level(self, risk_score: float) -> str:
        """根据风险评分获取风险级别"""
        if risk_score >= 8.0:
            return "🔴 严重"
        elif risk_score >= 6.0:
            return "🟠 高危"
        elif risk_score >= 4.0:
            return "🟡 中危"
        elif risk_score >= 2.0:
            return "🟢 低危"
        else:
            return "⚪ 极低"

    def _generate_executive_summary(self, result: AuditResult, risk_score: float, risk_level: str) -> str:
        """生成执行摘要 (给管理层的高层总结)"""
        stats = result.statistics
        severity_dist = stats.get('severity_distribution', {})

        # 统计关键信息
        critical_count = severity_dist.get('critical', 0)
        high_count = severity_dist.get('high', 0)
        confirmed = stats.get('confirmed', 0)
        exploitable = stats.get('exploit_verification', {}).get('verified', 0)

        # 生成简洁的执行摘要
        summary_parts = []

        # 第一段：总体风险评估
        if risk_score >= 8.0:
            summary_parts.append(
                f"**该合约存在严重安全风险。** "
                f"部署前需要立即修复。"
            )
        elif risk_score >= 6.0:
            summary_parts.append(
                f"**该合约存在高危安全风险。** "
                f"发现了需要关注的重大漏洞。"
            )
        elif risk_score >= 4.0:
            summary_parts.append(
                f"**该合约存在中等安全风险。** "
                f"发现了若干需要处理的问题。"
            )
        else:
            summary_parts.append(
                f"**该合约安全风险较低。** "
                f"仅发现少量小问题，整体安全状况良好。"
            )

        # 第二段：关键发现
        if critical_count > 0 or high_count > 0:
            findings_text = []
            if critical_count > 0:
                findings_text.append(f"{critical_count} 个严重")
            if high_count > 0:
                findings_text.append(f"{high_count} 个高危")
            summary_parts.append(
                f"审计发现 **{' 和 '.join(findings_text)}漏洞**，"
                f"共 {confirmed} 个确认问题。"
            )

        # 第三段：可利用性
        if exploitable > 0:
            summary_parts.append(
                f"**{exploitable} 个漏洞已验证可利用**，"
                f"并提供了概念验证代码 (PoC)。"
            )

        return " ".join(summary_parts)

    def _generate_vulnerability_summary_table(self, confirmed_findings: List) -> str:
        """
        🔥 v2.4.11: 生成漏洞摘要表 (快速索引)

        每个漏洞一行，包含：ID、严重性、类型、位置、简短描述
        """
        if not confirmed_findings:
            return "未发现确认的漏洞。"

        # 按严重性排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            confirmed_findings,
            key=lambda f: severity_order.get(f.final_severity.lower(), 4)
        )

        # 生成表格
        rows = ["| # | 严重性 | 类别 | 位置 | 标题 |",
                "|:-:|:------:|:----:|:-----|:-----|"]

        for i, finding in enumerate(sorted_findings, 1):
            orig = finding.original_finding
            severity = finding.final_severity.upper()

            # 严重性图标
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

            category = orig.get("category", "N/A")[:15]
            title = orig.get("title", "Unknown")[:50]
            if len(orig.get("title", "")) > 50:
                title += "..."

            # 提取简短位置
            location = orig.get("location", {})
            if isinstance(location, dict):
                func = location.get("function", "")
                module = location.get("module", "")
                if module and func:
                    loc_short = f"`{module.split('::')[-1]}::{func}`"
                elif func:
                    loc_short = f"`{func}`"
                else:
                    loc_short = "—"
            else:
                loc_short = "—"

            rows.append(f"| {i} | {sev_icon} {severity} | {category} | {loc_short} | {title} |")

        return "\n".join(rows)

    def _generate_propagation_summary_rows(self, propagation_vulns: List[Dict], start_index: int) -> str:
        """
        🔥 v2.5.12: 生成传播链漏洞的摘要表

        Args:
            propagation_vulns: 传播链漏洞列表
            start_index: 起始编号

        Returns:
            Markdown 表格（含表头和子标题）
        """
        if not propagation_vulns:
            return ""

        rows = [
            "\n\n### 🔗 传播链漏洞\n",
            "> 以下漏洞通过函数调用链从上游漏洞传播而来\n",
            "| # | 严重性 | 类别 | 入口点 | 传播来源 |",
            "|:-:|:------:|:----:|:-------|:---------|"
        ]

        for i, vuln in enumerate(propagation_vulns, start_index):
            severity = vuln.get("severity", "medium").upper()
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

            category = vuln.get("category", "propagation")[:15]
            entry_point = vuln.get("entry_point", "—")
            loc_short = f"`{entry_point}`" if entry_point and entry_point != "—" else "—"

            # 显示传播来源
            propagated_from = vuln.get("propagated_from_title", "Unknown")
            if len(propagated_from) > 35:
                propagated_from = propagated_from[:35] + "..."

            rows.append(f"| {i} | {sev_icon} {severity} | {category} | {loc_short} | {propagated_from} |")

        return "\n".join(rows)

    def _format_location(self, location: Any, orig: Dict[str, Any]) -> str:
        """
        格式化位置信息为 module::function:line 格式

        Args:
            location: 位置信息 (可能是 dict 或 str)
            orig: 原始 finding 数据

        Returns:
            格式化后的位置字符串
        """
        if isinstance(location, dict):
            module = location.get('module', '')
            func = location.get('function', '')
            line = location.get('line', '')
            file = location.get('file', '')

            # 尝试从 path 提取模块名
            if not module and location.get('path'):
                path = location.get('path', '')
                if '::' in path:
                    parts = path.split('::')
                    module = parts[0] if len(parts) > 0 else ''
                    if not func and len(parts) > 1:
                        func = parts[-1]

            # 构建位置字符串
            parts = []
            if module:
                parts.append(module)
            if func:
                parts.append(func)

            if parts:
                loc_str = '::'.join(parts)
                if line:
                    loc_str += f":{line}"
                return f"`{loc_str}`"
            elif file:
                return f"{file}:{line}" if line else file
            else:
                return str(location)
        elif isinstance(location, str):
            return f"`{location}`" if location else "unknown"
        else:
            return "unknown"

    def _format_exploitation_analysis(self, ea: Dict[str, Any]) -> str:
        """
        🔥 v2.5.0: 格式化利用性分析结果

        Args:
            ea: exploitation_analysis 字典

        Returns:
            格式化后的 Markdown 字符串
        """
        if not ea:
            return ""

        lines = ["\n**Exploitation Analysis**:\n"]

        # 攻击路径
        entry_point = ea.get('entry_point')
        attack_path = ea.get('attack_path')
        if entry_point or attack_path:
            lines.append(f"- **Attack Path**: {attack_path or 'N/A'}")
            if entry_point and entry_point != 'null':
                lines.append(f"- **Entry Point**: `{entry_point}`")

        # 可控输入
        controllable = ea.get('controllable_inputs', [])
        if controllable:
            inputs_str = ', '.join(f"`{i}`" for i in controllable if i)
            lines.append(f"- **Controllable Inputs**: {inputs_str}")

        # 前置条件
        preconditions = ea.get('preconditions', [])
        if preconditions:
            cond_str = ', '.join(preconditions)
            lines.append(f"- **Preconditions**: {cond_str}")

        # 实际影响
        impact = ea.get('concrete_impact')
        if impact:
            lines.append(f"- **Concrete Impact**: {impact}")

        # 是否仅为理论性风险
        is_theoretical = ea.get('is_theoretical_only')
        if is_theoretical is True:
            lines.append(f"- ⚠️ **Note**: This is a theoretical risk only")

        if len(lines) > 1:
            return '\n'.join(lines) + '\n\n'
        return ""

    def _get_false_positive_reason(self, finding) -> str:
        """提取误报原因"""
        # 🔥 v2.5.7: 优先从 early_filter 获取 (规则过滤)
        if hasattr(finding, 'early_filter') and finding.early_filter:
            ef = finding.early_filter
            if isinstance(ef, dict) and ef.get('reason'):
                return ef.get('reason')

        # 尝试从 manager_verdict 获取原因
        verdict = getattr(finding, 'manager_verdict', None)
        if isinstance(verdict, dict):
            reason = verdict.get('reasoning') or verdict.get('reason', '')
            if reason:
                # 截断过长的原因
                return reason[:100] + "..." if len(reason) > 100 else reason

        # 尝试从 expert_review 获取
        expert = getattr(finding, 'expert_review', None)
        if isinstance(expert, dict):
            verification = expert.get('verification', {})
            if isinstance(verification, dict):
                reason = verification.get('reasoning', '')
                if reason:
                    return reason[:100] + "..." if len(reason) > 100 else reason

        # 🔥 v2.5.7: 从 recommendations 提取原因
        recs = getattr(finding, 'recommendations', None)
        if recs and isinstance(recs, list) and len(recs) > 0:
            rec = recs[0]
            # 提取 "无需修复。" 之后的原因，或直接使用第一个建议
            if isinstance(rec, str):
                # 移除 "无需修复。" 前缀
                if rec.startswith('无需修复。'):
                    rec = rec[5:]
                return rec[:100] + "..." if len(rec) > 100 else rec

        return "经多智能体验证判定为不可利用"

    def _get_needs_review_reason(self, finding) -> str:
        """解释为什么需要人工审查"""
        reasons = []

        # 检查是否有 JSON 解析错误
        if finding.expert_review.get('error'):
            reasons.append("专家审查时 LLM 响应解析失败")
        if finding.analyst_assessment.get('error'):
            reasons.append("影响评估时 LLM 响应解析失败")
        if finding.manager_verdict.get('error'):
            reasons.append("最终判定时 LLM 响应解析失败")

        # 检查置信度
        if finding.final_confidence < 50:
            reasons.append(f"置信度过低 ({finding.final_confidence}%)")

        # 检查是否有冲突的意见
        swap_rounds = finding.swap_rounds
        if swap_rounds:
            verdicts = [r.verdict.lower() for r in swap_rounds if r.verdict]
            if 'confirmed' in verdicts and 'false_positive' in verdicts:
                reasons.append("智能体之间意见冲突")

        # 检查依赖外部因素
        orig = finding.original_finding
        desc = orig.get('description', '').lower()
        if 'external' in desc or 'depends on' in desc or 'requires' in desc:
            reasons.append("可利用性依赖外部因素")

        if reasons:
            return "; ".join(reasons)
        else:
            return "自动验证信息不足，建议人工代码审查"

    def _generate_markdown_report(self, result: AuditResult) -> str:
        """生成Markdown格式报告"""
        stats = result.statistics
        report = result.final_report

        # 🔥 计算总体风险评分 (0-10)
        risk_score = self._calculate_risk_score(stats)
        risk_level = self._get_risk_level(risk_score)

        # 🔥 生成 Executive Summary
        executive_summary = self._generate_executive_summary(result, risk_score, risk_level)

        # 🔥 v2.4.11: 生成漏洞摘要表
        confirmed_findings = [
            f for f in result.verified_findings
            if f.verification_status == VerificationStatus.CONFIRMED
        ]
        vuln_summary_rows = self._generate_vulnerability_summary_table(confirmed_findings)

        # 🔥 v2.5.12: 添加传播链漏洞到摘要表
        propagation_vulns = [
            ev for ev in result.exploit_verifications
            if ev.get("is_propagation", False)
        ]
        if propagation_vulns:
            vuln_summary_rows += self._generate_propagation_summary_rows(
                propagation_vulns,
                start_index=len(confirmed_findings) + 1
            )

        md = f"""# 安全审计报告: {result.project_name}

## 执行摘要

{executive_summary}

---

## 目录

1. [概览](#概览)
2. [漏洞摘要](#漏洞摘要) - 快速索引
3. [详细发现](#详细发现) - 漏洞详情
4. [已过滤误报](#已过滤误报)
5. [漏洞利用链分析](#漏洞利用链分析-whitehat)
6. [修复建议](#修复建议)

---

## 概览

| 指标 | 值 |
|------|-----|
| 审计日期 | {result.audit_timestamp} |
| 耗时 | {result.duration_seconds:.1f}s |
| 风险评分 | **{risk_score}/10** ({risk_level}) |
| 初始发现 | {stats['total_raw_findings']} |
| 确认漏洞 | {stats['confirmed']} |
| 误报过滤 | {stats['false_positives']} ({stats['false_positive_rate']*100:.1f}%) |

### 严重性分布

| 🔴 严重 | 🟠 高危 | 🟡 中危 | 🟢 低危 |
|:-------:|:------:|:------:|:------:|
| {stats['severity_distribution']['critical']} | {stats['severity_distribution']['high']} | {stats['severity_distribution']['medium']} | {stats['severity_distribution']['low']} |

---

## 漏洞摘要

> 快速索引表，点击编号查看详情。

{vuln_summary_rows}

---

## 详细发现

"""
        # 添加确认的发现
        confirmed_findings = [
            f for f in result.verified_findings
            if f.verification_status == VerificationStatus.CONFIRMED
        ]

        for i, finding in enumerate(confirmed_findings, 1):
            orig = finding.original_finding
            location = orig.get('location', {})

            # 提取代码证据：优先使用 location.code_snippet，否则用 evidence/proof
            code_snippet = ''
            if isinstance(location, dict):
                code_snippet = location.get('code_snippet', '')
            if not code_snippet:
                code_snippet = orig.get('evidence') or orig.get('proof') or ''
            if not code_snippet:
                code_snippet = 'N/A'

            # 🔥 改进位置信息格式化: module::function:line
            loc_str = self._format_location(location, orig)

            # 🔥 v2.4.11: 整个漏洞详情可折叠，配合摘要表使用
            severity = finding.final_severity.upper()
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
            category = orig.get('category', 'N/A')
            title = orig.get('title', 'Unknown Issue')
            description = orig.get('description', 'N/A')
            recommendation = orig.get('recommendation', 'N/A')

            # 🔥 v2.5.0: 提取利用性分析
            exploit_analysis = ""
            if finding.manager_verdict and isinstance(finding.manager_verdict, dict):
                ea = finding.manager_verdict.get('exploitation_analysis', {})
                if ea and isinstance(ea, dict):
                    exploit_analysis = self._format_exploitation_analysis(ea)

            md += f"""<details>
<summary><strong>{i}. {title}</strong> — {sev_icon} {severity} | {category} | 置信度 {finding.final_confidence}%</summary>

**位置**: {loc_str}

**描述**: {description}

**漏洞代码**:
```move
{code_snippet}
```
{exploit_analysis}
**修复建议**: {recommendation}

</details>

"""

        # 🔥 添加误报过滤章节
        false_positives = [
            f for f in result.verified_findings
            if f.verification_status == VerificationStatus.FALSE_POSITIVE
        ]

        if false_positives:
            md += "\n## 已过滤误报\n\n"
            md += "> 以下发现经多智能体验证后判定为误报。\n\n"
            md += "| # | 标题 | 类别 | 过滤原因 |\n"
            md += "|---|------|------|----------|\n"
            for i, finding in enumerate(false_positives, 1):
                orig = finding.original_finding
                title = orig.get('title', 'Unknown')[:50]
                category = orig.get('category', 'N/A')
                # 尝试获取误报原因
                reason = self._get_false_positive_reason(finding)
                md += f"| {i} | {title} | {category} | {reason} |\n"
            md += "\n"

        # 🔥 改进需要人工审查的部分
        needs_review = [
            f for f in result.verified_findings
            if f.verification_status == VerificationStatus.NEEDS_REVIEW
        ]

        if needs_review:
            md += "\n## 需人工审查\n\n"
            md += "> 以下发现无法自动确认或排除，建议人工复核。\n\n"
            for finding in needs_review:
                orig = finding.original_finding
                loc_str = self._format_location(orig.get('location', {}), orig)
                md += f"### {orig.get('title', 'Unknown')}\n\n"
                md += f"- **位置**: {loc_str}\n"
                md += f"- **类别**: {orig.get('category', 'N/A')}\n"
                md += f"- **置信度**: {finding.final_confidence}%\n\n"
                md += f"**描述**: {orig.get('description', 'N/A')}\n\n"
                # 🔥 说明为什么需要人工审查
                review_reason = self._get_needs_review_reason(finding)
                md += f"**需要人工审查的原因**: {review_reason}\n\n"
                md += "---\n\n"

        # WhiteHat 利用链验证结果
        if result.exploit_verifications:
            md += "\n## 漏洞利用链分析 (WhiteHat)\n\n"

            # 分离单个漏洞和组合利用链
            individual_exploits = [e for e in result.exploit_verifications if not e.get("is_combined_exploit")]
            combined_exploits = [e for e in result.exploit_verifications if e.get("is_combined_exploit")]

            # 可利用的漏洞 (verified/likely) - GitHub Security Advisory 格式
            verified_exploits = [e for e in individual_exploits if e.get("status") in ["verified", "likely"]]
            if verified_exploits:
                md += "### ⚠️ 已验证可利用的漏洞\n\n"
                for ev in verified_exploits:
                    # 获取 advisory 信息
                    advisory = ev.get('advisory', {})
                    title = advisory.get('title') or ev.get('title', 'Unknown')
                    severity = advisory.get('severity') or ev.get('severity', 'N/A')

                    md += f"#### {title}\n\n"
                    md += f"| Field | Value |\n"
                    md += f"|-------|-------|\n"
                    md += f"| **Severity** | {severity.upper()} |\n"
                    md += f"| **Exploitability Score** | {ev.get('exploitability_score', 0)}/10 |\n"
                    md += f"| **Vulnerability Type** | {advisory.get('vulnerability_type', ev.get('vulnerability_type', 'N/A'))} |\n"
                    md += f"| **Affected Component** | {advisory.get('affected_component', 'N/A')} |\n\n"

                    # Vulnerability Summary
                    if ev.get('vulnerability_summary'):
                        md += f"**Vulnerability Summary**\n\n{ev['vulnerability_summary']}\n\n"

                    # Technical Details
                    tech = ev.get('technical_details', {})
                    if tech:
                        md += f"**Technical Details**\n\n"
                        # 🔥 v2.5.11: 处理 tech 可能是 str (传播链分析结果) 或 dict 的情况
                        if isinstance(tech, str):
                            md += f"{tech}\n\n"
                        elif isinstance(tech, dict):
                            if tech.get('root_cause'):
                                md += f"- **Root Cause**: {tech['root_cause']}\n"
                            if tech.get('vulnerable_line'):
                                md += f"- **Vulnerable Line**: {tech['vulnerable_line']}\n"
                            if tech.get('vulnerable_code'):
                                md += f"\n**Vulnerable Code**:\n```move\n{tech['vulnerable_code']}\n```\n"
                            md += "\n"

                    # Entry Point / Exploit Analysis
                    entry = ev.get('entry_point', {})
                    if entry and isinstance(entry, dict):
                        md += f"**Exploit Entry Point**\n\n"
                        if entry.get('function'):
                            md += f"```move\n{entry['function']}\n```\n"
                        md += f"| Property | Value |\n"
                        md += f"|----------|-------|\n"
                        if entry.get('visibility'):
                            md += f"| Visibility | {entry['visibility']} |\n"
                        if entry.get('required_objects'):
                            objs = entry['required_objects']
                            md += f"| Required Objects | {', '.join(objs) if isinstance(objs, list) else objs} |\n"
                        if entry.get('required_capabilities'):
                            md += f"| Required Capabilities | {entry['required_capabilities']} |\n"
                        if entry.get('attack_type'):
                            md += f"| Attack Type | {entry['attack_type']} |\n"
                        md += "\n"

                    # Attack Scenario
                    attack_scenario = ev.get('attack_scenario', [])
                    if attack_scenario:
                        md += f"**Attack Scenario**\n\n"
                        for step in attack_scenario:
                            if isinstance(step, str):
                                md += f"- {step}\n"
                            elif isinstance(step, dict):
                                md += f"- Step {step.get('step', '?')}: {step.get('action', step)}\n"
                        md += "\n"

                    # 🔥 Exploit Reasoning (利用思路)
                    if ev.get('exploit_reasoning'):
                        md += f"**Exploit Reasoning**\n\n> {ev['exploit_reasoning']}\n\n"

                    # 🔥 Exploit Module Code (完整利用代码)
                    if ev.get('exploit_module_code'):
                        md += f"**Exploit Code (Move Module)**\n\n```move\n{ev['exploit_module_code']}\n```\n\n"
                    # Legacy PoC Code
                    elif ev.get('poc_code'):
                        md += f"**Proof of Concept**\n\n```\n{ev['poc_code']}\n```\n\n"

                    # Impact Assessment
                    impact = ev.get('impact_assessment', ev.get('impact', {}))
                    if impact and isinstance(impact, dict):
                        md += f"**Impact Assessment**\n\n"
                        md += f"| Metric | Value |\n"
                        md += f"|--------|-------|\n"
                        if impact.get('what_attacker_gains'):
                            md += f"| What Attacker Gains | {impact['what_attacker_gains']} |\n"
                        md += f"| Max Loss | {impact.get('max_loss', 'N/A')} |\n"
                        md += f"| Affected Users | {impact.get('affected_users', impact.get('affected_parties', 'N/A'))} |\n"
                        if impact.get('attack_cost'):
                            md += f"| Attack Cost | {impact['attack_cost']} |\n"
                        if impact.get('profit_ratio'):
                            md += f"| Profit Ratio | {impact['profit_ratio']} |\n"
                        md += "\n"

                    # Preconditions
                    preconditions = ev.get('preconditions', [])
                    if preconditions:
                        md += f"**Preconditions**\n\n"
                        for pre in preconditions:
                            if isinstance(pre, str):
                                md += f"- {pre}\n"
                            elif isinstance(pre, dict):
                                cond = pre.get('condition', str(pre))
                                diff = pre.get('difficulty', '')
                                md += f"- {cond}"
                                if diff:
                                    md += f" (Difficulty: {diff})"
                                md += "\n"
                        md += "\n"

                    # Recommended Mitigation
                    mitigation = ev.get('recommended_mitigation', [])
                    if mitigation:
                        md += f"**Recommended Mitigation**\n\n"
                        for m in mitigation:
                            md += f"- {m}\n"
                        md += "\n"

                    md += "---\n\n"

            # 理论性/需审查的漏洞 - 也需要完整信息供人工分析
            other_exploits = [e for e in individual_exploits if e.get("status") in ["theoretical", "needs_review"]]
            if other_exploits:
                md += "### ⚪ 理论性 / 需审查\n\n"
                for ev in other_exploits:
                    advisory = ev.get('advisory', {})
                    title = advisory.get('title') or ev.get('title', 'Unknown')
                    severity = advisory.get('severity') or ev.get('severity', 'N/A')

                    md += f"#### {title}\n\n"
                    md += f"| Field | Value |\n"
                    md += f"|-------|-------|\n"
                    md += f"| **Severity** | {severity.upper()} |\n"
                    md += f"| **Status** | {ev.get('status', 'needs_review')} |\n"
                    md += f"| **Exploitability Score** | {ev.get('exploitability_score', 0)}/10 |\n\n"

                    # Vulnerability Summary
                    if ev.get('vulnerability_summary'):
                        md += f"**Vulnerability Summary**\n\n{ev['vulnerability_summary']}\n\n"

                    # Technical Details
                    tech = ev.get('technical_details', {})
                    if tech:
                        if tech.get('vulnerable_code'):
                            md += f"**Vulnerable Code**:\n```move\n{tech['vulnerable_code']}\n```\n\n"
                        if tech.get('root_cause'):
                            md += f"**Root Cause**: {tech['root_cause']}\n\n"

                    # 为什么不可利用
                    if ev.get('why_not_exploitable'):
                        md += f"**Why Not Exploitable**\n\n{ev['why_not_exploitable']}\n\n"

                    # Blocking Factors
                    blocking = ev.get('blocking_factors', [])
                    if blocking:
                        md += f"**Blocking Factors**\n\n"
                        for b in blocking:
                            md += f"- {b}\n"
                        md += "\n"

                    # 即使是理论性的，也显示攻击场景（如果有）
                    attack_scenario = ev.get('attack_scenario', [])
                    if attack_scenario:
                        md += f"**Theoretical Attack Scenario**\n\n"
                        for step in attack_scenario:
                            if isinstance(step, str):
                                md += f"{step}\n"
                            elif isinstance(step, dict):
                                md += f"Step {step.get('step', '?')}: {step.get('action', step)}\n"
                        md += "\n"

                    # Recommended Mitigation
                    mitigation = ev.get('recommended_mitigation', [])
                    if mitigation:
                        md += f"**Recommended Mitigation** (if risk accepted)\n\n"
                        for m in mitigation:
                            md += f"- {m}\n"
                        md += "\n"

                    md += "---\n\n"

            # 失败的验证
            failed_exploits = [e for e in individual_exploits if e.get("status") == "error"]
            if failed_exploits:
                md += "### ❌ 验证失败\n\n"
                for ev in failed_exploits:
                    md += f"- **{ev.get('title', 'Unknown')}**: {ev.get('error', 'Unknown error')}\n"
                md += "\n"

            # 组合利用链
            if combined_exploits:
                md += "### 🔗 组合利用链\n\n"
                for ev in combined_exploits:
                    # 🔥 标注是否跨模块
                    chain_type = "🔥 Cross-Module" if ev.get('is_cross_module') else "Module-Internal"
                    md += f"**{ev.get('title', 'Combined Attack')}** ({chain_type})\n"
                    md += f"- Involved Vulnerabilities: {', '.join(ev.get('involved_vulnerabilities', []))}\n"
                    md += f"- Exploitability Score: {ev.get('exploitability_score', 0)}/10\n"

                    # 🔥 显示跨模块调用关系
                    if ev.get('cross_module_calls'):
                        md += f"- Cross-Module Calls:\n"
                        for call in ev.get('cross_module_calls', []):
                            md += f"  - `{call}`\n"

                    # 入口点
                    if ev.get('entry_point'):
                        entry = ev['entry_point']
                        if isinstance(entry, dict):
                            md += f"\n**Entry Point**:\n"
                            md += f"```move\n{entry.get('function', 'unknown')}\n```\n"
                        else:
                            md += f"- Entry Point: `{entry}`\n"

                    # 攻击路径
                    if ev.get('attack_path'):
                        md += f"\n**Attack Path**:\n"
                        for step in ev.get('attack_path', []):
                            if isinstance(step, dict):
                                md += f"\n**Step {step.get('step', '?')}**: {step.get('action', '')}\n"
                                if step.get('function_call'):
                                    md += f"- Function Call: `{step['function_call']}`\n"
                                if step.get('attack_arguments'):
                                    args = step['attack_arguments']
                                    if isinstance(args, dict):
                                        md += f"- Arguments: {', '.join(f'{k}={v}' for k, v in args.items())}\n"
                                    else:
                                        md += f"- Arguments: {args}\n"
                                if step.get('state_change'):
                                    md += f"- State Change: {step['state_change']}\n"
                            else:
                                md += f"  - {step}\n"

                    if ev.get('one_liner_exploit'):
                        md += f"\n**Combined Exploit**: {ev['one_liner_exploit']}\n"

                    # 🔥 Exploit Reasoning (利用思路)
                    if ev.get('exploit_reasoning'):
                        md += f"\n**Exploit Reasoning**\n\n> {ev['exploit_reasoning']}\n"

                    # 🔥 Exploit Module Code (完整利用代码)
                    if ev.get('exploit_module_code'):
                        md += f"\n**Exploit Code (Move Module)**\n\n```move\n{ev['exploit_module_code']}\n```\n"
                    elif ev.get('poc_code'):
                        md += f"\n**PoC Code**\n\n```move\n{ev['poc_code']}\n```\n"

                    # Attack Scenario
                    if ev.get('attack_scenario'):
                        md += "\n**Attack Scenario**\n\n"
                        for i, step in enumerate(ev['attack_scenario'], 1):
                            md += f"- {step}\n"

                    # Recommended Mitigation
                    if ev.get('recommended_mitigation'):
                        md += "\n**Recommended Mitigation**\n\n"
                        for fix in ev['recommended_mitigation']:
                            md += f"- {fix}\n"

                    md += "\n---\n\n"

            # 利用统计
            exploit_stats = stats.get('exploit_verification', {})
            md += f"""
### 利用验证统计

| 状态 | 数量 |
|------|------|
| 已验证 | {exploit_stats.get('verified', 0)} |
| 可能 | {exploit_stats.get('likely', 0)} |
| 理论性 | {exploit_stats.get('theoretical', 0)} |
| 组合链 | {exploit_stats.get('combined_chains', 0)} |

"""

        md += f"""
## 修复建议

"""
        for rec in report.get("summary", {}).get("recommendations", []):
            md += f"- {rec}\n"

        md += """
---

*报告由 AutoSpec 安全审计引擎自动生成*
"""
        return md

    def _print_summary(self, result: AuditResult):
        """打印审计摘要"""
        stats = result.statistics

        print(f"\n{'='*60}")
        print("📋 审计完成摘要")
        print(f"{'='*60}")
        print(f"项目: {result.project_name}")
        print(f"耗时: {result.duration_seconds:.1f} 秒")
        print(f"\n发现统计:")
        print(f"  原始发现: {stats['total_raw_findings']}")
        print(f"  确认漏洞: {stats['confirmed']}")
        print(f"  误报过滤: {stats['false_positives']} ({stats['false_positive_rate']*100:.1f}%)")
        print(f"  需人工审查: {stats['needs_review']}")
        print(f"\n严重性分布:")
        for sev, count in stats['severity_distribution'].items():
            if count > 0:
                print(f"  {sev.upper()}: {count}")
        print(f"\n平均置信度: {stats['average_confidence']:.1f}%")

        # WhiteHat 利用链验证统计
        exploit_stats = stats.get('exploit_verification', {})
        if any(exploit_stats.values()):
            print(f"\n🎩 WhiteHat 利用链验证:")
            verified = exploit_stats.get('verified', 0)
            likely = exploit_stats.get('likely', 0)
            combined = exploit_stats.get('combined_chains', 0)
            if verified + likely > 0:
                print(f"  ⚠️ 可利用漏洞: {verified + likely}")
            if combined > 0:
                print(f"  🔗 组合利用链: {combined}")
            print(f"  理论性: {exploit_stats.get('theoretical', 0)}")

        print(f"{'='*60}")

        # 🔥 v2.5.8: 打印 Token 使用量统计
        self._print_token_usage()

    def _get_all_agents(self):
        """🔥 v2.5.8: 获取所有 Agent 实例"""
        agents = []
        for attr_name in ['manager', 'analyst', 'auditor', 'white_hat', 'verifier', 'expert']:
            agent = getattr(self, attr_name, None)
            if agent is not None:
                agents.append((attr_name, agent))
        return agents

    def _print_token_usage(self):
        """🔥 v2.5.8: 打印 Token 使用量统计"""
        print(f"\n{'='*60}")
        print("📊 Token 使用量统计")
        print(f"{'='*60}")

        total_prompt = 0
        total_completion = 0
        total_tokens = 0
        total_calls = 0

        for agent_name, agent in self._get_all_agents():
            if hasattr(agent, 'get_token_usage'):
                usage = agent.get_token_usage()
                if usage.get('call_count', 0) > 0:
                    print(f"  {agent_name:12}: {usage['total_tokens']:>8,} tokens ({usage['call_count']} calls)")
                    total_prompt += usage.get('prompt_tokens', 0)
                    total_completion += usage.get('completion_tokens', 0)
                    total_tokens += usage.get('total_tokens', 0)
                    total_calls += usage.get('call_count', 0)

        print(f"  {'-'*40}")
        print(f"  {'Total':12}: {total_tokens:>8,} tokens ({total_calls} calls)")
        print(f"    - Prompt:     {total_prompt:>8,}")
        print(f"    - Completion: {total_completion:>8,}")
        print(f"{'='*60}")


async def run_audit(
    code: str,
    project_name: str = "Unknown",
    config: Optional[AuditConfig] = None,
    project_path: Optional[str] = None
) -> AuditResult:
    """
    便捷函数：运行安全审计

    Args:
        code: Move源代码
        project_name: 项目名称
        config: 审计配置
        project_path: Move 项目路径 (用于精准上下文检索)

    Returns:
        审计结果
    """
    engine = SecurityAuditEngine(config=config, project_path=project_path)
    return await engine.audit(code, project_name, project_path=project_path)
