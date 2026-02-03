"""
RoleSwapMechanism v2 - 精简版角色交换机制 (v2.5.3)

从 5 Agent 架构精简为 3 Agent 架构:
- 原架构: Auditor → Expert → Analyst → Manager (4 次 LLM 调用)
- 新架构: Verifier → Manager (可选) (1-2 次 LLM 调用)

Token 消耗对比 (10 个漏洞):
- 原架构: 4 × 10 = 40 次 LLM 调用
- 新架构: 10 + ~3 = 13 次 LLM 调用 (Manager 只在低置信度时介入)
- 节省: 约 68%

工作流程:
1. Verifier 从三个视角一次性验证漏洞
2. 如果 Verifier 置信度 >= 80 且结论明确，直接返回
3. 如果置信度 < 80 或结论为 needs_review，Manager 介入判定
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

from .base_agent import AgentRole, AgentMessage
from .manager_agent import ManagerAgent
from .verifier_agent import VerifierAgent, VERIFIER_VERIFICATION_PROMPT

# 🔥 v2.5.11: VerificationStatus 直接定义 (role_swap.py 已移至 backup/)
class VerificationStatus(Enum):
    """验证状态"""
    CONFIRMED = "confirmed"           # 确认是真实漏洞
    FALSE_POSITIVE = "false_positive" # 误报
    NEEDS_REVIEW = "needs_review"     # 需要人工审查
    PARTIALLY_VALID = "partially_valid"  # 部分有效

# 🔥 v2.5.10: 恢复 move_knowledge 误报排除功能
from .move_knowledge import get_relevant_knowledge

# 🔥 v2.5.10: 引入预判断函数 (与 verifier_agent.py 保持一致)
try:
    from src.prompts.sui_move_security_knowledge import is_likely_false_positive
    KNOWLEDGE_AVAILABLE = True
except ImportError:
    KNOWLEDGE_AVAILABLE = False
    def is_likely_false_positive(vtype, desc): return False, ""

# 配置 logger
logger = logging.getLogger(__name__)


@dataclass
class SwapRoundResult:
    """单轮交换结果"""
    round_number: int
    agent_role: str  # "verifier" | "manager"
    analysis: Dict[str, Any]
    verdict: str
    confidence: int
    notes: str = ""


@dataclass
class VerifiedFinding:
    """经过验证的发现 (兼容 V1 接口)"""
    original_finding: Dict[str, Any]
    verification_status: VerificationStatus
    swap_rounds: List[SwapRoundResult]
    final_severity: str
    final_confidence: int
    verifier_result: Dict[str, Any]  # Verifier 的完整结果
    manager_verdict: Dict[str, Any]   # Manager 的判定 (如果有)
    recommendations: List[str] = field(default_factory=list)
    # 保存 Phase 3 分析使用的代码上下文，供 Phase 4 复用
    code_context: str = ""

    # 🔥 v2.5.3 fix: 兼容 V1 接口的属性别名
    @property
    def expert_review(self) -> Dict[str, Any]:
        """兼容 V1: 从 verifier_result 提取技术分析部分"""
        return self.verifier_result.get("technical_analysis", self.verifier_result)

    @property
    def analyst_assessment(self) -> Dict[str, Any]:
        """兼容 V1: 从 verifier_result 提取业务分析部分"""
        return self.verifier_result.get("business_impact", {})


class RoleSwapMechanismV2:
    """
    精简版角色交换机制 (3 Agent 架构)

    Verifier: 合并 Auditor/Expert/Analyst，一次调用完成多视角验证
    Manager: 只在低置信度或结论不明确时介入

    使用示例:
    ```python
    role_swap = RoleSwapMechanismV2(
        verifier=VerifierAgent(config),
        manager=ManagerAgent(config),
        use_tools=True
    )
    verified = await role_swap.verify_finding(finding, code_context)
    ```
    """

    # 置信度阈值：高于此值且结论明确时，跳过 Manager
    CONFIDENCE_THRESHOLD = 80

    def __init__(
        self,
        verifier: VerifierAgent,
        manager: ManagerAgent,
        toolkit: Optional[Any] = None,
        use_tools: bool = False
    ):
        self.verifier = verifier
        self.manager = manager
        self.toolkit = toolkit
        self.use_tools = use_tools

        # 保存配置，用于并行时创建独立实例
        self._verifier_config = getattr(verifier, 'config', None)
        self._manager_config = getattr(manager, 'config', None)

    def _create_agent_set(self) -> Dict[str, Any]:
        """创建一组独立的 Agent 实例 (用于并行验证)"""
        return {
            "verifier": VerifierAgent(self._verifier_config),
            "manager": ManagerAgent(self._manager_config),
        }

    def _extract_function_name(self, finding: Dict[str, Any]) -> str:
        """从 finding 中提取函数名"""
        location = finding.get('location', {})

        if isinstance(location, dict):
            func_name = location.get('function', '')
            if func_name:
                return func_name
            path = location.get('path', '')
            if '::' in path:
                return path.split('::')[-1]
        elif isinstance(location, str) and '::' in location:
            return location.split('::')[-1]

        # 从标题中提取
        title = finding.get('title', '')
        patterns = [
            r'`([a-zA-Z_][a-zA-Z0-9_<>,\s:-]*)`',
            r'([a-zA-Z_][a-zA-Z0-9_-]*)\s*函数',
            r'::([a-zA-Z_][a-zA-Z0-9_-]*)',
        ]
        for pattern in patterns:
            match = re.search(pattern, title)
            if match:
                return match.group(1).split('<')[0].strip()

        return ''

    def _ensure_code_context(
        self,
        finding: Dict[str, Any],
        code_context: str,
        full_code: str,
        task_id: str = ""
    ) -> str:
        """
        🔥 v2.5.8 优化: 只提取漏洞相关函数，不传完整代码

        优先级:
        1. Phase 2 预构建的上下文 (_phase2_context)
        2. toolkit 智能提取 (目标函数 + 调用者/被调用者)
        3. finding 中的 evidence/proof 代码片段
        4. 最小化回退 (不再传完整代码)
        """
        MIN_CONTEXT_LENGTH = 50

        # 1. 优先使用 Phase 2 预构建的上下文
        phase2_context = finding.get("_phase2_context", "")
        if phase2_context and len(phase2_context.strip()) >= MIN_CONTEXT_LENGTH:
            return phase2_context

        # 2. 使用 toolkit 智能提取
        if self.toolkit:
            func_name = self._extract_function_name(finding)
            location = finding.get('location', {})
            module_name = location.get('module', '') if isinstance(location, dict) else ''

            if func_name:
                try:
                    context_parts = []
                    caller_tag = "RoleSwapV2"

                    # 获取目标函数实现
                    func_result = self.toolkit.call_tool("get_function_code", {
                        "module": module_name,
                        "function": func_name
                    }, caller=caller_tag)
                    if func_result.success:
                        body = func_result.data.get("body", "")
                        context_parts.append(f"// 目标函数: {module_name}::{func_name}\n{body}")

                    # 获取调用者 (帮助理解入口点)
                    callers_result = self.toolkit.call_tool("get_callers", {
                        "module": module_name,
                        "function": func_name,
                        "depth": 1
                    }, caller=caller_tag)
                    if callers_result.success:
                        callers = callers_result.data.get("callers", [])
                        if callers:
                            caller_names = [c.get("id", c) if isinstance(c, dict) else c for c in callers[:3]]
                            context_parts.append(f"// 调用者: {', '.join(caller_names)}")

                    # 🔥 v2.5.8: 获取被调用函数 (帮助理解内部逻辑)
                    callees_result = self.toolkit.call_tool("get_callees", {
                        "module": module_name,
                        "function": func_name,
                        "depth": 1
                    }, caller=caller_tag)
                    if callees_result.success:
                        callees = callees_result.data.get("callees", [])
                        if callees:
                            callee_names = [c.get("id", c) if isinstance(c, dict) else c for c in callees[:3]]
                            context_parts.append(f"// 调用链: {', '.join(callee_names)}")

                    if context_parts:
                        combined = "\n\n".join(context_parts)
                        if len(combined.strip()) >= MIN_CONTEXT_LENGTH:
                            return combined

                except Exception as e:
                    logger.warning(f"{task_id} toolkit 提取失败: {e}")

        # 3. 🔥 v2.5.8: 使用 finding 中的证据代码 (不再回退到完整代码)
        evidence = finding.get("evidence", finding.get("proof", ""))
        if evidence and len(evidence.strip()) >= MIN_CONTEXT_LENGTH:
            func_name = self._extract_function_name(finding)
            return f"// 漏洞相关代码 ({func_name}):\n{evidence[:2000]}"

        # 4. 最小化回退: 只返回漏洞描述，让 Agent 用工具查询
        description = finding.get("description", "")
        title = finding.get("title", "Unknown")
        return f"// 漏洞: {title}\n// 描述: {description[:500]}\n// ⚠️ 请使用工具查询相关函数代码"

    async def verify_finding(
        self,
        finding: Dict[str, Any],
        code_context: str = "",  # 🔥 v2.5.8: 不再使用
        full_code: str = ""      # 🔥 v2.5.8: 不再使用
    ) -> VerifiedFinding:
        """
        验证单个发现 (精简流程)

        🔥 v2.5.8 优化: 代码上下文由 _ensure_code_context 按需提取，不依赖传入参数

        流程:
        1. Verifier 多视角验证
        2. 如果置信度 >= 80 且结论明确，直接返回
        3. 否则 Manager 介入判定

        Args:
            finding: 原始漏洞发现
            code_context: [已废弃] 保留兼容性
            full_code: [已废弃] 保留兼容性

        Returns:
            验证后的发现
        """
        finding_id = finding.get('id', finding.get('title', 'unknown')[:20])
        task_id = f"[{finding_id}]"
        finding_title = finding.get('title', 'Unknown')[:50]

        # 确保有足够的代码上下文
        actual_code_context = self._ensure_code_context(finding, code_context, full_code, task_id)

        swap_rounds = []

        # ============================================================
        # Step 1: Verifier 多视角验证 (1 次 LLM 调用)
        # ============================================================
        print(f"\n  🔍 [Verifier] 验证漏洞: {finding_title}")

        if self.use_tools and self.toolkit:
            self.verifier.set_toolkit(self.toolkit)
            function_index = self.toolkit.get_function_index()
            analysis_context = self.toolkit.get_analysis_context()

            verifier_result = await self.verifier.verify_with_tools(
                finding={**finding, "code_context": actual_code_context},
                verification_prompt=VERIFIER_VERIFICATION_PROMPT,
                function_index=function_index,
                analysis_context=analysis_context
            )
        else:
            verifier_result = await self.verifier.verify_finding(finding, actual_code_context)

        conclusion = verifier_result.get("conclusion", "needs_review")
        confidence = verifier_result.get("confidence", 50)
        print(f"     → 结论: {conclusion}, 置信度: {confidence}%")

        swap_rounds.append(SwapRoundResult(
            round_number=1,
            agent_role="verifier",
            analysis=verifier_result,
            verdict=conclusion,
            confidence=confidence,
            notes=verifier_result.get("reasoning", "")
        ))

        # ============================================================
        # Step 2: 🔥 v2.5.8 简化: 移除 Manager 介入，Verifier 直接判定
        # ============================================================
        # 原逻辑: 低置信度时 Manager 介入
        # 新逻辑: Verifier 直接判定，needs_review 转为 confirmed (保守策略)
        manager_result = {}
        final_conclusion = conclusion
        final_confidence = confidence

        # 如果 Verifier 返回 needs_review，转为 confirmed (需要人工审查)
        if conclusion == "needs_review":
            print(f"     → needs_review 转为 confirmed (保守策略)")
            final_conclusion = "confirmed"
            final_confidence = max(confidence, 60)  # 至少 60% 置信度

        # ============================================================
        # Step 3: 构建结果
        # ============================================================
        final_status = self._determine_final_status(final_conclusion)
        final_severity = verifier_result.get("final_severity", finding.get("severity", "medium"))

        if final_status == VerificationStatus.FALSE_POSITIVE:
            final_severity = "none"

        recommendations = []
        if verifier_result.get("recommendation"):
            recommendations.append(verifier_result["recommendation"])
        if manager_result.get("action_required"):
            recommendations.append(manager_result["action_required"])

        return VerifiedFinding(
            original_finding=finding,
            verification_status=final_status,
            swap_rounds=swap_rounds,
            final_severity=final_severity,
            final_confidence=final_confidence,
            verifier_result=verifier_result,
            manager_verdict=manager_result,
            recommendations=recommendations,
            code_context=actual_code_context
        )

    async def batch_verify(
        self,
        findings: List[Dict[str, Any]],
        code_context: str = "",  # 🔥 v2.5.8: 不再使用，保留参数兼容性
        parallel: bool = True,
        max_concurrent: int = None,
        batch_size: int = None,  # 并发批次大小 (不用于分组)
        batch_cooldown: float = None,
        use_group_verify: bool = True,  # 🔥 v2.5.11: 是否使用分组批量验证
        group_size: int = 5  # 🔥 v2.5.16: 独立的分组大小参数
    ) -> List[VerifiedFinding]:
        """
        🔥 v2.5.11: 分组批量验证 + 工具调用 + Token 优化

        验证模式:
        - use_group_verify=True (默认): 分组批量验证，节省 ~60% Token
        - use_group_verify=False: 单个漏洞验证，最高准确度

        Token 优化策略:
        1. 智能分组: 同模块漏洞分到一组 (共享代码上下文)
        2. 预构建上下文: 批量获取函数代码，减少工具调用
        3. 共享知识: 一组漏洞共享安全知识
        4. 工具缓存: 同组漏洞共享工具调用结果

        预计节省:
        - 100 漏洞 → 20 组
        - System prompt: 100 次 → 20 次 (节省 80%)
        - 代码上下文: 共享复用 (节省 60%)
        - 总计: ~450K tokens vs ~1.15M tokens (节省 60%)

        Args:
            findings: 发现列表
            code_context: [已废弃] 不再使用
            parallel: 是否并行验证
            max_concurrent: 最大并发数
            batch_size: 并发批次大小 (不用于分组)
            batch_cooldown: 批次间冷却时间
            use_group_verify: 是否使用分组批量验证
            group_size: 每组漏洞数 (默认 5)

        Returns:
            验证后的发现列表
        """
        from src.config import AUDIT_CONCURRENCY

        if max_concurrent is None:
            max_concurrent = AUDIT_CONCURRENCY["max_concurrent_verify"]
        if batch_cooldown is None:
            batch_cooldown = AUDIT_CONCURRENCY["batch_cooldown"]

        # 🔥 v2.5.16: 分组大小独立配置，不再误用 batch_size
        GROUP_SIZE = group_size
        total = len(findings)

        # ============================================================
        # Step 1: 按模块分组漏洞
        # ============================================================
        module_groups = {}  # {module_name: [findings]}
        for finding in findings:
            location = finding.get("location", {})
            module_name = finding.get("_module_name", location.get("module", "unknown") if isinstance(location, dict) else "unknown")

            if module_name not in module_groups:
                module_groups[module_name] = []
            module_groups[module_name].append(finding)

        # 统计
        print(f"\n  🔍 验证 {total} 个发现 (分布在 {len(module_groups)} 个模块)")

        # ============================================================
        # Step 2: 获取每个漏洞的函数代码
        # ============================================================
        print(f"  📥 获取漏洞相关函数代码...")
        code_from_phase2 = 0
        code_from_toolkit = 0
        code_from_evidence = 0

        for module_name, module_findings in module_groups.items():
            for finding in module_findings:
                location = finding.get("location", {})
                func_name = location.get("function", "unknown") if isinstance(location, dict) else "unknown"

                # 尝试获取函数代码
                function_code = ""

                # 1. 优先使用 Phase 2 保存的上下文
                phase2_ctx = finding.get("_phase2_func_context", {})
                if phase2_ctx:
                    function_code = phase2_ctx.get("function_code", "")
                    if function_code:
                        code_from_phase2 += 1
                    # 🔥 获取调用者签名 (用于判断分层设计)
                    caller_sigs = phase2_ctx.get("caller_signatures", [])
                    if caller_sigs:
                        finding["_caller_signatures"] = caller_sigs

                # 2. 使用 toolkit 获取
                if not function_code and self.toolkit and func_name != "unknown":
                    func_result = self.toolkit.call_tool("get_function_code", {
                        "module": module_name,
                        "function": func_name
                    }, caller="RoleSwapV2")
                    if func_result.success:
                        function_code = func_result.data.get("body", "")
                        if function_code:
                            code_from_toolkit += 1

                # 3. 使用 evidence 作为后备
                if not function_code:
                    function_code = finding.get("evidence", finding.get("proof", ""))
                    if function_code:
                        code_from_evidence += 1

                # 保存到 finding
                finding["_function_code"] = function_code

        print(f"     → Phase2 上下文: {code_from_phase2}, Toolkit: {code_from_toolkit}, Evidence: {code_from_evidence}")

        # ============================================================
        # 🔥 v2.5.11: 分组批量验证 (Token 优化)
        # ============================================================
        if use_group_verify and self.use_tools and self.toolkit:
            return await self._batch_verify_grouped(
                findings=findings,
                module_groups=module_groups,
                group_size=GROUP_SIZE,
                max_concurrent=max_concurrent,
                batch_cooldown=batch_cooldown
            )

        # ============================================================
        # Step 3: 单个漏洞并行验证 (备选模式)
        # ============================================================
        # 注: 原来的批量验证 (verify_findings_batch) 没有工具调用能力，导致判断不准确
        # 现在改回单个漏洞验证 (verify_with_tools)，每个漏洞都可以按需查询代码
        semaphore = asyncio.Semaphore(max_concurrent)
        all_verified = []
        completed_count = 0
        completed_lock = asyncio.Lock()

        async def verify_single(
            finding_idx: int,
            finding: Dict[str, Any]
        ) -> VerifiedFinding:
            """
            🔥 v2.5.10 修复: 恢复单个验证 + 工具调用 + move_knowledge 注入

            v2.5.9 修复了工具调用，但丢失了 move_knowledge 误报排除。
            v2.5.10 同时保留：
            1. 工具调用能力 (按需查询代码)
            2. move_knowledge 注入 (针对性知识)
            3. 预判断提示 (is_likely_false_positive)
            """
            nonlocal completed_count

            async with semaphore:
                try:
                    finding_title = finding.get('title', 'Unknown')[:50]

                    # 获取代码上下文
                    actual_code_context = self._ensure_code_context(finding, "", "", f"[{finding_idx+1}/{total}]")

                    # ============================================================
                    # 🔥 v2.5.10: 注入 move_knowledge + 预判断
                    # ============================================================
                    # 1. 获取针对性知识
                    vuln_knowledge = get_relevant_knowledge(finding)

                    # 2. 预判断是否是误报
                    # 🔥 v2.5.13: 优先使用软过滤提示（来自排除规则）
                    fp_hint = ""
                    soft_filter = finding.get("soft_filter_hint")
                    if soft_filter:
                        fp_hint = f"\n🔶 **排除规则提示** [{soft_filter.get('rule_name', 'unknown')}]:\n{soft_filter.get('hint_for_ai', '')}\n"
                    elif KNOWLEDGE_AVAILABLE:
                        category = finding.get("category", "")
                        description = finding.get("description", "")
                        is_fp, fp_reason = is_likely_false_positive(category, description)
                        if is_fp:
                            fp_hint = f"\n⚠️ **预判断提示**: 此漏洞类型可能是误报 - {fp_reason}\n"

                    # 3. 构建增强的 verification_prompt
                    enhanced_prompt = VERIFIER_VERIFICATION_PROMPT
                    if vuln_knowledge or fp_hint:
                        knowledge_section = ""
                        if vuln_knowledge:
                            knowledge_section += f"\n## 🔥 针对性安全知识 (根据漏洞类型匹配)\n{vuln_knowledge}\n"
                        if fp_hint:
                            knowledge_section += fp_hint
                        enhanced_prompt = knowledge_section + "\n---\n" + VERIFIER_VERIFICATION_PROMPT

                    # 🔥 使用带工具调用的验证方法
                    if self.use_tools and self.toolkit:
                        self.verifier.set_toolkit(self.toolkit)
                        function_index = self.toolkit.get_function_index()
                        analysis_context = self.toolkit.get_analysis_context()

                        # 🔥 v2.5.14: 减少工具轮次从 8 降到 3
                        result = await self.verifier.verify_with_tools(
                            finding={**finding, "code_context": actual_code_context},
                            verification_prompt=enhanced_prompt,
                            function_index=function_index,
                            analysis_context=analysis_context,
                            max_tool_rounds=3
                        )
                    else:
                        result = await self.verifier.verify_finding(finding, actual_code_context)

                    conclusion = result.get("conclusion", "needs_review")
                    confidence = result.get("confidence", 50)

                    # needs_review 转为 confirmed (保守策略)
                    if conclusion == "needs_review":
                        conclusion = "confirmed"
                        confidence = max(confidence, 60)

                    status = self._determine_final_status(conclusion)
                    severity = result.get("final_severity", finding.get("severity", "medium"))
                    if status == VerificationStatus.FALSE_POSITIVE:
                        severity = "none"

                    async with completed_lock:
                        completed_count += 1

                    # 打印进度
                    status_icon = "✓" if status == VerificationStatus.FALSE_POSITIVE else "🔴"
                    print(f"    {status_icon} [{completed_count}/{total}] {finding_title} → {conclusion}")

                    return VerifiedFinding(
                        original_finding=finding,
                        verification_status=status,
                        swap_rounds=[SwapRoundResult(
                            round_number=1,
                            agent_role="verifier",
                            analysis=result,
                            verdict=conclusion,
                            confidence=confidence,
                            notes=result.get("reasoning", "")
                        )],
                        final_severity=severity,
                        final_confidence=confidence,
                        verifier_result=result,
                        manager_verdict={},
                        recommendations=[],
                        code_context=actual_code_context[:2000]
                    )

                except Exception as e:
                    async with completed_lock:
                        completed_count += 1
                    print(f"    ⚠️ [{completed_count}/{total}] {finding.get('title', 'Unknown')[:30]} → 失败: {e}")
                    return self._create_error_finding(finding, str(e))

        # 🔥 v2.5.9: 改为单个漏洞验证 (恢复工具调用能力)
        # 展平所有漏洞列表
        all_findings_flat = []
        for module_name, module_findings in module_groups.items():
            for finding in module_findings:
                finding["_module_name"] = module_name  # 保留模块名
                all_findings_flat.append(finding)

        # 创建单个漏洞验证任务
        tasks = [
            verify_single(i, finding)
            for i, finding in enumerate(all_findings_flat)
        ]

        # 并行执行
        print(f"  ⚡ 并发验证: {total} 漏洞, 最大并发 {max_concurrent}")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 收集结果
        for result in results:
            if isinstance(result, Exception):
                print(f"  ⚠️ 任务异常: {result}")
                continue
            if isinstance(result, VerifiedFinding):
                all_verified.append(result)

        # ============================================================
        # Step 5: 统计和返回
        # ============================================================
        confirmed = sum(1 for v in all_verified if v.verification_status == VerificationStatus.CONFIRMED)
        false_pos = sum(1 for v in all_verified if v.verification_status == VerificationStatus.FALSE_POSITIVE)

        print(f"\n  📊 Phase 3 完成: {len(all_verified)} 验证")
        print(f"     - Confirmed: {confirmed}")
        print(f"     - False Positive: {false_pos}")

        return all_verified

    async def _batch_verify_grouped(
        self,
        findings: List[Dict[str, Any]],
        module_groups: Dict[str, List[Dict[str, Any]]],
        group_size: int = 5,
        max_concurrent: int = 3,
        batch_cooldown: float = 1.0
    ) -> List[VerifiedFinding]:
        """
        🔥 v2.5.11: 分组批量验证实现

        核心流程：
        1. 智能分组：同模块漏洞分到一组
        2. 预构建上下文：每组共享代码上下文
        3. 收集知识：每组共享安全知识
        4. 批量验证：每组一次 LLM 调用 + 工具调用

        Args:
            findings: 所有漏洞
            module_groups: 按模块分组的漏洞
            group_size: 每组最大漏洞数
            max_concurrent: 最大并发组数
            batch_cooldown: 批次间冷却时间

        Returns:
            验证后的发现列表
        """
        total = len(findings)

        # Step 1: 智能分组
        groups = self._group_findings_smart(findings, max_per_group=group_size)
        print(f"\n  📦 分组策略: {total} 漏洞 → {len(groups)} 组 (每组最多 {group_size} 个)")

        # Step 2: 并行验证各组
        semaphore = asyncio.Semaphore(max_concurrent)
        all_verified = []
        completed_groups = 0
        completed_lock = asyncio.Lock()

        async def verify_group(group_idx: int, group: List[Dict[str, Any]]) -> List[VerifiedFinding]:
            """验证一组漏洞"""
            nonlocal completed_groups

            async with semaphore:
                try:
                    module_name = group[0].get("_group_module", "unknown") if group else "unknown"
                    group_titles = [f.get("title", "?")[:20] for f in group[:3]]
                    print(f"  🔍 组 {group_idx + 1}/{len(groups)}: {module_name} ({len(group)} 漏洞)")

                    # 预构建共享上下文
                    shared_context, func_code_map = self._build_group_context(group)

                    # 收集共享知识
                    group_knowledge = self._collect_group_knowledge(group)

                    # 设置 toolkit
                    self.verifier.set_toolkit(self.toolkit)
                    function_index = self.toolkit.get_function_index()
                    analysis_context = self.toolkit.get_analysis_context()

                    # 调用分组验证
                    # 🔥 v2.5.14: 减少工具轮次从 8 降到 3，因为已有预构建上下文
                    results = await self.verifier.verify_group_with_tools(
                        findings=group,
                        shared_context=shared_context,
                        group_knowledge=group_knowledge,
                        function_index=function_index,
                        analysis_context=analysis_context,
                        max_tool_rounds=3  # 已有共享上下文，不需要太多轮次
                    )

                    # 转换为 VerifiedFinding
                    verified_findings = []
                    for i, result in enumerate(results):
                        finding = result.get("original_finding", group[i] if i < len(group) else {})
                        conclusion = result.get("conclusion", "needs_review")
                        confidence = result.get("confidence", 50)

                        # needs_review 转为 confirmed (保守策略)
                        if conclusion == "needs_review":
                            conclusion = "confirmed"
                            confidence = max(confidence, 60)

                        status = self._determine_final_status(conclusion)
                        severity = result.get("final_severity", finding.get("severity", "medium"))
                        if status == VerificationStatus.FALSE_POSITIVE:
                            severity = "none"

                        verified_findings.append(VerifiedFinding(
                            original_finding=finding,
                            verification_status=status,
                            swap_rounds=[SwapRoundResult(
                                round_number=1,
                                agent_role="verifier",
                                analysis=result,
                                verdict=conclusion,
                                confidence=confidence,
                                notes=result.get("reasoning", "")
                            )],
                            final_severity=severity,
                            final_confidence=confidence,
                            verifier_result=result,
                            manager_verdict={},
                            recommendations=[],
                            code_context=shared_context[:1000]
                        ))

                    async with completed_lock:
                        completed_groups += 1

                    # 打印组结果
                    fp_count = sum(1 for v in verified_findings if v.verification_status == VerificationStatus.FALSE_POSITIVE)
                    conf_count = len(verified_findings) - fp_count
                    print(f"     ✅ 组 {group_idx + 1} 完成: {fp_count} FP, {conf_count} Confirmed")

                    return verified_findings

                except Exception as e:
                    async with completed_lock:
                        completed_groups += 1
                    print(f"     ⚠️ 组 {group_idx + 1} 失败: {e}")

                    # 返回错误结果
                    return [self._create_error_finding(f, str(e)) for f in group]

        # 创建组验证任务
        tasks = [verify_group(i, group) for i, group in enumerate(groups)]

        # 并行执行
        print(f"  ⚡ 并发验证: {len(groups)} 组, 最大并发 {max_concurrent}")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 收集结果
        for result in results:
            if isinstance(result, Exception):
                print(f"  ⚠️ 组任务异常: {result}")
                continue
            if isinstance(result, list):
                all_verified.extend(result)

        # 统计
        confirmed = sum(1 for v in all_verified if v.verification_status == VerificationStatus.CONFIRMED)
        false_pos = sum(1 for v in all_verified if v.verification_status == VerificationStatus.FALSE_POSITIVE)

        print(f"\n  📊 Phase 3 完成 (分组模式): {len(all_verified)} 验证")
        print(f"     - Confirmed: {confirmed}")
        print(f"     - False Positive: {false_pos}")
        print(f"     - Token 节省: ~{(1 - len(groups) / total) * 100:.0f}% (System prompt)")

        return all_verified

    # ========================================================================
    # 🔥 v2.5.11: Token 优化 - 智能分组 + 共享上下文
    # ========================================================================

    def _group_findings_smart(
        self,
        findings: List[Dict[str, Any]],
        max_per_group: int = 5
    ) -> List[List[Dict[str, Any]]]:
        """
        🔥 v2.5.11: 智能分组漏洞

        分组策略：
        1. 按模块分组（同模块的漏洞共享代码上下文）
        2. 每组最多 max_per_group 个漏洞（避免 prompt 过长）
        3. 保持原始顺序

        Args:
            findings: 漏洞列表
            max_per_group: 每组最大漏洞数

        Returns:
            分组后的漏洞列表，每组是一个 List[Dict]
        """
        from collections import defaultdict

        # 按模块分组
        module_groups = defaultdict(list)
        for finding in findings:
            location = finding.get("location", {})
            module_name = finding.get("_module_name",
                location.get("module", "unknown") if isinstance(location, dict) else "unknown"
            )
            module_groups[module_name].append(finding)

        # 每组最多 max_per_group 个
        result = []
        for module_name, items in module_groups.items():
            for i in range(0, len(items), max_per_group):
                group = items[i:i + max_per_group]
                # 标记模块名
                for f in group:
                    f["_group_module"] = module_name
                result.append(group)

        return result

    def _build_group_context(
        self,
        group: List[Dict[str, Any]]
    ) -> Tuple[str, Dict[str, str]]:
        """
        🔥 v2.5.11: 为一组漏洞预构建共享代码上下文

        优化策略：
        1. 提取该组所有漏洞涉及的函数
        2. 一次性获取所有函数的代码
        3. 构建共享上下文 + 函数代码映射

        Args:
            group: 一组漏洞

        Returns:
            (shared_context, func_code_map)
            - shared_context: 共享的代码上下文字符串
            - func_code_map: {func_name: code} 映射表
        """
        if not self.toolkit:
            return "", {}

        module_name = group[0].get("_group_module", "unknown") if group else "unknown"

        # 收集所有涉及的函数
        functions = set()
        for finding in group:
            location = finding.get("location", {})
            func_name = location.get("function", "") if isinstance(location, dict) else ""
            if func_name and func_name != "unknown":
                functions.add(func_name)

        if not functions:
            return "", {}

        # 批量获取函数代码
        func_code_map = {}
        context_parts = []

        for func_name in functions:
            # 获取函数代码
            func_result = self.toolkit.call_tool("get_function_code", {
                "module": module_name,
                "function": func_name
            }, caller="RoleSwapV2-GroupContext")

            if func_result.success:
                code = func_result.data.get("body", "")
                if code:
                    func_code_map[func_name] = code
                    context_parts.append(f"### {module_name}::{func_name}\n```move\n{code}\n```")

        # 获取调用关系（可选，增加上下文理解）
        if len(functions) <= 3 and self.toolkit:
            for func_name in list(functions)[:2]:  # 最多查 2 个
                callees_result = self.toolkit.call_tool("get_callees", {
                    "module": module_name,
                    "function": func_name,
                    "depth": 1
                }, caller="RoleSwapV2-GroupContext")
                if callees_result.success:
                    callees = callees_result.data.get("callees", [])
                    if callees:
                        callee_names = [c.get("id", c) if isinstance(c, dict) else c for c in callees[:3]]
                        context_parts.append(f"// {func_name} 调用: {', '.join(callee_names)}")

        # 🔥 v2.5.11: 添加调用者签名 (用于判断分层设计)
        # 从 Phase 2 保存的上下文中获取
        caller_parts = []
        for finding in group:
            caller_sigs = finding.get("_caller_signatures", [])
            if caller_sigs:
                func_name = finding.get("location", {}).get("function", "unknown") if isinstance(finding.get("location"), dict) else "unknown"
                caller_parts.append(f"// {func_name} 被以下函数调用 (检查分层设计!):\n" + "\n".join(f"//   {sig}" for sig in caller_sigs[:3]))
        if caller_parts:
            context_parts.append("\n### 调用者签名 (判断分层设计关键!)\n" + "\n".join(caller_parts))

        shared_context = "\n\n".join(context_parts) if context_parts else ""
        return shared_context, func_code_map

    def _collect_group_knowledge(
        self,
        group: List[Dict[str, Any]]
    ) -> str:
        """
        🔥 v2.5.11: 收集一组漏洞的共享安全知识

        优化策略：
        1. 合并所有漏洞匹配的知识（去重）
        2. 添加预判断提示

        Args:
            group: 一组漏洞

        Returns:
            共享的安全知识字符串
        """
        all_knowledge = set()
        fp_hints = []

        for finding in group:
            # 获取针对性知识
            vuln_knowledge = get_relevant_knowledge(finding)
            if vuln_knowledge:
                all_knowledge.add(vuln_knowledge)

            # 🔥 v2.5.13: 优先使用软过滤提示
            finding_id = finding.get("id", finding.get("title", "unknown")[:20])
            soft_filter = finding.get("soft_filter_hint")
            if soft_filter:
                fp_hints.append(f"- 🔶 [{finding_id}] 排除规则 [{soft_filter.get('rule_name', '')}]: {soft_filter.get('reason', '')}")
            elif KNOWLEDGE_AVAILABLE:
                category = finding.get("category", "")
                description = finding.get("description", "")
                is_fp, fp_reason = is_likely_false_positive(category, description)
                if is_fp:
                    fp_hints.append(f"- [{finding_id}] 可能是误报: {fp_reason}")

        result_parts = []
        if all_knowledge:
            result_parts.append("## 🔥 针对性安全知识\n" + "\n\n".join(all_knowledge))
        if fp_hints:
            result_parts.append("## ⚠️ 预判断提示\n" + "\n".join(fp_hints))

        return "\n\n".join(result_parts) if result_parts else ""

    def _determine_final_status(self, conclusion: str) -> VerificationStatus:
        """确定最终验证状态"""
        conclusion = conclusion.lower()

        if conclusion == "confirmed":
            return VerificationStatus.CONFIRMED
        elif conclusion == "false_positive":
            return VerificationStatus.FALSE_POSITIVE
        else:
            return VerificationStatus.NEEDS_REVIEW

    def _create_error_finding(self, finding: Dict[str, Any], error: str) -> VerifiedFinding:
        """创建错误情况下的默认结果"""
        return VerifiedFinding(
            original_finding=finding,
            verification_status=VerificationStatus.NEEDS_REVIEW,
            swap_rounds=[],
            final_severity=finding.get("severity", "medium"),
            final_confidence=0,
            verifier_result={"error": error},
            manager_verdict={},
            recommendations=[f"验证失败: {error}"]
        )

