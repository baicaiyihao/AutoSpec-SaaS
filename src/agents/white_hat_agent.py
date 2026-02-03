"""
White Hat Agent - 白帽黑客角色 Agent

核心职责：
1. 像真正的安全研究员一样思考漏洞利用
2. 分析漏洞的入口点、利用链、攻击影响
3. 过滤掉"理论性漏洞"（无法实际利用的）
4. 生成可验证的漏洞报告

设计理念：
- 如果无法说清楚利用链，就不能确认是真实漏洞
- 利用 RAG 知识库中的真实案例来辅助分析
- 输出必须包含：入口点、攻击路径、前置条件、最终影响
- 最终目标：将"疑似漏洞"转化为"可验证漏洞"或"误报"

工作流程：
    漏洞扫描结果 (SecurityScanner)
            ↓
    WhiteHatAgent.analyze()
            ↓
    ┌───────────────────────────────────┐
    │ 1. RAG检索类似历史漏洞            │
    │ 2. 入口点分析                     │
    │ 3. 利用链构建                     │
    │ 4. 前置条件识别                   │
    │ 5. 影响评估                       │
    │ 6. 可利用性判断                   │
    └───────────────────────────────────┘
            ↓
    漏洞验证报告 (ExploitVerificationReport)
"""

import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from enum import Enum

from src.llm_providers import LLMProviderFactory, LLMConfig, ProviderType
from src.utils.json_parser import robust_parse_json, extract_fields_regex, WHITEHAT_FIELD_PATTERNS
from src.security.exploit_analyzer import (
    ExploitChain, ExploitChainAnalyzer,
    ExploitGoal, ExploitComplexity, ExploitConfidence,
    EntryPoint, AttackStep, Precondition, ExploitImpact
)
from src.prompts.exploit_prompts import (
    WHITE_HAT_VERIFICATION_PROMPT,  # 🔥 统一的工具辅助利用链分析
    build_rag_query,
    format_rag_results,
    get_exploit_hints,
)

# 🔥 v2.5.7: 完全移除安全知识注入
# - Phase 3 (VerifierAgent) 已处理 Move 机制相关的误报过滤
# - RAG 历史漏洞模式通过 _retrieve_similar_cases() 单独检索
# - 删除了 _get_relevant_security_knowledge() 方法
# - 节省 ~5-8K tokens/审计


class VerificationStatus(Enum):
    """漏洞验证状态"""
    VERIFIED = "verified"           # 已验证可利用
    LIKELY = "likely"               # 很可能可利用
    NEEDS_REVIEW = "needs_review"   # 需要人工审查
    THEORETICAL = "theoretical"     # 仅理论上存在
    FALSE_POSITIVE = "false_positive"  # 误报


@dataclass
class ExploitVerificationReport:
    """漏洞验证报告 - GitHub Security Advisory 格式"""
    vulnerability_id: str
    vulnerability_type: str
    severity: str

    # 验证结果
    status: VerificationStatus
    confidence_score: float  # 0-100
    exploitability_score: float  # 0-10

    # === 新增: GitHub Security Advisory 格式字段 ===
    advisory: Dict = field(default_factory=dict)  # title, severity, vulnerability_type, affected_component
    vulnerability_summary: str = ""  # 漏洞摘要
    technical_details: Dict = field(default_factory=dict)  # root_cause, vulnerable_code, vulnerable_function
    attack_scenario: List[str] = field(default_factory=list)  # 攻击步骤列表
    poc_code: str = ""  # PoC 代码
    impact_assessment: Dict = field(default_factory=dict)  # impact_type, affected_users, max_loss, attack_cost, attack_complexity
    recommended_mitigation: List[str] = field(default_factory=list)  # 修复建议
    blocking_factors: List[str] = field(default_factory=list)  # 阻断因素（不可利用时）

    # 利用链分析 (保留兼容)
    entry_point: Optional[Dict] = None
    attack_path: List[Dict] = field(default_factory=list)
    preconditions: List[Dict] = field(default_factory=list)
    impact: Optional[Dict] = None

    # 关键信息
    one_liner_exploit: str = ""  # 一句话描述如何利用
    why_exploitable: str = ""    # 为什么可以利用
    why_not_exploitable: Optional[str] = None  # 为什么不能利用（如果是理论性的）

    # 参考信息
    similar_cases: List[str] = field(default_factory=list)  # 类似的历史案例
    rag_sources: List[str] = field(default_factory=list)    # RAG 检索来源

    # 🔥 新增：完整的 exploit 代码和思路
    exploit_module_code: str = ""   # 完整的 Move exploit 模块代码
    exploit_reasoning: str = ""     # 利用思路（箭头链）

    # 原始数据
    raw_vulnerability: Dict = field(default_factory=dict)
    analysis_reasoning: str = ""   # 分析推理过程

    def to_markdown(self) -> str:
        """生成 Markdown 格式的报告"""
        status_emoji = {
            VerificationStatus.VERIFIED: "🔴",
            VerificationStatus.LIKELY: "🟠",
            VerificationStatus.NEEDS_REVIEW: "🟡",
            VerificationStatus.THEORETICAL: "⚪",
            VerificationStatus.FALSE_POSITIVE: "🟢",
        }

        lines = []
        lines.append(f"## {status_emoji.get(self.status, '❓')} {self.vulnerability_id}")
        lines.append(f"**类型**: {self.vulnerability_type}")
        lines.append(f"**严重性**: {self.severity}")
        lines.append(f"**验证状态**: {self.status.value.upper()}")
        lines.append(f"**可利用性评分**: {self.exploitability_score}/10")
        lines.append(f"**置信度**: {self.confidence_score}%")
        lines.append("")

        # 一句话利用方式
        lines.append("### 利用方式")
        lines.append(f"> {self.one_liner_exploit}")
        lines.append("")

        # 为什么可以/不能利用
        if self.status in [VerificationStatus.VERIFIED, VerificationStatus.LIKELY]:
            lines.append("### 为什么可以利用")
            lines.append(self.why_exploitable)
        elif self.why_not_exploitable:
            lines.append("### 为什么无法确认利用")
            lines.append(self.why_not_exploitable)
        lines.append("")

        # 入口点
        if self.entry_point:
            lines.append("### 入口点")
            lines.append(f"- **函数**: `{self.entry_point.get('function', 'Unknown')}`")
            lines.append(f"- **可见性**: {self.entry_point.get('visibility', 'Unknown')}")
            lines.append(f"- **调用者要求**: {self.entry_point.get('caller_requirement', 'Unknown')}")
            lines.append("")

        # 攻击路径
        if self.attack_path:
            lines.append("### 攻击路径")
            for step in self.attack_path:
                step_num = step.get('step', step.get('step_number', '?'))
                lines.append(f"**Step {step_num}**: {step.get('action', '')}")
                if step.get('function_call'):
                    lines.append(f"  - 调用: `{step['function_call']}`")
                if step.get('purpose'):
                    lines.append(f"  - 目的: {step['purpose']}")
                if step.get('state_change'):
                    lines.append(f"  - 状态变化: {step['state_change']}")
            lines.append("")

        # 前置条件
        if self.preconditions:
            lines.append("### 前置条件")
            for pre in self.preconditions:
                difficulty = pre.get('difficulty', 'unknown')
                realistic = "✅" if pre.get('realistic', False) else "⚠️"
                lines.append(f"- {pre.get('condition', '')}")
                lines.append(f"  - 达成方式: {pre.get('how_to_achieve', '')}")
                lines.append(f"  - 难度: {difficulty} {realistic}")
            lines.append("")

        # 影响
        if self.impact:
            lines.append("### 攻击影响")
            lines.append(f"- **目标**: {self.impact.get('goal', 'Unknown')}")
            lines.append(f"- **描述**: {self.impact.get('description', '')}")
            if self.impact.get('affected_parties'):
                lines.append(f"- **受影响方**: {', '.join(self.impact['affected_parties'])}")
            lines.append(f"- **最大损失**: {self.impact.get('max_loss', 'Unknown')}")
            lines.append("")

        # 🔥 利用思路
        if self.exploit_reasoning:
            lines.append("### 利用思路")
            lines.append(f"> {self.exploit_reasoning}")
            lines.append("")

        # 🔥 完整 Exploit 代码
        if self.exploit_module_code:
            lines.append("### Exploit 代码 (PoC)")
            lines.append("```move")
            lines.append(self.exploit_module_code)
            lines.append("```")
            lines.append("")

        # 类似案例
        if self.similar_cases:
            lines.append("### 类似历史案例")
            for case in self.similar_cases[:5]:
                lines.append(f"- {case}")
            lines.append("")

        return "\n".join(lines)


class WhiteHatAgent:
    """
    白帽黑客 Agent

    以安全研究员的视角分析漏洞，验证漏洞的真实性和可利用性。

    核心能力：
    1. 入口点发现 - 找到能够触发漏洞的 public/entry 函数
    2. 利用链构建 - 从入口到漏洞触发的完整路径
    3. 前置条件识别 - 利用需要满足什么条件
    4. 影响评估 - 攻击成功后能达成什么目的
    5. 可利用性判断 - 综合评估是否是真实漏洞

    🔥 支持工具辅助验证模式:
    当 use_tools=True 时，AI 可自主调用工具查看代码来验证漏洞。

    Prompt 定义在: src/prompts/exploit_prompts.py
    - WHITE_HAT_VERIFICATION_PROMPT: 统一的工具辅助利用链分析
    """

    def __init__(self, rag_retriever=None, config=None, use_tools: bool = False):
        """
        Args:
            rag_retriever: RAG 检索器，用于查询历史漏洞案例
            config: AgentConfig 配置 (可选)，如果不传则使用默认配置
            use_tools: 是否启用工具辅助验证模式
        """
        import threading
        self.rag_retriever = rag_retriever
        self.config = config
        self.use_tools = use_tools  # 🔥 工具辅助验证模式

        # 根据配置初始化 LLM (config 由 engine.py 从 PRESET 传入)
        self.llm = self._init_llm_from_config(config)

        # 🔥 LLM 调用锁 - 防止同一实例并发调用 (线程锁，因为 verify_vulnerability 是同步方法)
        self._llm_lock = threading.Lock()

        self.exploit_analyzer = ExploitChainAnalyzer(
            rag_retriever=rag_retriever,
            llm_client=None  # 我们在这个 agent 中直接使用 LLM
        )

        # 🔥 工具箱 (用于自主检索代码上下文)
        self.toolkit = None

        # 🔥 v2.5.8: Token 使用量统计
        self._token_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "call_count": 0
        }

        provider = config.provider if config else "deepseek"
        model = config.model if config else "deepseek-chat"
        tools_info = " [工具辅助模式]" if use_tools else ""
        print(f"🎩 [WhiteHatAgent] 白帽黑客模式已启动 (using {provider}/{model}){tools_info}")

    def set_toolkit(self, toolkit):
        """
        设置工具箱，让 Agent 能够自主检索代码

        Args:
            toolkit: AgentToolkit 实例
        """
        self.toolkit = toolkit

    def _track_token_usage(self, usage: Dict[str, int]):
        """🔥 v2.5.8: 累加 token 使用量"""
        if usage:
            self._token_usage["prompt_tokens"] += usage.get("prompt_tokens", 0)
            self._token_usage["completion_tokens"] += usage.get("completion_tokens", 0)
            self._token_usage["total_tokens"] += usage.get("total_tokens", 0)
            self._token_usage["call_count"] += 1

    def get_token_usage(self) -> Dict[str, int]:
        """🔥 v2.5.8: 获取 token 使用量统计"""
        return self._token_usage.copy()

    def reset_token_usage(self):
        """🔥 v2.5.8: 重置 token 使用量统计"""
        self._token_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "call_count": 0
        }

    # 🔥 v2.5.7: 移除 _get_relevant_security_knowledge() 方法
    # Phase 3 (VerifierAgent) 已经处理了 Move 机制相关的误报过滤
    # RAG 历史漏洞模式通过 _retrieve_similar_cases() 单独检索
    # 这样可以节省 ~5-8K tokens/审计

    def retrieve_context_for_finding(self, finding: Dict) -> Dict:
        """
        🔥 根据 finding 的 location 自动检索相关代码上下文

        Args:
            finding: 漏洞发现，需包含 location: {module, function}

        Returns:
            检索到的代码上下文
        """
        import re

        if not self.toolkit:
            return {"error": "No toolkit available", "context_summary": ""}

        location = finding.get("location", {})
        module = location.get("module", "")
        function = location.get("function", "")

        if not module or not function:
            # 尝试从 title 或 description 提取
            title = finding.get("title", "")
            desc = finding.get("description", "")
            match = re.search(r'(\w+)::(\w+)', f"{title} {desc}")
            if match:
                module, function = match.groups()

        if not function:
            return {"error": "Cannot determine function location", "context_summary": ""}

        context_parts = []
        result = {"target_function": None, "callers": [], "callees": [], "context_summary": ""}
        caller_tag = "WhiteHat"

        # 1. 获取目标函数代码
        func_result = self.toolkit.call_tool("get_function_code", {"module": module, "function": function}, caller=caller_tag)
        if func_result.success:
            result["target_function"] = func_result.data
            body = func_result.data.get("body", "")
            context_parts.append(f"## 目标函数: {module}::{function}\n```move\n{body}\n```")

        # 2. 获取调用者
        callers_result = self.toolkit.call_tool("get_callers", {"module": module, "function": function, "depth": 2}, caller=caller_tag)
        if callers_result.success:
            callers = callers_result.data.get("callers", [])
            result["callers"] = callers
            if callers:
                caller_names = [c.get("id", "?") for c in callers[:5]]
                context_parts.append(f"## 调用者\n" + "\n".join(f"- {n}" for n in caller_names))

        # 3. 获取被调用者
        callees_result = self.toolkit.call_tool("get_callees", {"module": module, "function": function, "depth": 2}, caller=caller_tag)
        if callees_result.success:
            callees = callees_result.data.get("callees", [])
            result["callees"] = callees
            if callees:
                callee_names = [c.get("id", "?") for c in callees[:5]]
                context_parts.append(f"## 被调用者\n" + "\n".join(f"- {n}" for n in callee_names))

        # 4. 获取函数功能描述
        purpose_result = self.toolkit.call_tool("get_function_purpose", {"function_id": function}, caller=caller_tag)
        if purpose_result.success:
            purpose = purpose_result.data.get("purpose", "")
            context_parts.append(f"## 函数功能\n{purpose}")

        # 5. 获取相关分析提示
        hints_result = self.toolkit.call_tool("get_analysis_hints", {"hint_type": "all"}, caller=caller_tag)
        if hints_result.success:
            hints = hints_result.data
            if hints.get("analysis_summary"):
                context_parts.append(f"## 合约分析摘要\n{hints['analysis_summary']}")

        result["context_summary"] = "\n\n".join(context_parts)
        return result

    def _init_llm_from_config(self, config):
        """根据 AgentConfig 初始化 LLM"""
        provider_type = ProviderType(config.provider.lower())
        llm_config = LLMConfig(
            provider=provider_type,
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            timeout=getattr(config, 'timeout', 120)
        )
        return LLMProviderFactory.create(llm_config)

    def verify_vulnerability(
        self,
        vulnerability: Dict,
        source_code: str = "",
        context: Optional[Dict] = None
    ) -> ExploitVerificationReport:
        """
        验证单个漏洞的真实性

        🔥 v2.5.3: 只处理 HIGH/CRITICAL 严重性的漏洞
        MEDIUM/LOW/ADVISORY 级别直接跳过，减少 token 消耗

        Args:
            vulnerability: 漏洞扫描结果
            source_code: 相关源代码（如果有 toolkit 则可选）
            context: 额外上下文（模块信息、ABI 等）

        Returns:
            ExploitVerificationReport: 漏洞验证报告
        """
        vuln_id = vulnerability.get("id", vulnerability.get("pattern_id", "UNKNOWN"))
        vuln_type = vulnerability.get("category", vulnerability.get("issue_tags", ["unknown"])[0] if vulnerability.get("issue_tags") else "unknown")
        severity = vulnerability.get("severity", "medium").lower()

        # 🔥 v2.5.3: 只处理 HIGH/CRITICAL 漏洞
        if severity not in ["high", "critical"]:
            print(f"⏭️ [WhiteHatAgent] 跳过 {vuln_id} (严重性: {severity}, 只处理 HIGH/CRITICAL)")
            return ExploitVerificationReport(
                vulnerability_id=vuln_id,
                vulnerability_type=vuln_type,
                severity=severity,
                status=VerificationStatus.NEEDS_REVIEW,
                confidence_score=0,
                exploitability_score=0,
                one_liner_exploit="",
                why_exploitable="",
                why_not_exploitable=f"已跳过: 严重性为 {severity}，WhiteHat 只分析 HIGH/CRITICAL 漏洞",
                raw_vulnerability=vulnerability,
                analysis_reasoning=f"v2.5.3: 优化 token 消耗，只对 HIGH/CRITICAL 进行利用链分析"
            )

        print(f"🔍 [WhiteHatAgent] 分析漏洞: {vuln_id} ({vuln_type})")

        # 🔥 优先使用 toolkit 检索相关代码，避免传入整个代码库
        if self.toolkit and not source_code:
            retrieved = self.retrieve_context_for_finding(vulnerability)
            if retrieved.get("context_summary"):
                source_code = retrieved["context_summary"]
                print(f"  📚 使用工具检索了相关代码 (目标函数 + 调用链)")
            else:
                print(f"  ⚠️ 工具检索失败: {retrieved.get('error', 'unknown')}")

        # Step 1: RAG 检索类似案例
        similar_cases = self._retrieve_similar_cases(vulnerability)
        rag_context = format_rag_results(similar_cases)

        # Step 2: 获取漏洞类型对应的利用提示
        exploit_hints = get_exploit_hints(vuln_type)

        # Step 3: 调用 LLM 进行完整的利用链分析
        # 🔥 如果启用工具辅助模式且有 toolkit，使用工具辅助分析
        if self.use_tools and self.toolkit:
            print(f"  🔧 使用工具辅助模式分析漏洞...")
            analysis_result = self._analyze_with_tools(
                vulnerability=vulnerability,
                source_code=source_code,  # 🔥 传入预构建的代码上下文
                rag_context=rag_context,
                exploit_hints=exploit_hints,
                context=context
            )
        else:
            analysis_result = self._analyze_with_llm(
                vulnerability=vulnerability,
                source_code=source_code,
                rag_context=rag_context,
                exploit_hints=exploit_hints,
                context=context
            )

        # Step 4: 解析 LLM 响应
        parsed = self._parse_analysis_result(analysis_result)

        # Step 5: 确定验证状态
        status = self._determine_status(parsed)

        # Step 6: 构建报告 (支持新的漏洞验证格式)

        # 从 exploit_analysis 或旧格式获取 entry_point
        exploit_analysis = parsed.get("exploit_analysis", {})
        entry_point = parsed.get("entry_point") or {
            "function": exploit_analysis.get("entry_function", ""),
            "visibility": exploit_analysis.get("entry_visibility", ""),
            "required_objects": exploit_analysis.get("required_objects", []),
            "required_capabilities": exploit_analysis.get("required_capabilities", ""),
            "attack_type": exploit_analysis.get("attack_type", "")
        } if exploit_analysis else None

        # 从 exploit_attempt 获取失败原因（如果不可利用）
        exploit_attempt = parsed.get("exploit_attempt", {})
        why_not = parsed.get("why_not_exploitable") or parsed.get("reason")
        if not why_not and exploit_attempt:
            why_not = f"尝试了 {exploit_attempt.get('what_i_tried', '?')}，在 {exploit_attempt.get('where_it_failed', '?')} 失败"

        return ExploitVerificationReport(
            vulnerability_id=vuln_id,
            vulnerability_type=vuln_type,
            severity=severity,
            status=status,
            confidence_score=parsed.get("confidence", 50),
            exploitability_score=parsed.get("exploitability_score", 5.0),

            # 安全公告格式字段
            advisory=parsed.get("advisory", {}),
            vulnerability_summary=parsed.get("vulnerability_summary", ""),
            technical_details=parsed.get("technical_details", {}),
            attack_scenario=parsed.get("attack_scenario", []),
            poc_code=parsed.get("poc_code", ""),
            impact_assessment=parsed.get("impact_assessment", {}),
            recommended_mitigation=parsed.get("recommended_mitigation", []),
            blocking_factors=parsed.get("blocking_factors", []),

            # 利用链分析
            entry_point=entry_point,
            attack_path=parsed.get("attack_path", []),
            preconditions=parsed.get("preconditions", []),
            impact=parsed.get("impact") or parsed.get("impact_assessment"),

            # 结论
            one_liner_exploit=parsed.get("vulnerability_summary", "")[:200] if parsed.get("vulnerability_summary") else "",
            why_exploitable=parsed.get("vulnerability_summary", ""),
            why_not_exploitable=why_not,

            # 🔥 完整的 exploit 代码和思路
            exploit_module_code=self._format_exploit_code(parsed.get("poc_code", "")),
            exploit_reasoning=parsed.get("exploit_reasoning", ""),

            # 参考
            similar_cases=[c.get("title", c.get("id", "")) for c in similar_cases[:5]],
            rag_sources=[c.get("id", "") for c in similar_cases[:5]],
            raw_vulnerability=vulnerability,
            analysis_reasoning=parsed.get("reasoning", analysis_result)
        )

    def verify_all(
        self,
        vulnerabilities: List[Dict],
        source_code: str,
        context: Optional[Dict] = None
    ) -> Dict[str, List[ExploitVerificationReport]]:
        """
        批量验证漏洞

        Args:
            vulnerabilities: 漏洞列表
            source_code: 源代码
            context: 上下文

        Returns:
            按状态分组的验证报告
        """
        results = {
            "verified": [],      # 已验证可利用
            "likely": [],        # 很可能可利用
            "needs_review": [],  # 需要审查
            "theoretical": [],   # 理论性
            "false_positive": [] # 误报
        }

        print(f"🎩 [WhiteHatAgent] 开始验证 {len(vulnerabilities)} 个漏洞...")

        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_id = vuln.get("id", vuln.get("pattern_id", f"VULN-{i}"))
            print(f"\n[{i}/{len(vulnerabilities)}] 验证: {vuln_id}")

            report = self.verify_vulnerability(vuln, source_code, context)

            # 按状态分类
            status_key = report.status.value
            if status_key in results:
                results[status_key].append(report)
            else:
                results["needs_review"].append(report)

            # 显示结果摘要
            status_emoji = {
                VerificationStatus.VERIFIED: "🔴 已验证",
                VerificationStatus.LIKELY: "🟠 很可能",
                VerificationStatus.NEEDS_REVIEW: "🟡 需审查",
                VerificationStatus.THEORETICAL: "⚪ 理论性",
                VerificationStatus.FALSE_POSITIVE: "🟢 误报",
            }
            print(f"   → {status_emoji.get(report.status, '❓')} | 可利用性: {report.exploitability_score}/10")

        # 打印统计
        print(f"\n{'='*50}")
        print("📊 验证统计:")
        print(f"   🔴 已验证漏洞: {len(results['verified'])}")
        print(f"   🟠 很可能漏洞: {len(results['likely'])}")
        print(f"   🟡 需要审查: {len(results['needs_review'])}")
        print(f"   ⚪ 理论性漏洞: {len(results['theoretical'])}")
        print(f"   🟢 误报: {len(results['false_positive'])}")
        print(f"{'='*50}")

        return results

    def _retrieve_similar_cases(self, vulnerability: Dict) -> List[Dict]:
        """从 RAG 检索类似的历史漏洞案例"""
        if not self.rag_retriever:
            return []

        try:
            query = build_rag_query(vulnerability)
            results = self.rag_retriever.search(query=query, top_k=10)
            return results
        except Exception as e:
            print(f"   ⚠️ RAG 检索失败: {e}")
            return []

    def _analyze_with_llm(
        self,
        vulnerability: Dict,
        source_code: str,
        rag_context: str,
        exploit_hints: Dict,
        context: Optional[Dict]
    ) -> str:
        """使用 LLM 进行利用链分析"""

        # 准备漏洞信息
        vuln_id = vulnerability.get("id", vulnerability.get("pattern_id", "UNKNOWN"))
        vuln_type = vulnerability.get("category", "unknown")
        severity = vulnerability.get("severity", "medium")
        location = vulnerability.get("location", {})
        description = vulnerability.get("description", vulnerability.get("recommendation", ""))

        # 构建位置字符串
        location_str = ""
        if isinstance(location, dict):
            location_str = f"{location.get('module', 'unknown')}::{location.get('function', 'unknown')}"
        elif isinstance(location, str):
            location_str = location
        else:
            location_str = str(location)

        # 🔥 v2.5.7: 移除安全知识注入，Phase 3 已处理机制过滤
        # RAG 历史漏洞案例通过 rag_context 参数传入

        # 构建分析提示词 (漏洞信息 + 代码 + 统一的验证指南)
        prompt = f"""
## 前面Agent发现的潜在漏洞

**ID**: {vuln_id}
**类型**: {vuln_type}
**严重性**: {severity}
**位置**: {location_str}
**描述**: {description}

## 目标合约源代码

```move
{source_code[:6000]}
```

## 类似漏洞的历史案例

{rag_context}

{WHITE_HAT_VERIFICATION_PROMPT}
"""

        # 添加利用提示
        if exploit_hints:
            prompt += f"""

## 该漏洞类型的常见利用模式

- **典型入口**: {exploit_hints.get('typical_entry', 'unknown')}
- **攻击方式**: {exploit_hints.get('attack_hint', '')}
- **前置条件**: {exploit_hints.get('precondition_hint', '')}
- **预期影响**: {exploit_hints.get('impact_hint', '')}
"""

        # 带重试的 LLM 调用 (处理 429 rate limit)
        # 🔥 增强重试: 更多次数 + 更长退避 + 随机抖动
        import random
        max_retries = 5  # 至少5次重试
        base_delay = 3.0  # 基础延迟3秒
        max_delay = 30.0  # 最大延迟30秒

        for attempt in range(max_retries):
            try:
                # 🔥 使用锁序列化同一实例的 LLM 调用，避免并发踩踏
                with self._llm_lock:
                    # 参照 BaseAgent.call_llm() 实现
                    # 判断是使用 Provider (.chat) 还是 LangChain (.invoke)
                    if hasattr(self.llm, 'chat'):
                        # 使用 LLMProvider (新系统)
                        messages = [
                            {"role": "system", "content": "你是一位专业的白帽黑客，擅长分析智能合约漏洞的可利用性。"},
                            {"role": "user", "content": prompt}
                        ]
                        response = self.llm.chat(messages)
                        # 🔥 v2.5.8: 追踪 token 使用量
                        if hasattr(response, 'usage') and response.usage:
                            self._track_token_usage(response.usage)
                        content = response.content
                    else:
                        # 使用 LangChain (传统方式)
                        response = self.llm.invoke(prompt)
                        content = response.content if hasattr(response, 'content') else str(response)
                return content
            except Exception as e:
                error_str = str(e)
                # 检查是否是 429 rate limit 错误
                if "429" in error_str or "rate" in error_str.lower() or "1302" in error_str:
                    if attempt < max_retries - 1:
                        # 🔥 指数退避 + 随机抖动 (避免多Agent同时重试)
                        delay = min(base_delay * (2 ** attempt), max_delay)
                        jitter = random.uniform(0.5, 1.5)  # 0.5x ~ 1.5x 随机因子
                        actual_delay = delay * jitter
                        print(f"   ⏳ API 限流，{actual_delay:.1f}s 后重试 ({attempt + 1}/{max_retries})...")
                        time.sleep(actual_delay)
                        continue

                print(f"   ⚠️ LLM 分析失败: {e}")
                return json.dumps({
                    "is_exploitable": False,
                    "confidence": "low",
                    "exploitability_score": 2,
                    "reason": f"LLM 分析失败: {str(e)[:100]}"
                })

        # 所有重试都失败
        return json.dumps({
            "is_exploitable": False,
            "confidence": "low",
            "exploitability_score": 2,
            "reason": "API 限流，所有重试均失败"
        })

    def _run_lightweight_verification(
        self,
        vuln_id: str,
        minimal_prompt: str,
        tools: list,
        max_rounds: int = 5
    ) -> str:
        """
        🔥 轻量级子 Agent：独立会话 + 独立 LLM 实例

        核心优化 (v2.4.8):
        1. 每次验证使用全新的消息列表，不带主 Agent 的历史上下文
        2. 创建独立的 LLM 实例，不共享主 Agent 的锁 → 支持并行执行
        3. 只传递必要信息：漏洞描述 + 预构建代码 + 函数索引
        4. 工具调用在隔离环境中完成，结果返回给主流程

        这相当于 "真正的子 Agent"：
        - 主 Agent: 保持完整上下文，负责协调
        - 子 Agent: 独立 LLM + 最小上下文，专注于单个漏洞验证

        Args:
            vuln_id: 漏洞 ID（用于日志）
            minimal_prompt: 精简的验证 prompt（只含必要信息）
            tools: 可用工具列表
            max_rounds: 最大工具调用轮次

        Returns:
            LLM 的最终分析结果（JSON 字符串）
        """
        import random
        import time

        # 🔥 v2.4.8: 创建独立的 LLM 实例，不共享主 Agent 的锁
        # 这是实现真正并行执行的关键
        sub_agent_llm = self._init_llm_from_config(self.config)

        # 🔥 轻量级系统 prompt（比主 Agent 短得多）
        system_prompt = """你是白帽安全验证子程序，专注于验证单个漏洞。

工作原则：
1. 直接分析提供的代码，高效使用工具
2. 每轮最多调用 2 个工具
3. 收集足够信息后立即输出 JSON 结果
4. 不要重复获取相同信息
5. **所有输出必须使用中文！**

输出格式（所有字段必须用中文）：
{
  "is_exploitable": true/false,
  "exploitability_score": 0-10,
  "confidence": "low/medium/high",
  "exploit_summary": "一句话利用方法（中文）",
  "attack_steps": ["步骤1（中文）", "步骤2（中文）"],
  "poc_code": "exploit 代码",
  "blocking_factors": ["阻断因素（中文，如果不可利用）"]
}"""

        # 🔥 创建全新的消息列表（不带任何历史上下文）
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": minimal_prompt}
        ]

        # 工具调用去重
        called_tools: set = set()

        def get_tool_key(name: str, args: dict) -> str:
            import json as _json
            return f"{name}:{_json.dumps(args, sort_keys=True, ensure_ascii=False)}"

        # 🔥 轻量级工具调用循环（使用独立 LLM，无锁）
        for round_num in range(max_rounds):
            try:
                # 🔥 不需要锁，因为是独立的 LLM 实例
                response = sub_agent_llm.chat(messages, tools=tools)
                # 🔥 v2.5.8: 追踪子 Agent token 使用量
                if hasattr(response, 'usage') and response.usage:
                    self._track_token_usage(response.usage)
            except Exception as e:
                error_str = str(e)
                if "429" in error_str or "rate" in error_str.lower():
                    delay = 2.0 * (2 ** round_num) * random.uniform(0.5, 1.5)
                    print(f"      ⏳ [{vuln_id}] API 限流，{delay:.1f}s 后重试...")
                    time.sleep(delay)
                    continue
                return json.dumps({
                    "is_exploitable": False,
                    "confidence": "low",
                    "reason": f"子 Agent 调用失败: {str(e)[:100]}"
                })

            # 检查是否完成（无工具调用）
            if response.finish_reason != "tool_calls" or not response.tool_calls:
                if round_num > 0:
                    print(f"      ✓ [{vuln_id}] 子 Agent 完成 (共 {round_num + 1} 轮, {len(called_tools)} 次工具调用)")
                return response.content or ""

            # 过滤重复工具调用
            unique_calls = []
            for tc in response.tool_calls:
                tool_key = get_tool_key(tc.name, tc.arguments)
                if tool_key not in called_tools:
                    called_tools.add(tool_key)
                    unique_calls.append(tc)

            if not unique_calls:
                # 所有调用都重复，强制输出
                messages.append({
                    "role": "user",
                    "content": "所有请求的工具已执行过。请立即输出 JSON 分析结果。"
                })
                try:
                    final_resp = sub_agent_llm.chat(messages)
                    # 🔥 v2.5.8: 追踪子 Agent token 使用量
                    if hasattr(final_resp, 'usage') and final_resp.usage:
                        self._track_token_usage(final_resp.usage)
                    return final_resp.content or ""
                except:
                    break

            # 记录工具调用
            messages.append({
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [{"id": tc.id, "name": tc.name, "args": tc.arguments} for tc in unique_calls]
            })

            # 执行工具
            for tc in unique_calls:
                args_summary = tc.arguments.get("function", tc.arguments.get("type_name", "?"))
                result = self.toolkit.call_tool(tc.name, tc.arguments, caller=f"SubAgent-{vuln_id}")
                tool_output = json.dumps(result.data, ensure_ascii=False)[:2000] if result.success else f"Error: {result.error}"
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": tool_output})
                print(f"      🔧 [{vuln_id}] {tc.name}({args_summary})")

        # 最大轮次耗尽
        messages.append({"role": "user", "content": "请立即输出 JSON 分析结果，不再调用工具。"})
        try:
            final_resp = sub_agent_llm.chat(messages)
            # 🔥 v2.5.8: 追踪子 Agent token 使用量
            if hasattr(final_resp, 'usage') and final_resp.usage:
                self._track_token_usage(final_resp.usage)
            return final_resp.content or ""
        except:
            return json.dumps({"is_exploitable": False, "confidence": "low", "reason": "子 Agent 轮次耗尽"})

    def _analyze_with_tools(
        self,
        vulnerability: Dict,
        source_code: str,  # 🔥 添加：预构建的代码上下文
        rag_context: str,
        exploit_hints: Dict,
        context: Optional[Dict]
    ) -> str:
        """
        🔥 使用工具辅助分析漏洞 (子 Agent 委托模式)

        核心改进 (v2.4.7):
        1. 预构建的代码上下文直接给 LLM
        2. 委托给轻量级子 Agent 执行工具调用
        3. 子 Agent 使用最小上下文，避免上下文膨胀
        """
        if not self.toolkit:
            print("   ⚠️ 工具辅助模式需要 toolkit，回退到普通分析")
            return self._analyze_with_llm(vulnerability, source_code, rag_context, exploit_hints, context)

        # 获取函数索引和分析上下文
        function_index = self.toolkit.get_function_index()
        analysis_context = self.toolkit.get_analysis_context()

        # 准备漏洞信息
        vuln_id = vulnerability.get("id", vulnerability.get("pattern_id", "UNKNOWN"))
        vuln_type = vulnerability.get("category", "unknown")
        severity = vulnerability.get("severity", "medium")
        location = vulnerability.get("location", {})
        description = vulnerability.get("description", vulnerability.get("recommendation", ""))

        # 构建位置字符串
        location_str = ""
        if isinstance(location, dict):
            location_str = f"{location.get('module', 'unknown')}::{location.get('function', 'unknown')}"
        elif isinstance(location, str):
            location_str = location
        else:
            location_str = str(location)

        # 🔥 判断是否有预构建的代码上下文
        has_prebuilt_context = bool(source_code and len(source_code.strip()) > 100)

        # 显示预构建上下文状态
        if has_prebuilt_context:
            # 🔥 检查是否来自 Phase 3
            context_type = context.get("context_type", "") if context else ""
            if context_type == "phase3_inherited":
                print(f"       → Phase 3 上下文: {len(source_code)} 字符 (继承)")
            else:
                print(f"       → 预构建上下文: {len(source_code)} 字符")
        else:
            print(f"       → 无预构建上下文，将使用工具获取代码")

        # 🔥 显示 Phase 3 分析结果状态
        phase3_ctx = context.get("phase3_analysis", {}) if context else {}
        if phase3_ctx:
            p3_status = phase3_ctx.get("verification_status", "")
            p3_conf = phase3_ctx.get("final_confidence", 0)
            print(f"       → Phase 3 验证: {p3_status} ({p3_conf}% 置信度)")

        # 🔥 提取 Phase 3 分析结果
        phase3_analysis = context.get("phase3_analysis", {}) if context else {}
        phase3_section = ""
        if phase3_analysis:
            expert_review = phase3_analysis.get("expert_review", {})
            analyst_assessment = phase3_analysis.get("analyst_assessment", {})
            verification_reasoning = phase3_analysis.get("verification_reasoning", [])

            # 构建 Phase 3 分析摘要
            phase3_lines = ["## 📋 Phase 3 多Agent验证结果 (已完成)"]
            phase3_lines.append(f"- 验证状态: {phase3_analysis.get('verification_status', 'unknown')}")
            phase3_lines.append(f"- 置信度: {phase3_analysis.get('final_confidence', 0)}%")

            # Expert 分析
            if expert_review:
                expert_status = expert_review.get("verification", {}).get("status", "")
                expert_reasoning = expert_review.get("verification", {}).get("reasoning", "")[:300]
                if expert_status:
                    phase3_lines.append(f"\n### Expert 技术分析:")
                    phase3_lines.append(f"- 结论: {expert_status}")
                    if expert_reasoning:
                        phase3_lines.append(f"- 推理: {expert_reasoning}")

            # Analyst 分析
            if analyst_assessment:
                priority = analyst_assessment.get("mitigation_priority", "")
                attack_scenario = analyst_assessment.get("attack_scenario", "")[:300]
                if priority:
                    phase3_lines.append(f"\n### Analyst 业务影响:")
                    phase3_lines.append(f"- 优先级: {priority}")
                    if attack_scenario:
                        phase3_lines.append(f"- 攻击场景: {attack_scenario}")

            # 各轮次推理
            if verification_reasoning:
                phase3_lines.append(f"\n### 验证轮次摘要:")
                for r in verification_reasoning:
                    phase3_lines.append(f"- [{r['agent']}] {r['verdict']} ({r['confidence']}%)")

            phase3_section = "\n".join(phase3_lines)

        # 🔥 v2.5.7: 移除安全知识注入，Phase 3 已处理机制过滤
        # RAG 历史漏洞案例通过 rag_context 参数传入

        # 构建工具辅助分析 prompt
        prompt = f"""
## 漏洞信息
- ID: {vuln_id}
- 类型: {vuln_type}
- 严重性: {severity}
- 位置: {location_str}
- 描述: {description}

{phase3_section}

## 🔥 预构建的代码上下文 (来自Phase 3分析)
{"```move" + chr(10) + source_code[:8000] + chr(10) + "```" if has_prebuilt_context else "无预构建上下文"}

## 📝 工具使用指南
{"上面已经提供了漏洞函数及其调用链的代码（与Phase 3相同）。请优先基于这些代码进行利用链分析。" if has_prebuilt_context else "请使用工具获取代码进行分析。"}
- **只有在以下情况才需要调用工具**：
  1. 需要查看跨模块的函数实现
  2. 需要获取类型定义 (struct abilities)
  3. 需要追踪更深的调用链
- **效率要求**：每轮最多调用 2 个工具，避免重复调用
- **重点**：Phase 3 已确认漏洞存在，你的任务是分析如何利用它

## 可用函数索引 (用于工具调用)
{function_index}

## 类似漏洞案例 (RAG)
{rag_context}

{WHITE_HAT_VERIFICATION_PROMPT}
"""

        # 添加利用提示
        if exploit_hints:
            prompt += f"""
## 该漏洞类型的常见利用模式
- **典型入口**: {exploit_hints.get('typical_entry', 'unknown')}
- **攻击方式**: {exploit_hints.get('attack_hint', '')}
- **前置条件**: {exploit_hints.get('precondition_hint', '')}
- **预期影响**: {exploit_hints.get('impact_hint', '')}
"""

        # 获取安全工具
        tools = self.toolkit.get_security_tools()

        # ============================================================
        # 🔥 v2.4.7: 子 Agent 委托模式
        # 将工具调用循环委托给轻量级子 Agent，避免上下文膨胀
        # ============================================================

        # 🔥 构建精简的子 Agent prompt（只含必要信息）
        minimal_prompt = f"""## 漏洞验证任务

**漏洞信息**:
- ID: {vuln_id}
- 类型: {vuln_type}
- 严重性: {severity}
- 位置: {location_str}
- 描述: {description[:500]}

**Phase 3 分析结论**: {phase3_ctx.get('verification_status', 'unknown')} ({phase3_ctx.get('final_confidence', 0)}% 置信度)

**代码上下文**:
```move
{source_code[:6000] if has_prebuilt_context else "请使用工具获取代码"}
```

**可用函数**: {function_index[:1500]}

**任务**: 验证此漏洞是否可被利用，构建完整的 exploit。如果代码已足够分析，直接输出结论；如需更多代码，使用工具获取。"""

        # 添加 RAG 上下文（精简版）
        if rag_context and len(rag_context) > 50:
            minimal_prompt += f"\n\n**类似漏洞案例**: {rag_context[:800]}"

        # 添加利用提示
        if exploit_hints:
            minimal_prompt += f"""

**利用提示**:
- 入口: {exploit_hints.get('typical_entry', 'unknown')}
- 攻击方式: {exploit_hints.get('attack_hint', '')[:200]}"""

        print(f"   🚀 [{vuln_id}] 委托给子 Agent (上下文: {len(minimal_prompt)} 字符)")

        # 🔥 委托给轻量级子 Agent 执行
        result = self._run_lightweight_verification(
            vuln_id=vuln_id,
            minimal_prompt=minimal_prompt,
            tools=tools,
            max_rounds=5
        )

        # 如果子 Agent 成功返回结果，直接使用
        if result and len(result.strip()) > 10:
            return result

        # 子 Agent 失败，回退到直接分析
        print(f"   ⚠️ [{vuln_id}] 子 Agent 未返回有效结果，回退到直接分析")
        return self._analyze_with_llm(vulnerability, source_code, rag_context, exploit_hints, context)

    # 注: 旧版 _analyze_with_tools_legacy 已移除 (v2.4.7)
    # 如需参考旧实现，请查看 git 历史记录

    def _parse_analysis_result(self, result: str) -> Dict:
        """解析 LLM 分析结果 - 使用 json_parser 工具模块的 9 种策略"""
        # 🔥 使用工具模块的健壮 JSON 解析器
        parsed = robust_parse_json(result, verbose=True)

        # 检查是否解析成功
        if "error" not in parsed:
            return parsed

        # 9 种策略都失败了，尝试 WhiteHat 专用的字段提取
        print(f"   ⚠️ 9 种策略失败，尝试 WhiteHat 字段提取...")
        extracted = extract_fields_regex(result, WHITEHAT_FIELD_PATTERNS)

        if extracted.get("is_exploitable") is not None:
            return {
                "is_exploitable": extracted.get("is_exploitable", False),
                "confidence": extracted.get("confidence", "medium"),
                "exploitability_score": extracted.get("exploitability_score", 5),
                "exploit_reasoning": extracted.get("exploit_reasoning", ""),
                "reason": "WhiteHat 字段提取成功",
                "_partial_parse": True
            }

        print(f"   ⚠️ 所有解析策略失败，原始响应前200字符: {result[:200]}...")
        return {
            "is_exploitable": False,
            "confidence": "low",
            "exploitability_score": 3,
            "reason": "无法解析 LLM 响应",
            "reasoning": result[:500]
        }

    def _format_exploit_code(self, code: str) -> str:
        """格式化 exploit 代码，处理转义字符"""
        if not code:
            return ""
        # 处理 JSON 中的转义换行符
        formatted = code.replace("\\n", "\n").replace("\\t", "    ")
        # 移除多余的转义
        formatted = formatted.replace('\\"', '"')
        return formatted.strip()

    def _determine_status(self, parsed: Dict) -> VerificationStatus:
        """根据分析结果确定验证状态"""
        is_exploitable = parsed.get("is_exploitable", False)
        confidence = parsed.get("confidence", "low")
        score = parsed.get("exploitability_score", 5)

        # 映射置信度字符串到数值
        confidence_map = {
            "high": 85,
            "medium": 60,
            "low": 35,
            "theoretical": 15
        }

        if isinstance(confidence, str):
            confidence_num = confidence_map.get(confidence.lower(), 50)
        else:
            confidence_num = confidence

        # 更新 parsed 中的置信度数值
        parsed["confidence"] = confidence_num

        # 根据组合条件判断状态
        if is_exploitable and confidence_num >= 80 and score >= 7:
            return VerificationStatus.VERIFIED
        elif is_exploitable and confidence_num >= 60 and score >= 5:
            return VerificationStatus.LIKELY
        elif is_exploitable and score >= 4:
            return VerificationStatus.NEEDS_REVIEW
        elif not is_exploitable and confidence_num >= 80:
            # 高置信度说不可利用
            if score <= 2:
                return VerificationStatus.FALSE_POSITIVE
            else:
                return VerificationStatus.THEORETICAL
        else:
            return VerificationStatus.NEEDS_REVIEW

    def generate_verification_report(
        self,
        results: Dict[str, List[ExploitVerificationReport]],
        module_name: str = "Unknown"
    ) -> str:
        """生成完整的漏洞验证报告"""
        lines = []
        lines.append("=" * 70)
        lines.append("        🎩 WHITE HAT VULNERABILITY VERIFICATION REPORT")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"📦 Module: {module_name}")
        lines.append(f"🔍 Total Findings Analyzed: {sum(len(v) for v in results.values())}")
        lines.append("")

        # 统计摘要
        lines.append("-" * 70)
        lines.append("📊 VERIFICATION SUMMARY")
        lines.append("-" * 70)
        lines.append(f"   🔴 Verified Vulnerabilities: {len(results.get('verified', []))}")
        lines.append(f"   🟠 Likely Vulnerabilities: {len(results.get('likely', []))}")
        lines.append(f"   🟡 Needs Manual Review: {len(results.get('needs_review', []))}")
        lines.append(f"   ⚪ Theoretical (Low Risk): {len(results.get('theoretical', []))}")
        lines.append(f"   🟢 False Positives: {len(results.get('false_positive', []))}")
        lines.append("")

        # 已验证的漏洞
        if results.get('verified'):
            lines.append("=" * 70)
            lines.append("            🔴 VERIFIED VULNERABILITIES")
            lines.append("=" * 70)
            for report in results['verified']:
                lines.append(report.to_markdown())
                lines.append("-" * 70)

        # 很可能的漏洞
        if results.get('likely'):
            lines.append("")
            lines.append("=" * 70)
            lines.append("            🟠 LIKELY VULNERABILITIES")
            lines.append("=" * 70)
            for report in results['likely']:
                lines.append(report.to_markdown())
                lines.append("-" * 70)

        # 需要审查
        if results.get('needs_review'):
            lines.append("")
            lines.append("=" * 70)
            lines.append("            🟡 NEEDS MANUAL REVIEW")
            lines.append("=" * 70)
            for report in results['needs_review']:
                lines.append(f"### {report.vulnerability_id}")
                lines.append(f"**类型**: {report.vulnerability_type}")
                lines.append(f"**评分**: {report.exploitability_score}/10")
                lines.append(f"**原因**: {report.why_not_exploitable or '需要人工判断'}")
                lines.append("-" * 70)

        # 理论性漏洞（折叠）
        if results.get('theoretical'):
            lines.append("")
            lines.append("=" * 70)
            lines.append("            ⚪ THEORETICAL VULNERABILITIES (Low Priority)")
            lines.append("=" * 70)
            for report in results['theoretical']:
                lines.append(f"   • {report.vulnerability_id}: {report.vulnerability_type}")
                lines.append(f"     Reason: {report.why_not_exploitable or 'No clear exploit path'}")

        # 误报（折叠）
        if results.get('false_positive'):
            lines.append("")
            lines.append("=" * 70)
            lines.append("            🟢 FALSE POSITIVES")
            lines.append("=" * 70)
            for report in results['false_positive']:
                lines.append(f"   ✓ {report.vulnerability_id}: {report.vulnerability_type}")

        lines.append("")
        lines.append("=" * 70)
        lines.append("💡 NOTE: Verified and Likely vulnerabilities should be fixed immediately.")
        lines.append("   Needs Review items require manual investigation.")
        lines.append("=" * 70)

        return "\n".join(lines)


# ============================================================================
# 集成到完整审计流程
# ============================================================================

class EnhancedSecurityAuditPipeline:
    """
    增强版安全审计管道

    完整流程:
    1. SecurityScanner - 漏洞扫描
    2. WhiteHatAgent - 漏洞验证
    3. SecurityReviewer - Spec 覆盖分析
    4. 生成最终报告
    """

    def __init__(self, scanner, rag_retriever=None):
        """
        Args:
            scanner: SecurityScanner 实例
            rag_retriever: RAG 检索器
        """
        self.scanner = scanner
        self.white_hat = WhiteHatAgent(rag_retriever=rag_retriever)

    def audit(
        self,
        source_code: str,
        verified_spec: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        执行完整审计

        Args:
            source_code: 源代码
            verified_spec: 已验证的 spec 代码（如果有）
            context: 额外上下文

        Returns:
            完整审计报告
        """
        print("🔍 [Pipeline] Stage 1: 漏洞扫描...")
        scan_report = self.scanner.scan(source_code)

        if not scan_report.matches:
            print("✅ [Pipeline] 未发现漏洞，审计完成。")
            return {
                "status": "clean",
                "scan_findings": 0,
                "verified_vulnerabilities": [],
                "theoretical_vulnerabilities": [],
                "false_positives": [],
                "report": "No vulnerabilities found."
            }

        print(f"   发现 {len(scan_report.matches)} 个潜在漏洞")

        # 转换为标准格式
        vulnerabilities = []
        for match in scan_report.matches:
            vulnerabilities.append({
                "id": match.pattern_id,
                "pattern_id": match.pattern_id,
                "category": match.category if hasattr(match, 'category') else "unknown",
                "severity": match.severity,
                "description": match.recommendation,
                "detection_cues": match.matched_cues,
                "location": {
                    "module": context.get("module_name", "unknown") if context else "unknown",
                    "line_hints": match.line_hints
                }
            })

        print("\n🎩 [Pipeline] Stage 2: 漏洞验证...")
        verification_results = self.white_hat.verify_all(
            vulnerabilities=vulnerabilities,
            source_code=source_code,
            context=context
        )

        # 生成报告
        module_name = context.get("module_name", "Unknown") if context else "Unknown"
        report = self.white_hat.generate_verification_report(
            verification_results,
            module_name=module_name
        )

        # 计算风险评分
        verified_count = len(verification_results.get('verified', []))
        likely_count = len(verification_results.get('likely', []))

        if verified_count > 0:
            risk_level = "CRITICAL" if any(r.severity == "critical" for r in verification_results['verified']) else "HIGH"
        elif likely_count > 0:
            risk_level = "HIGH" if any(r.severity in ["critical", "high"] for r in verification_results['likely']) else "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "status": "vulnerabilities_found",
            "risk_level": risk_level,
            "scan_findings": len(scan_report.matches),
            "verified_vulnerabilities": [asdict(r) if hasattr(r, '__dict__') else r for r in verification_results.get('verified', [])],
            "likely_vulnerabilities": [asdict(r) if hasattr(r, '__dict__') else r for r in verification_results.get('likely', [])],
            "needs_review": [asdict(r) if hasattr(r, '__dict__') else r for r in verification_results.get('needs_review', [])],
            "theoretical_vulnerabilities": [asdict(r) if hasattr(r, '__dict__') else r for r in verification_results.get('theoretical', [])],
            "false_positives": [asdict(r) if hasattr(r, '__dict__') else r for r in verification_results.get('false_positive', [])],
            "report": report,
            "summary": {
                "total_scanned": len(scan_report.matches),
                "verified": verified_count,
                "likely": likely_count,
                "needs_review": len(verification_results.get('needs_review', [])),
                "theoretical": len(verification_results.get('theoretical', [])),
                "false_positive": len(verification_results.get('false_positive', [])),
                "verification_rate": (verified_count + likely_count) / max(1, len(scan_report.matches))
            }
        }
