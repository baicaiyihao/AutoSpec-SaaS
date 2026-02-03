"""
VerifierAgent - 统一验证Agent (v2.5.3)

合并原有的 Auditor/Expert/Analyst 三个 Agent，在一次 LLM 调用中完成多视角验证。

优化效果:
- Token 消耗: 3 次 LLM 调用 → 1 次，节省 ~66%
- 架构简化: 5 Agent → 3 Agent (Verifier, Manager, WhiteHat)

验证维度 (在一次分析中完成):
1. 安全审计视角 (原 Auditor): 是否违反安全最佳实践？是否存在已知漏洞模式？
2. 技术专家视角 (原 Expert): Move 类型系统保护？Sui 对象模型阻止？
3. 业务分析视角 (原 Analyst): 攻击经济可行性？成本/收益比？
"""

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from enum import Enum

from .base_agent import BaseAgent, AgentRole, AgentMessage, AgentConfig
# 🔥 v2.5.8: 保留针对性知识注入
from .move_knowledge import get_relevant_knowledge

# 🔥 v2.5.8 修复: 引入完整的安全知识库 (原来漏掉了!)
try:
    from src.prompts.sui_move_security_knowledge import (
        get_false_positive_guide,
        get_auditor_context,
        SECURITY_PATTERNS,
        is_likely_false_positive,
    )
    SUI_SECURITY_KNOWLEDGE_AVAILABLE = True
except ImportError:
    SUI_SECURITY_KNOWLEDGE_AVAILABLE = False
    def get_false_positive_guide(): return ""
    def get_auditor_context(): return ""
    SECURITY_PATTERNS = ""
    def is_likely_false_positive(vtype, desc): return False, ""

# 扩展 AgentRole 枚举
class ExtendedAgentRole(Enum):
    """扩展的 Agent 角色枚举"""
    MANAGER = "manager"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    EXPERT = "expert"
    VERIFIER = "verifier"  # 新增


VERIFIER_ROLE_PROMPT = """你是一个 Move/Sui 智能合约安全验证专家。

## 核心任务
判断漏洞是否被 Move/Sui 语言级安全机制覆盖，或是否为开发者逻辑错误。

## ⚠️ Move 语言级保护参考 (仅供参考，不是强制规则!)

以下漏洞类型**通常**会被 Move 语言级机制保护:

| 漏洞描述关键词 | 通常结论 | 保护机制 |
|--------------|---------|---------|
| 下溢、underflow、减法溢出 (非位移) | 通常是误报 | Move VM 自动 abort |
| 溢出、overflow、加法/乘法溢出 (非位移) | 通常是误报 | Move VM 自动 abort |
| 越界、out of bounds、向量/数组越界 | 通常是误报 | Move vector 自动检查 |
| 重入、reentrancy、reentrant | 通常是误报 | Move 无动态调度 |

⚠️ **例外情况 - 仍是真实漏洞**:
1. **位移操作** (<<, >>) 不受溢出保护 → 需要审查
2. **开发者逻辑错误**: 如忘记验证类型参数、遗漏检查、逻辑不一致
3. **类型检查缺失**: 如闪电贷借出 A 类型但还款时未验证是否也是 A 类型

## 判断流程
1. 阅读代码，理解实际逻辑
2. 检查是否有 Move 语言级保护
3. **关键**: 即使有语言级保护，也要检查是否存在开发者逻辑错误
4. 综合判断后输出结论

## 工作原则
- **代码优先**: 仔细阅读代码，不要仅凭漏洞类型名称下结论
- **区分语言保护 vs 逻辑错误**: 语言级保护是误报，开发者逻辑错误是真实漏洞
- 高置信度输出，避免 needs_review
"""


VERIFIER_OUTPUT_FORMAT = """
## 输出要求 (精简版)

🔴 **所有输出必须使用中文！** reasoning、mechanism_name 等字段必须用中文描述！

请输出 JSON 格式:
```json
{
    "conclusion": "confirmed|false_positive",
    "confidence": 0-100,
    "final_severity": "critical|high|medium|low|none",
    "security_mechanism_covered": true/false,
    "mechanism_name": "如被覆盖，说明是哪个机制（中文）",
    "reasoning": "简短判定理由（中文，1-2句话）"
}
```

**判断逻辑**:
- security_mechanism_covered=true → conclusion=false_positive
- security_mechanism_covered=false → 分析是否为真实漏洞
"""


@dataclass
class VerificationResult:
    """验证结果 (v2.5.8 精简版)"""
    conclusion: str  # "confirmed" | "false_positive"
    confidence: int  # 0-100
    final_severity: str
    security_mechanism_covered: bool  # 是否被安全机制覆盖
    mechanism_name: str  # 覆盖机制名称
    reasoning: str


class VerifierAgent(BaseAgent):
    """
    统一验证 Agent

    合并 Auditor/Expert/Analyst 的功能，在一次调用中完成多视角验证。

    v2.5.4: 支持 toolkit 按需查询安全知识
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        # 使用自定义的 role (不在原枚举中)
        super().__init__(
            role=AgentRole.AUDITOR,  # 复用 AUDITOR 作为基础 role
            role_prompt=VERIFIER_ROLE_PROMPT,
            config=config
        )
        self._actual_role = "verifier"  # 实际角色标识
        self.toolkit = None  # 🔥 v2.5.4: 工具箱引用

    def set_toolkit(self, toolkit):
        """
        🔥 v2.5.4: 设置工具箱引用

        Args:
            toolkit: AgentToolkit 实例，用于按需查询安全知识
        """
        self.toolkit = toolkit

    async def process(self, message: AgentMessage) -> AgentMessage:
        """处理消息"""
        msg_type = message.content.get("type")

        if msg_type == "verify":
            result = await self.verify_finding(message.content.get("finding"), message.content.get("code_context"))
        else:
            result = {"error": f"Unknown message type: {msg_type}"}

        return AgentMessage(
            from_agent=self.role,
            to_agent=message.from_agent,
            message_type="response",
            content=result
        )

    async def verify_finding(
        self,
        finding: Dict[str, Any],
        code_context: str = ""
    ) -> Dict[str, Any]:
        """
        验证单个漏洞发现 (多视角一次完成)

        Args:
            finding: 漏洞发现
            code_context: 代码上下文

        Returns:
            验证结果 (包含三个视角的分析)
        """
        # 提取漏洞信息
        vuln_id = finding.get("id", finding.get("title", "unknown"))
        severity = finding.get("severity", "medium")
        description = finding.get("description", "")
        location = finding.get("location", {})
        evidence = finding.get("evidence", finding.get("proof", ""))

        # 构建位置字符串
        if isinstance(location, dict):
            location_str = f"{location.get('module', '?')}::{location.get('function', '?')}"
        else:
            location_str = str(location)

        # 🔥 v2.5.8: 注入针对性 Move 安全知识 (根据漏洞类型匹配)
        # 注: 闪电贷知识已在 sui_move_security_knowledge.py 中，无需单独工具调用
        security_knowledge = get_relevant_knowledge(finding)

        prompt = f"""
## 待验证漏洞

**ID**: {vuln_id}
**严重性**: {severity}
**位置**: {location_str}
**描述**: {description}

**证据/代码片段**:
```move
{evidence[:2000] if evidence else "无"}
```

## 代码上下文
```move
{code_context[:3000] if code_context else "无代码上下文，请使用工具查询"}
```

{security_knowledge}
## 验证任务 (v2.5.8 精简)

**核心问题**: 此漏洞是否被 Move/Sui 安全机制覆盖？

1. 阅读上方注入的 **Move 安全知识**
2. 判断漏洞是否被语言级机制保护
3. 如果被保护 → `false_positive`，说明机制名称
4. 如果不被保护 → 分析是否为真实漏洞

{VERIFIER_OUTPUT_FORMAT}
"""

        # 单次 LLM 调用完成多视角验证
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        result = self.parse_json_response(response)

        # 确保必要字段存在
        if "conclusion" not in result:
            result["conclusion"] = "needs_review"
        if "confidence" not in result:
            result["confidence"] = 50
        if "final_severity" not in result:
            result["final_severity"] = severity

        return result

    async def verify_with_tools(
        self,
        finding: Dict[str, Any],
        verification_prompt: str = "",
        function_index: str = "",
        analysis_context: str = "",
        max_tool_rounds: int = 3  # 🔥 v2.5.14: 已有预构建上下文，3轮足够
    ) -> Dict[str, Any]:
        """
        使用工具辅助验证 (继承自 BaseAgent)

        Args:
            finding: 漏洞发现
            verification_prompt: 额外的验证提示
            function_index: 函数索引
            analysis_context: 分析上下文
            max_tool_rounds: 最大工具调用轮数 (默认 8)

        Returns:
            验证结果
        """
        # 提取代码上下文
        code_context = finding.get('code_context', '')

        # 🔥 v2.5.8: 注入针对性 Move 安全知识
        relevant_knowledge = get_relevant_knowledge(finding)

        # 构建完整的验证 prompt
        full_verification_prompt = f"""
{VERIFIER_ROLE_PROMPT}
{relevant_knowledge}
{verification_prompt if verification_prompt else ""}

{VERIFIER_OUTPUT_FORMAT}
"""

        # 使用 BaseAgent 的工具辅助验证方法
        result = await super().verify_with_tools(
            finding=finding,
            verification_prompt=full_verification_prompt,
            function_index=function_index,
            analysis_context=analysis_context,
            max_tool_rounds=max_tool_rounds
        )

        # 确保必要字段存在
        if "conclusion" not in result:
            result["conclusion"] = "needs_review"
        if "confidence" not in result:
            result["confidence"] = 50

        return result

    async def verify_lightweight(
        self,
        finding: Dict[str, Any],
        verification_prompt: str = "",
        minimal_context: str = "",
        function_index: str = "",
        max_tool_rounds: int = 3
    ) -> Dict[str, Any]:
        """
        轻量级验证 (使用独立 LLM 实例)

        Args:
            finding: 漏洞发现
            verification_prompt: 额外的验证提示
            minimal_context: 最小代码上下文
            function_index: 函数索引
            max_tool_rounds: 最大工具调用轮数

        Returns:
            验证结果
        """
        # 🔥 v2.5.8: 注入针对性 Move 安全知识
        relevant_knowledge = get_relevant_knowledge(finding)

        # 构建完整的验证 prompt
        full_verification_prompt = f"""
{VERIFIER_ROLE_PROMPT}
{relevant_knowledge}
{verification_prompt if verification_prompt else ""}

{VERIFIER_OUTPUT_FORMAT}
"""

        # 使用 BaseAgent 的轻量级验证方法
        result = await super().verify_lightweight(
            finding=finding,
            verification_prompt=full_verification_prompt,
            minimal_context=minimal_context,
            function_index=function_index,
            max_tool_rounds=max_tool_rounds
        )

        # 确保必要字段存在
        if "conclusion" not in result:
            result["conclusion"] = "needs_review"
        if "confidence" not in result:
            result["confidence"] = 50

        return result

    async def verify_findings_batch(
        self,
        findings: List[Dict[str, Any]],
        module_name: str = ""
    ) -> List[Dict[str, Any]]:
        """
        🔥 v2.5.8 修复: 批量验证漏洞 - 使用完整安全知识库

        功能:
        - 注入完整的 sui_move_security_knowledge (误报指南、安全模式)
        - 注入 move_knowledge (针对性知识匹配)
        - 闪电贷自动检测
        - 三视角分析

        Args:
            findings: 漏洞列表
            module_name: 模块名

        Returns:
            每个漏洞的验证结果列表
        """
        if not findings:
            return []

        # ================================================================
        # 1. 获取完整安全知识库 (原来漏掉了!)
        # ================================================================
        false_positive_guide = get_false_positive_guide() if SUI_SECURITY_KNOWLEDGE_AVAILABLE else ""
        security_patterns = SECURITY_PATTERNS if SUI_SECURITY_KNOWLEDGE_AVAILABLE else ""

        # ================================================================
        # 2. 构建每个漏洞的分析文本
        # ================================================================
        findings_text = []
        all_knowledge_set = set()

        for i, finding in enumerate(findings, 1):
            vuln_id = finding.get("id", f"VULN-{i}")
            severity = finding.get("severity", "medium")
            title = finding.get("title", "Unknown")
            description = finding.get("description", "")
            category = finding.get("category", "")
            evidence = finding.get("evidence", finding.get("proof", ""))
            location = finding.get("location", {})
            func_name = location.get("function", "unknown") if isinstance(location, dict) else "unknown"
            function_code = finding.get("_function_code", "")
            caller_signatures = finding.get("_caller_signatures", [])

            # 获取针对性知识 (关键词匹配)
            vuln_knowledge = get_relevant_knowledge(finding)
            if vuln_knowledge:
                all_knowledge_set.add(vuln_knowledge)

            # 🔥 预判断: 使用 is_likely_false_positive
            # 🔥 v2.5.23: 改为建议而非强制，保留 LLM 判断权
            # 避免类型检查缺失等开发者逻辑错误被误过滤
            fp_hint = ""

            # 🔥 v2.5.13: 优先使用软过滤提示（来自排除规则）
            soft_filter = finding.get("soft_filter_hint")
            if soft_filter:
                fp_hint = f"""
🔶 **排除规则提示** [{soft_filter.get('rule_name', 'unknown')}]:
{soft_filter.get('hint_for_ai', '')}"""
            elif SUI_SECURITY_KNOWLEDGE_AVAILABLE:
                is_fp, fp_reason = is_likely_false_positive(category, description)
                if is_fp:
                    fp_hint = f"""
⚠️ **参考提示**: 此漏洞类型通常是误报（{fp_reason}）
**但请注意**: 如果这是开发者逻辑错误（如忘记验证类型参数、遗漏检查等），则仍是真实漏洞。
**请仔细检查代码后再做判断，不要仅凭漏洞类型就下结论。**"""

            findings_text.append(f"""
================================================================================
### 漏洞 [{i}]: {vuln_id}
================================================================================
**标题**: {title}
**严重性**: {severity}
**分类**: {category}
**位置**: `{module_name}::{func_name}`
{fp_hint}
**漏洞描述**:
{description}

**证据代码**:
```move
{evidence[:1200] if evidence else "无"}
```

**函数完整实现** (仔细分析权限控制!):
```move
{function_code[:3000] if function_code else "⚠️ 无函数代码"}
```

**上层调用者签名** (检查分层设计! 上层有 Cap 则底层安全):
{chr(10).join(caller_signatures) if caller_signatures else "无调用者信息"}
""")

        # 合并针对性知识 (不限制数量)
        combined_knowledge = "\n\n".join(all_knowledge_set) if all_knowledge_set else ""

        # ================================================================
        # 3. 构建完整 Prompt
        # ================================================================
        prompt = f"""# Sui Move 智能合约安全验证

{VERIFIER_ROLE_PROMPT}

---

## 🔥 核心: Sui Move 安全设计模式 (必读!)

{security_patterns}

---

## 🔥 误报判断指南 (必读!)

{false_positive_guide}

---

## 针对性安全知识 (根据漏洞类型匹配)

{combined_knowledge}

---

## 待验证漏洞

**模块**: `{module_name}`
**数量**: {len(findings)}

{"".join(findings_text)}

---

## 验证任务

对每个漏洞执行:

### 1. 🔴 Capability 检查 (最重要! 最常见误报!)
看函数签名是否有 Cap 参数:
```move
public fun xxx(_: &AdminCap, ...)  // ← 有 Cap = 有权限控制 = false_positive!
public entry fun yyy(_: &OwnerCap, ...)  // ← 即使参数名是 _ 也算!
```
**看到 `_: &XXXCap` 参数 → 立即判定 false_positive**

### 2. 分层设计检查
如果是 acl/utils/helper 等辅助模块的函数:
- 底层函数可能没有权限检查
- 但如果只被上层带 Cap 的函数调用 → false_positive

### 3. 语言级保护检查
- 算术溢出 (+,-,*,/) → Move 自动保护 → false_positive
- 重入攻击 → Move 无动态调度 → false_positive
- 位移溢出 (<<,>>) → **不受保护** → 需要审查

### 4. 结论判定
- **false_positive**: 有 Cap 参数 / 分层设计 / 语言级保护
- **confirmed**: 确实存在安全问题

## 输出格式

🔴 **所有输出必须使用中文！** mechanism_name、code_evidence、reasoning 等字段必须用中文！

```json
{{
    "results": [
        {{
            "vuln_index": 1,
            "vuln_id": "漏洞ID",
            "conclusion": "false_positive 或 confirmed",
            "confidence": 85,
            "final_severity": "critical/high/medium/low/none",
            "security_mechanism_covered": true,
            "mechanism_name": "能力访问控制 / 溢出保护 / 热土豆模式 等（中文）",
            "code_evidence": "代码中的权限控制证据（中文描述）",
            "reasoning": "判定理由（中文）"
        }}
    ]
}}
```
"""
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        result = self.parse_json_response(response)

        # 解析结果
        results_list = result.get("results", [])
        verified_results = []

        for i, finding in enumerate(findings):
            matched_result = None
            for r in results_list:
                if r.get("vuln_index") == i + 1 or r.get("vuln_id") == finding.get("id"):
                    matched_result = r
                    break

            if matched_result:
                verified_results.append({
                    "original_finding": finding,
                    "conclusion": matched_result.get("conclusion", "needs_review"),
                    "confidence": matched_result.get("confidence", 50),
                    "final_severity": matched_result.get("final_severity", finding.get("severity", "medium")),
                    "security_mechanism_covered": matched_result.get("security_mechanism_covered", False),
                    "mechanism_name": matched_result.get("mechanism_name", ""),
                    "code_evidence": matched_result.get("code_evidence", ""),
                    "reasoning": matched_result.get("reasoning", "")
                })
            else:
                verified_results.append({
                    "original_finding": finding,
                    "conclusion": "confirmed",
                    "confidence": 50,
                    "final_severity": finding.get("severity", "medium"),
                    "security_mechanism_covered": False,
                    "mechanism_name": "",
                    "code_evidence": "",
                    "reasoning": "批量验证未返回结果，保守判定为 confirmed"
                })

        return verified_results

    async def verify_group_with_tools(
        self,
        findings: List[Dict[str, Any]],
        shared_context: str,
        group_knowledge: str,
        function_index: str = "",
        analysis_context: str = "",
        max_tool_rounds: int = 3  # 🔥 v2.5.14: 已有预构建上下文，3轮足够
    ) -> List[Dict[str, Any]]:
        """
        🔥 v2.5.11: 分组批量验证 + 工具调用

        核心优化：
        1. 一组漏洞（3-5个）共享代码上下文，减少重复
        2. 共享安全知识，只注入一次
        3. 保留工具调用能力，可按需查询更多代码
        4. 一次 LLM 调用验证多个漏洞

        Token 节省：
        - System prompt: 5 次 → 1 次 (节省 80%)
        - 代码上下文: 5 份 → 1 份共享 (节省 60-80%)
        - 安全知识: 5 次 → 1 次 (节省 80%)

        Args:
            findings: 一组漏洞（3-5个，同模块）
            shared_context: 预构建的共享代码上下文
            group_knowledge: 合并的安全知识
            function_index: 函数索引
            analysis_context: Phase 0/1 分析上下文
            max_tool_rounds: 最大工具调用轮数

        Returns:
            每个漏洞的验证结果列表
        """
        if not findings:
            return []

        if not self.toolkit:
            # 无工具，退化为普通批量验证
            return await self.verify_findings_batch(findings)

        # 构建漏洞列表文本
        findings_text = []
        for i, finding in enumerate(findings, 1):
            vuln_id = finding.get("id", f"VULN-{i}")
            title = finding.get("title", "Unknown")
            severity = finding.get("severity", "medium")
            description = finding.get("description", "")
            evidence = finding.get("evidence", finding.get("proof", ""))[:800]
            location = finding.get("location", {})
            func_name = location.get("function", "unknown") if isinstance(location, dict) else "unknown"

            # 🔥 v2.5.14: 在每个漏洞描述中直接包含软过滤提示
            soft_hint_text = ""
            soft_filter = finding.get("soft_filter_hint")
            if soft_filter:
                rule_name = soft_filter.get("rule_name", "unknown")
                reason = soft_filter.get("reason", "")
                soft_hint_text = f"""
> ⚠️ **排除规则提示 [{rule_name}]**: {reason}
> 请仔细验证此漏洞是否真实存在。如果确实是语言/框架保护或设计选择，应判定为 false_positive。"""

            findings_text.append(f"""
### 漏洞 [{i}]: {vuln_id}
- **标题**: {title}
- **严重性**: {severity}
- **函数**: {func_name}
- **描述**: {description}
- **证据代码**: ```{evidence}```
{soft_hint_text}
""")

        # 构建完整 prompt
        tools = self.toolkit.get_security_tools()

        prompt = f"""# 批量漏洞验证任务

你需要验证以下 {len(findings)} 个漏洞。这些漏洞来自同一模块，共享代码上下文。

{group_knowledge if group_knowledge else ""}

---

## 共享代码上下文

```move
{shared_context if shared_context else "无预构建上下文，请使用工具获取"}
```

{f"## 可查询的函数{chr(10)}{function_index}" if function_index else ""}

---

## 待验证漏洞

{"".join(findings_text)}

---

## 验证任务

对每个漏洞判断是否为**真实安全漏洞**。

### 🔥 核心判断标准：外部攻击者能否利用？

**只有满足以下条件才是真实漏洞 (confirmed)**:
1. **外部攻击者可触发** - 无需 AdminCap/OwnerCap 等特权
2. **可造成实际损害** - 资金损失、状态损坏、权限提升
3. **攻击路径可行** - 不是理论风险，有具体利用方式

**以下情况判定为 false_positive**:
- ❌ **管理员控制**: 需要 AdminCap/OwnerCap 才能触发 → 管理员应知道后果
- ❌ **代码质量问题**: 精度损失、未对齐、状态不同步 → 不是安全漏洞
- ❌ **防御性 abort**: 无效输入导致交易失败 → 是保护机制不是漏洞
- ❌ **设计选择**: 费用比例、时间窗口、优先级策略 → 协议的业务决策

### 🔥 常见设计模式 (非漏洞)

1. **默认允许模式**: `allowed = in_allowlist || !in_denylist`
   - 这是 "default allow, explicit deny" 策略
   - 适用于无许可 DeFi 协议（任何币种默认可用，除非被明确禁止）
   - **不是逻辑错误**，是有意设计

2. **闪电贷无调用者验证**: Flash loan 设计上就是无许可的
   - 任何人都可以借，只要同交易内还款
   - 不需要验证调用者身份

3. **公开读取函数**: 只读函数没有权限检查是正常的

4. **init 函数无调用者验证**: Sui Move 的 init 函数由运行时保护
   - 只在模块发布时调用一次
   - 外部用户**无法调用** init 函数
   - "未验证调用者" 是误报 → **false_positive**

### 排除规则提示
🔥 **重要**: 如果漏洞有 ⚠️ 排除规则提示，**强烈倾向于 false_positive**，除非能证明：
1. 开发者忘记了某个关键检查（如忘记验证类型）
2. 存在具体的资金损失路径
3. 攻击者可以获得超出设计意图的权限

### 技术检查

1. **Capability ACL** - 有 `&XXXCap` 参数 → **false_positive**
   - 🔥 **重要**: `_: &AdminCap` 参数名为 `_` 不代表"未使用"
   - 调用者必须持有 AdminCap 对象才能调用函数，这**就是访问控制**
   - Move 要求传递引用 = 强制持有权限，即使函数不读取值
2. **Move 保护** - 算术溢出 (+,-,*,/) 自动 abort → **false_positive**
3. **分层设计** - 底层无权限但调用者有 Cap → **false_positive**
4. **位移溢出** - (<<,>>) 不受保护 → **需审查**

---

## 工具使用指南

上面已提供共享代码上下文。只有在需要以下信息时才调用工具：
- 跨模块函数定义
- 类型定义
- 更深的调用链

**效率要求**: 每轮最多调用 2 个工具

---

## 输出格式

🔴 **所有输出必须使用中文！** mechanism_name、code_evidence、reasoning 等字段必须用中文！

```json
{{
    "results": [
        {{
            "vuln_index": 1,
            "vuln_id": "漏洞ID",
            "conclusion": "false_positive 或 confirmed",
            "confidence": 85,
            "final_severity": "critical/high/medium/low/none",
            "security_mechanism_covered": true,
            "mechanism_name": "能力访问控制 / 溢出保护 等（中文）",
            "code_evidence": "代码证据（中文描述）",
            "reasoning": "判定理由（中文）"
        }}
    ]
}}
```
"""

        # 使用工具调用循环
        response = await self.call_llm_with_tools(
            prompt=prompt,
            tools=tools,
            max_tool_rounds=max_tool_rounds,
            json_mode=True
        )

        result = self.parse_json_response(response)

        # 解析结果
        results_list = result.get("results", [])
        verified_results = []

        for i, finding in enumerate(findings):
            matched_result = None
            for r in results_list:
                if r.get("vuln_index") == i + 1 or r.get("vuln_id") == finding.get("id"):
                    matched_result = r
                    break

            if matched_result:
                verified_results.append({
                    "original_finding": finding,
                    "conclusion": matched_result.get("conclusion", "needs_review"),
                    "confidence": matched_result.get("confidence", 50),
                    "final_severity": matched_result.get("final_severity", finding.get("severity", "medium")),
                    "security_mechanism_covered": matched_result.get("security_mechanism_covered", False),
                    "mechanism_name": matched_result.get("mechanism_name", ""),
                    "code_evidence": matched_result.get("code_evidence", ""),
                    "reasoning": matched_result.get("reasoning", "")
                })
            else:
                # 未匹配到结果，保守判定为 confirmed
                verified_results.append({
                    "original_finding": finding,
                    "conclusion": "confirmed",
                    "confidence": 50,
                    "final_severity": finding.get("severity", "medium"),
                    "security_mechanism_covered": False,
                    "mechanism_name": "",
                    "code_evidence": "",
                    "reasoning": "批量验证未返回结果，保守判定为 confirmed"
                })

        return verified_results


# 🔥 v2.5.3: Verifier 专用的验证 Prompt (用于 RoleSwap)
VERIFIER_VERIFICATION_PROMPT = """
你是一个智能合约安全验证专家。请从以下三个维度验证此漏洞:

### 1. 安全审计视角
- 此漏洞模式是否在真实攻击中被利用过？
- 代码是否违反了安全最佳实践？

### 2. 技术专家视角
- Move 的类型系统或 Sui 的对象模型是否阻止了此攻击？
- 如果有语言层面保护，说明具体机制

### 3. 业务分析视角
- 攻击者需要多少成本才能执行此攻击？
- 成功后能获得多少收益？
- 在真实业务场景中是否可能发生？

基于以上分析，给出你的结论。

🔴 **所有输出必须使用中文！** 不要输出英文描述！
"""
