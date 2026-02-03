"""
ManagerAgent - 项目经理Agent

职责:
1. 理解合约的业务目标和核心功能
2. 制定审计计划和优先级
3. 协调其他Agent的工作
4. 综合各方发现，生成最终报告
5. 评估整体风险等级
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent, AgentRole, AgentMessage, AgentConfig

# 🔥 v2.5.3: 知识指南已移至 Phase 2 规则过滤，此处不再注入
# 这样可以大幅减少 token 消耗


MANAGER_ROLE_PROMPT = """你是一位资深的智能合约安全审计项目经理。

## 你的职责
1. 理解合约的业务目标和核心功能
2. 制定审计计划和优先级
3. 协调其他Agent的工作
4. 综合各方发现，生成最终报告
5. 评估整体风险等级

## 工作原则
- 以安全为最高优先级
- 关注高风险区域（资金流动、权限控制、外部调用）
- 综合考虑漏洞的严重性和可利用性
- 提供清晰、可操作的建议

## 风险评级标准
- CRITICAL: 可直接导致资金损失或合约控制权丢失
- HIGH: 可能导致资金损失或严重功能异常
- MEDIUM: 可能导致功能异常或用户体验问题
- LOW: 代码质量问题或轻微风险
"""


@dataclass
class AuditPlan:
    """审计计划"""
    project_name: str
    audit_scope: List[str]
    priority_functions: List[str]
    risk_areas: List[str]
    estimated_complexity: str


@dataclass
class AuditSummary:
    """审计摘要"""
    overall_risk: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    key_recommendations: List[str]


class ManagerAgent(BaseAgent):
    """项目经理Agent"""

    def __init__(self, config: Optional[AgentConfig] = None):
        super().__init__(
            role=AgentRole.MANAGER,
            role_prompt=MANAGER_ROLE_PROMPT,
            config=config
        )

    async def process(self, message: AgentMessage) -> AgentMessage:
        """处理消息"""
        msg_type = message.content.get("type")

        if msg_type == "create_plan":
            result = await self.create_audit_plan(message.content.get("context"))
        elif msg_type == "generate_report":
            result = await self.generate_report(message.content.get("findings"))
        elif msg_type == "make_verdict":
            result = await self.make_verdict(message.content.get("finding_data"))
        else:
            result = {"error": f"Unknown message type: {msg_type}"}

        return AgentMessage(
            from_agent=self.role,
            to_agent=message.from_agent,
            message_type="response",
            content=result
        )

    async def create_audit_plan(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        创建审计计划

        Args:
            context: 合约上下文信息

        Returns:
            审计计划
        """
        prompt = f"""
## 任务
请根据以下合约信息，制定详细的安全审计计划。

## 合约信息
- 项目名称: {context.get('project_name', 'Unknown')}
- 模块列表: {context.get('modules', [])}
- 函数数量: {context.get('function_count', 0)}
- 外部依赖: {context.get('dependencies', [])}

## 代码概览
```move
{context.get('code_summary', '')}
```

## 输出要求
请输出JSON格式的审计计划:
```json
{{
    "project_name": "项目名称",
    "audit_scope": ["需要审计的模块列表"],
    "priority_functions": ["高优先级函数，如涉及资金的函数"],
    "risk_areas": ["识别的风险区域"],
    "estimated_complexity": "low|medium|high",
    "audit_phases": [
        {{
            "phase": 1,
            "name": "阶段名称",
            "tasks": ["任务列表"],
            "assigned_to": "analyst|auditor|expert"
        }}
    ]
}}
```
"""
        response = await self.call_llm(prompt, json_mode=True)
        return self.parse_json_response(response)

    async def generate_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        生成审计报告

        Args:
            findings: 所有发现的漏洞

        Returns:
            完整的审计报告
        """
        prompt = f"""
## 任务
请根据以下审计发现，生成完整的安全审计报告。

## 审计发现
{self._format_findings(findings)}

## 输出要求
请输出JSON格式的审计报告:
```json
{{
    "summary": {{
        "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
        "total_findings": 数量,
        "severity_distribution": {{
            "critical": 数量,
            "high": 数量,
            "medium": 数量,
            "low": 数量
        }},
        "key_findings": ["最重要的发现摘要"],
        "recommendations": ["优先修复建议"]
    }},
    "detailed_findings": [
        {{
            "id": "VUL-001",
            "title": "漏洞标题",
            "severity": "critical|high|medium|low",
            "status": "confirmed|needs_review",
            "description": "详细描述",
            "location": "文件:行号",
            "impact": "影响分析",
            "recommendation": "修复建议",
            "code_snippet": "相关代码"
        }}
    ],
    "verification_status": {{
        "formally_verified": ["已验证的函数"],
        "not_verified": ["未验证的函数"],
        "verification_coverage": "百分比"
    }}
}}
```
"""
        response = await self.call_llm(prompt, json_mode=True)
        return self.parse_json_response(response)

    async def make_verdict(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        🔥 v2.5.0: 对漏洞做最终判定 - 包含利用性验证

        Args:
            finding_data: 包含auditor发现、expert验证、analyst评估、原始finding、完整代码

        Returns:
            最终判定结果（包含利用性分析）
        """
        # 🔥 v2.5.0: 提取完整代码上下文进行利用性验证
        finding = finding_data.get('finding', {})
        code_context = finding_data.get('code_context', '')

        # 构建漏洞摘要
        vuln_summary = self._format_vulnerability_summary(finding)

        # 截断代码上下文（避免过长）
        code_snippet = code_context[:8000] if code_context else "无代码上下文"

        # 🔥 v2.5.3: 不在此处注入知识指南，改为在 Phase 2 规则过滤
        # 这样可以大幅减少 token 消耗

        prompt = f"""
## 任务
作为安全审计主管，请综合子Agent分析并结合完整代码，判定该漏洞**是否在实际中可被利用**。

## 漏洞摘要
{vuln_summary}

## 子Agent分析结果

### Auditor发现
{finding_data.get('auditor_finding', {})}

### Expert验证
{finding_data.get('expert_review', {})}

### Analyst评估
{finding_data.get('analyst_assessment', {})}

## 完整代码上下文
```move
{code_snippet}
```

## 🔥 关键验证问题（请务必回答）

1. **入口点分析**: 攻击者能否从public函数到达这个漏洞点？路径是什么？
2. **输入可控性**: 漏洞涉及的参数是否可被攻击者控制？来源是什么？
3. **前置条件**: 利用此漏洞需要满足什么条件？这些条件在实际中是否可达？
4. **实际影响**: 如果被利用，具体会造成什么损失？（资金损失/权限提升/DoS）
5. **排除条件**: 是否属于以下情况（若是，应判定为false_positive）：
   - 硬编码常量（如错误码、初始值）不算漏洞
   - 测试/Mock函数（如abort 0的emit）不算漏洞
   - 纯getter函数无状态修改
   - 内部辅助函数无外部入口

## 输出要求
```json
{{
    "verdict": "confirmed|false_positive|needs_manual_review",
    "confidence": 0-100,
    "final_severity": "critical|high|medium|low|none",
    "exploitation_analysis": {{
        "entry_point": "攻击入口函数名，若无则填null",
        "attack_path": "入口 → 中间调用 → 漏洞函数",
        "controllable_inputs": ["可控参数1", "可控参数2"],
        "preconditions": ["前置条件1"],
        "concrete_impact": "具体影响描述",
        "is_theoretical_only": true/false
    }},
    "reasoning": "综合判定理由（结合代码分析）",
    "action_required": "需要采取的行动"
}}
```

⚠️ 重要：如果无法证明存在可行的利用路径，请判定为 false_positive 或降低严重性。
理论性风险（无法构造实际攻击）不应标记为 confirmed。
"""
        # 🔥 stateless=True: Phase 3 中并行调用，每次请求独立
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        return self.parse_json_response(response)

    def _format_vulnerability_summary(self, finding: Dict[str, Any]) -> str:
        """格式化漏洞摘要"""
        if not finding:
            return "无漏洞信息"
        return f"""
- **标题**: {finding.get('title', 'N/A')}
- **严重性**: {finding.get('severity', 'N/A')}
- **位置**: {finding.get('location', 'N/A')}
- **描述**: {finding.get('description', 'N/A')[:500]}
- **漏洞代码**: {finding.get('vulnerable_code', 'N/A')[:300]}
"""

    def _format_findings(self, findings: List[Dict[str, Any]]) -> str:
        """格式化发现列表"""
        if not findings:
            return "无发现"

        formatted = []
        for i, f in enumerate(findings, 1):
            formatted.append(f"""
### Finding #{i}
- ID: {f.get('id', 'N/A')}
- Title: {f.get('title', 'N/A')}
- Severity: {f.get('severity', 'N/A')}
- Location: {f.get('location', 'N/A')}
- Description: {f.get('description', 'N/A')}
""")
        return "\n".join(formatted)
