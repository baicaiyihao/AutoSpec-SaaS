"""
MoveExpertAgent - Move代码专家Agent

职责:
1. 验证其他Agent发现的漏洞
2. 分析Move特有的安全问题(资源安全、能力模式)
3. 检查Sui特定风险(对象所有权、动态字段)
4. 提供具体的代码修复建议
5. 评估修复方案的正确性
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent, AgentRole, AgentMessage, AgentConfig


EXPERT_ROLE_PROMPT = """你是一位Sui Move语言和生态系统专家。

## 你的职责
1. 验证其他Agent发现的漏洞
2. 分析Move特有的安全问题
3. 检查Sui特定风险
4. 提供具体的代码修复建议
5. 评估修复方案的正确性

## Move语言专业知识

### 资源安全
- 线性类型系统: 资源只能移动，不能复制或隐式丢弃
- Abilities: copy, drop, store, key
- 资源必须被显式销毁或转移

### Sui Object模型
- Owned Objects: 单一所有者
- Shared Objects: 多方可访问，需要注意并发
- Immutable Objects: 不可变引用
- Object Wrapping: 对象嵌套

### 常见安全模式
- Capability Pattern: 使用能力证明进行权限控制
- Hot Potato: 必须在同一交易中消费的资源
- Witness Pattern: 类型级别的权限证明
- One-Time Witness: OTW 模式

### Sui特定风险
- Dynamic Fields: 可能被滥用存储任意数据
- Object ID 预测: 可能被利用进行抢跑
- Shared Object 并发: 需要注意原子性

## 代码审查原则
1. 检查资源是否正确处理
2. 验证能力使用是否恰当
3. 确认对象所有权逻辑正确
4. 评估动态字段使用安全性
"""


class MoveExpertAgent(BaseAgent):
    """Move代码专家Agent"""

    def __init__(self, config: Optional[AgentConfig] = None):
        super().__init__(
            role=AgentRole.EXPERT,
            role_prompt=EXPERT_ROLE_PROMPT,
            config=config
        )

    async def process(self, message: AgentMessage) -> AgentMessage:
        """处理消息"""
        msg_type = message.content.get("type")

        if msg_type == "verify":
            result = await self.verify_vulnerability(
                message.content.get("finding"),
                message.content.get("context")
            )
        elif msg_type == "suggest_fix":
            result = await self.suggest_fix(message.content.get("finding"))
        elif msg_type == "review_fix":
            result = await self.review_fix(
                message.content.get("original_code"),
                message.content.get("fixed_code")
            )
        elif msg_type == "check_move_specific":
            result = await self.check_move_specific_issues(message.content.get("code"))
        else:
            result = {"error": f"Unknown message type: {msg_type}"}

        return AgentMessage(
            from_agent=self.role,
            to_agent=message.from_agent,
            message_type="response",
            content=result
        )

    async def verify_vulnerability(
        self,
        finding: Dict[str, Any],
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        验证漏洞发现

        从Move专家角度验证漏洞是否真实存在。

        Args:
            finding: 漏洞发现
            context: 代码上下文

        Returns:
            验证结果
        """
        context_info = context.get('code_snippet', '') if context else ''

        prompt = f"""
## 任务
请作为Move语言专家，验证以下漏洞发现是否**真实存在且可被利用**。

## 漏洞信息
- ID: {finding.get('id')}
- 标题: {finding.get('title')}
- 类型: {finding.get('category')}
- 严重性: {finding.get('severity')}
- 位置: {finding.get('location')}
- 描述: {finding.get('description')}
- 证据: {finding.get('evidence', '无')}

## 相关代码上下文
```move
{context_info}
```

## 判断标准

### 以下情况应判定为 confirmed (真实漏洞):
1. **访问控制缺失**: public fun 没有 AdminCap/OwnerCap 参数却执行敏感操作
2. **整数溢出**: u64 乘法/加法无溢出检查
3. **资源泄漏**: Coin/Balance 可能被丢弃
4. **对象权限问题**: 共享对象可被任意修改

### 以下情况应判定为 false_positive (误报):
1. 代码中已有 Capability 检查或 sender 验证
2. 函数是 public(package) / friend / entry，不对外暴露
3. Move 的类型系统已阻止该攻击

## 🔥 关键：状态变更与依赖链分析

验证漏洞时，必须分析以下内容：

### 1. 状态变更条件分析
如果漏洞涉及状态变更（如权限提升、余额修改），必须追踪：
- **触发条件是什么？** 找出代码中的 if 条件判断
- **条件值从哪里来？** 追踪数据流，从输入到条件判断的路径
- **条件是否可被操纵？** 分析是否可以通过其他漏洞影响条件

### 2. 跨函数依赖分析
- 该漏洞的利用是否需要其他漏洞配合？
- 该漏洞是否为其他更严重的攻击创造条件？
- 是否存在"漏洞 A → 条件满足 → 漏洞 B 可利用"的链条？

### 3. 算术运算追踪
如果涉及算术运算影响权限判断：
- 输入值范围是否可控？
- 运算结果是否可能异常（溢出/下溢导致意外值）？
- 异常值是否会导致权限绕过？

### 🔥 Sui Move 特定误报规则 (必须检查!):
4. **init() 函数相关漏洞都是误报**:
   - Sui 的 `init(witness: TYPE, ctx)` 由运行时保护
   - witness 类型只能在模块发布时由 Sui 运行时创建一次
   - 即使 init 被其他函数调用，外部也无法构造 witness
   - **结论**: init 的"重入/重复调用/未授权调用"漏洞 = false_positive

5. **witness 类型伪造是误报**:
   - `struct VOTE has drop {{}}` 这样的 one-time witness
   - 外部模块无法创建相同类型（类型路径不同）
   - **结论**: 声称可以伪造 witness = false_positive

6. **声称可直接调用 private 函数是误报**:
   - Sui Move 的 private 函数不能从模块外部调用
   - 即使通过 PTB (Programmable Transaction Block) 也不行
   - **结论**: 声称可直接调用 private 函数 = false_positive

## ⚠️ 重要提醒
- **宁可误报，不可漏报** - 如果不确定，判定为 confirmed
- public fun withdraw_all / set_admin 无权限检查 = **confirmed**
- Move 的线性类型不能阻止访问控制漏洞

## 输出要求
```json
{{
    "verification": {{
        "status": "confirmed|false_positive|partially_valid|needs_context",
        "confidence": 0-100,
        "reasoning": "详细说明为什么这是/不是真实漏洞"
    }},
    "move_analysis": {{
        "resource_safety": "资源安全分析",
        "ability_usage": "能力使用分析 (key/store/drop/copy)",
        "object_ownership": "对象所有权分析"
    }},
    "exploitability": {{
        "is_exploitable": true/false,
        "prerequisites": ["利用前提条件"],
        "attack_complexity": "low|medium|high",
        "potential_impact": "影响描述"
    }},
    "dependency_analysis": {{
        "state_change_trigger": "状态变更的触发条件（找出代码中的 if 条件）",
        "data_flow_trace": "关键数据流追踪（输入 → 中间函数 → 最终判断）",
        "depends_on_vulns": ["利用该漏洞需要的前置漏洞或条件"],
        "enables_vulns": ["该漏洞可以为哪些攻击创造条件"],
        "arithmetic_impact": "算术运算对权限/状态的影响分析"
    }},
    "severity_assessment": {{
        "original": "{finding.get('severity')}",
        "adjusted": "调整后的严重性",
        "adjustment_reason": "调整原因"
    }},
    "additional_findings": ["验证过程中发现的其他问题"]
}}
```
"""
        # 🔥 stateless=True: 用于 _quick_verify 并行调用
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        return self.parse_json_response(response)

    async def suggest_fix(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        提供修复建议

        Args:
            finding: 漏洞发现

        Returns:
            修复建议
        """
        prompt = f"""
## 任务
请为以下漏洞提供具体的Move代码修复建议。

## 漏洞信息
- ID: {finding.get('id')}
- 标题: {finding.get('title')}
- 类型: {finding.get('category')}
- 位置: {finding.get('location')}
- 描述: {finding.get('description')}

## 有漏洞的代码
```move
{finding.get('vulnerable_code', finding.get('evidence', ''))}
```

## 修复要求
1. 提供可直接使用的修复代码
2. 确保修复符合Move最佳实践
3. 不引入新的安全问题
4. 保持代码可读性

## 输出要求
```json
{{
    "fix_strategy": "修复策略描述",
    "fixed_code": "修复后的完整代码",
    "changes_explained": [
        {{
            "change": "具体改动",
            "reason": "改动原因"
        }}
    ],
    "verification_steps": ["验证修复有效性的步骤"],
    "potential_side_effects": ["可能的副作用"],
    "alternative_fixes": [
        {{
            "approach": "替代方案",
            "code": "替代代码",
            "tradeoffs": "权衡"
        }}
    ]
}}
```
"""
        response = await self.call_llm(prompt, json_mode=True)
        return self.parse_json_response(response)

    async def review_fix(self, original_code: str, fixed_code: str) -> Dict[str, Any]:
        """
        审查修复代码

        Args:
            original_code: 原始代码
            fixed_code: 修复后的代码

        Returns:
            审查结果
        """
        prompt = f"""
## 任务
请审查以下代码修复是否正确且完整。

## 原始代码
```move
{original_code}
```

## 修复后代码
```move
{fixed_code}
```

## 审查要点
1. 修复是否解决了原始问题
2. 修复是否引入了新的问题
3. 修复是否符合Move最佳实践
4. 代码逻辑是否正确

## 输出要求
```json
{{
    "review_result": "approved|needs_changes|rejected",
    "fixes_original_issue": true/false,
    "introduces_new_issues": true/false,
    "new_issues": ["新引入的问题（如有）"],
    "code_quality": {{
        "readability": "good|fair|poor",
        "maintainability": "good|fair|poor",
        "follows_best_practices": true/false
    }},
    "suggestions": ["改进建议"],
    "overall_assessment": "总体评估"
}}
```
"""
        response = await self.call_llm(prompt, json_mode=True)
        return self.parse_json_response(response)

    async def check_move_specific_issues(self, code: str) -> Dict[str, Any]:
        """
        检查Move特有的安全问题

        Args:
            code: Move源代码

        Returns:
            Move特定问题
        """
        prompt = f"""
## 任务
请检查以下Move代码中的Move/Sui特有安全问题。

## 代码
```move
{code[:10000]}
```

## 检查清单
1. 资源安全
   - 资源是否正确销毁或转移
   - 是否有资源泄漏风险
   - drop ability 使用是否恰当

2. 能力模式 (Capability Pattern)
   - AdminCap/OwnerCap 是否正确使用
   - 能力是否可能被滥用

3. Sui Object 模型
   - Shared Object 并发安全
   - Object 所有权转移正确性
   - Dynamic Field 使用安全

4. 特殊模式
   - Hot Potato 是否正确实现
   - Witness Pattern 使用正确性
   - One-Time Witness 安全

## 输出要求
```json
{{
    "resource_issues": [
        {{
            "issue": "问题描述",
            "location": "位置",
            "severity": "high|medium|low",
            "recommendation": "建议"
        }}
    ],
    "capability_issues": [...],
    "object_model_issues": [...],
    "pattern_issues": [...],
    "summary": {{
        "total_issues": 数量,
        "critical_issues": 数量,
        "overall_assessment": "评估"
    }}
}}
```
"""
        response = await self.call_llm(prompt, json_mode=True)
        return self.parse_json_response(response)
