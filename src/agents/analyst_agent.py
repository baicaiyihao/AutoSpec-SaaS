"""
AnalystAgent - 合约分析师Agent

职责:
1. 分析合约的整体结构和模块划分
2. 识别关键函数和数据流
3. 构建函数调用图和依赖关系
4. 提取业务逻辑和状态变更模式
5. 识别外部依赖和接口边界
"""

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent, AgentRole, AgentMessage, AgentConfig


ANALYST_ROLE_PROMPT = """你是一位Move智能合约分析专家。

## 你的职责
1. 分析合约的整体结构和模块划分
2. 识别关键函数和数据流
3. 构建函数调用图和依赖关系
4. 提取业务逻辑和状态变更模式
5. 识别外部依赖和接口边界

## 分析重点
- 资金流向: Coin/Balance 的转移路径
- 状态变更: 哪些函数修改了关键状态
- 权限模型: AdminCap, OwnerCap 等能力的使用
- 外部调用: 对其他模块/包的依赖
- 关键数据结构: Pool, Position, Order 等核心结构

## Move/Sui 特定关注点
- Object 所有权和共享模式
- Dynamic Field 的使用
- Hot Potato 模式
- 资源的创建和销毁
"""


@dataclass
class ContractAnalysis:
    """合约分析结果"""
    modules: List[Dict[str, Any]]
    functions: List[Dict[str, Any]]
    callgraph: Dict[str, List[str]]
    data_flow: List[Dict[str, Any]]
    dependencies: List[str]
    risk_indicators: List[str]


class AnalystAgent(BaseAgent):
    """合约分析师Agent"""

    def __init__(self, config: Optional[AgentConfig] = None):
        super().__init__(
            role=AgentRole.ANALYST,
            role_prompt=ANALYST_ROLE_PROMPT,
            config=config
        )

    async def process(self, message: AgentMessage) -> AgentMessage:
        """处理消息"""
        msg_type = message.content.get("type")

        if msg_type == "analyze":
            result = await self.analyze_contract(message.content.get("code"))
        elif msg_type == "build_callgraph":
            result = await self.build_callgraph(message.content.get("code"))
        elif msg_type == "assess_impact":
            result = await self.assess_impact(message.content.get("finding"))
        else:
            result = {"error": f"Unknown message type: {msg_type}"}

        return AgentMessage(
            from_agent=self.role,
            to_agent=message.from_agent,
            message_type="response",
            content=result
        )

    async def analyze_contract(self, code: str) -> Dict[str, Any]:
        """
        分析合约结构

        Args:
            code: Move源代码

        Returns:
            合约分析结果
        """
        prompt = f"""
## 任务
请对以下Move智能合约进行全面的结构分析。

## 合约代码
```move
{code[:8000]}  // 截断以避免token限制
```

## 输出要求
请输出JSON格式的分析结果:
```json
{{
    "modules": [
        {{
            "name": "模块名",
            "description": "模块功能描述",
            "structs": ["结构体列表"],
            "public_functions": ["公开函数列表"],
            "friend_functions": ["友元函数列表"]
        }}
    ],
    "key_functions": [
        {{
            "name": "函数名",
            "module": "所属模块",
            "visibility": "public|public(friend)|private",
            "purpose": "函数用途",
            "modifies_state": true/false,
            "handles_funds": true/false,
            "risk_level": "high|medium|low"
        }}
    ],
    "data_structures": [
        {{
            "name": "结构体名",
            "abilities": ["copy", "drop", "store", "key"],
            "fields": ["字段列表"],
            "purpose": "用途"
        }}
    ],
    "fund_flows": [
        {{
            "from": "来源",
            "to": "目标",
            "via_function": "通过哪个函数",
            "coin_type": "代币类型"
        }}
    ],
    "external_dependencies": ["外部依赖模块"],
    "risk_indicators": ["识别到的风险指标"]
}}
```
"""
        response = await self.call_llm(prompt, json_mode=True)
        return self.parse_json_response(response)

    async def build_callgraph(self, code: str) -> Dict[str, Any]:
        """
        构建函数调用图

        Args:
            code: Move源代码

        Returns:
            调用图
        """
        prompt = f"""
## 任务
请分析以下Move代码，构建函数调用图。

## 代码
```move
{code[:8000]}
```

## 输出要求
```json
{{
    "callgraph": {{
        "function_name": ["被调用的函数列表"]
    }},
    "entry_points": ["入口函数（public fun）"],
    "critical_paths": [
        {{
            "path": ["函数A", "函数B", "函数C"],
            "description": "路径描述",
            "risk": "涉及的风险"
        }}
    ]
}}
```
"""
        response = await self.call_llm(prompt, json_mode=True)
        return self.parse_json_response(response)

    async def assess_impact(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        评估漏洞影响

        Args:
            finding: 漏洞发现 (context 已由 retriever 智能提取，包含目标函数+调用链)

        Returns:
            影响评估
        """
        title = finding.get('title', '')
        desc = finding.get('description', '')
        # context 由 retriever 智能提取，已是精准的函数级上下文
        context = finding.get('context', '')

        prompt = f"""## 任务
评估以下漏洞的业务影响。

## 漏洞信息
- 标题: {title}
- 描述: {desc}

## 相关代码上下文
{context}

## 输出要求
请简洁回答，直接输出JSON:

```json
{{
    "business_impact": {{
        "affected_functions": ["受影响的函数名"],
        "affected_users": "受影响用户群体",
        "potential_loss": "潜在损失描述",
        "exploitability": "easy|medium|hard",
        "likelihood": "high|medium|low"
    }},
    "attack_scenario": "攻击步骤简述",
    "mitigation_priority": "critical|high|medium|low",
    "additional_risks": ["其他关联风险"]
}}
```
"""
        # 🔥 stateless=True: Phase 3 中并行调用，每次请求独立
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        return self.parse_json_response(response)

    async def extract_analysis_hints(self, code: str, callgraph_context: Optional[str] = None) -> Dict[str, Any]:
        """
        🔥 智能预分析：自动提取关键信息，指导后续漏洞分析

        提取内容：
        1. 关键状态变量（布尔标志、余额、权限相关）
        2. 条件阈值（if 语句中的数值比较）
        3. 跨函数数据流（函数 A 的输出作为函数 B 的输入）
        4. 权限判断点和触发条件

        Args:
            code: Move源代码
            callgraph_context: 可选的调用图上下文（来自上下文系统）

        Returns:
            analysis_hints: 分析提示，供后续 Agent 使用
        """
        # 如果有调用图上下文，添加到 prompt 中
        callgraph_section = ""
        if callgraph_context:
            callgraph_section = f"""
{callgraph_context}

**请特别关注上述高风险函数和资金相关函数，分析它们之间的依赖关系！**
"""

        prompt = f"""
## 任务
你是一位安全分析预处理专家。请分析以下 Move 代码，提取关键信息帮助后续的漏洞分析 Agent 更好地理解代码。
{callgraph_section}
## 代码
```move
{code[:15000]}
```

## 提取要求

### 1. 关键状态变量
找出所有可能影响安全的状态变量：
- 布尔标志（如 is_authorized, is_paused, is_active）
- 余额/数量变量（如 balance, total_supply, amount）
- 权限相关（如 admin, owner, operator 地址）
- 配置参数（如 fee_rate, threshold, limit）

### 2. 条件阈值
找出代码中的条件判断，特别是：
- 数值比较（if x > 1000, if balance >= amount）
- 权限检查（if sender == admin）
- 状态检查（if is_authorized == true）
**提取实际的阈值数值和条件表达式**

### 3. 跨函数数据流
分析函数之间的数据依赖：
- 函数 A 的返回值被函数 B 使用
- 函数 A 修改的状态被函数 B 读取
- 算术运算结果影响后续的权限判断
**用箭头表示数据流向**

### 4. 权限/状态变更点
找出所有会修改关键状态的代码位置：
- 权限提升（设置 admin, 授权用户）
- 状态开关（设置 is_authorized = true）
- 余额修改（增加/减少 balance）
**记录触发条件和所在函数**

### 5. 潜在漏洞链
基于上述分析，推测可能的漏洞组合：
- 哪些漏洞可能为其他漏洞创造条件
- 哪些小问题组合后可能变成大问题

## 输出格式
```json
{{
    "key_state_variables": [
        {{
            "name": "变量名",
            "type": "bool|u64|address|...",
            "location": "所在 struct 或函数",
            "security_relevance": "为什么这个变量重要（权限控制/资金相关/...）"
        }}
    ],
    "condition_thresholds": [
        {{
            "condition": "从代码复制的完整条件表达式",
            "location": "函数名:行号",
            "threshold_value": "阈值数值（如果有）",
            "security_implication": "这个条件判断的安全含义"
        }}
    ],
    "cross_function_dataflow": [
        {{
            "flow": "函数A.output → 函数B.input → 函数C.condition",
            "description": "数据如何流动",
            "security_concern": "这个数据流可能带来什么风险"
        }}
    ],
    "state_change_points": [
        {{
            "variable": "被修改的变量",
            "function": "修改发生的函数",
            "trigger_condition": "触发修改的条件（从代码复制）",
            "security_implication": "这个状态变更的安全含义"
        }}
    ],
    "potential_vuln_chains": [
        {{
            "chain": "漏洞A → 条件满足 → 漏洞B → 最终影响",
            "involved_functions": ["相关函数列表"],
            "description": "为什么这些漏洞可能形成链条"
        }}
    ],
    "analysis_summary": "一段话总结这个合约的关键安全关注点"
}}
```

## 重要提示
- **从代码中复制真实的变量名、函数名、条件表达式**
- 不要编造不存在的内容
- 重点关注可能被攻击者利用的点
"""
        response = await self.call_llm(prompt, json_mode=True)
        return self.parse_json_response(response)

    async def analyze_function_purposes(
        self,
        functions: List[Dict],
        code: str,
        batch_size: int = 5,
        max_concurrent: int = 3
    ) -> Dict[str, str]:
        """
        并行分析函数功能（适用于大型项目如 Cetus）

        Args:
            functions: 函数列表，每个函数包含 {id, name, module, signature, ...}
            code: 完整的 Move 源代码
            batch_size: 每批分析的函数数量
            max_concurrent: 最大并发数

        Returns:
            {function_id: "这个函数做什么的描述"}
        """
        # 小项目直接单次调用
        if len(functions) <= batch_size:
            return await self._analyze_batch(functions, code)

        # 大项目：分批并行处理
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_with_semaphore(batch: List[Dict]) -> Dict[str, str]:
            async with semaphore:
                return await self._analyze_batch(batch, code)

        # 分批
        batches = [functions[i:i+batch_size] for i in range(0, len(functions), batch_size)]
        print(f"    函数分析: {len(functions)} 个函数，分 {len(batches)} 批并行处理")

        # 并行执行
        batch_results = await asyncio.gather(
            *[analyze_with_semaphore(b) for b in batches],
            return_exceptions=True
        )

        # 合并结果
        for i, batch_result in enumerate(batch_results):
            if isinstance(batch_result, Exception):
                print(f"    ⚠️ 批次 {i+1} 分析失败: {batch_result}")
                continue
            if isinstance(batch_result, dict):
                results.update(batch_result)

        return results

    async def _analyze_batch(self, functions: List[Dict], code: str) -> Dict[str, str]:
        """分析单批函数"""
        func_list = []
        for f in functions:
            func_id = f.get('id', f.get('name', ''))
            sig = f.get('signature', f.get('name', ''))
            func_list.append(f"- {func_id}: {sig}")

        func_list_str = "\n".join(func_list)

        prompt = f"""## 任务
请分析以下 Move 合约代码，为每个函数提供简洁的功能描述。

## 函数列表
{func_list_str}

## 代码
```move
{code[:15000]}
```

## 输出要求
请用一句话描述每个函数的功能，重点说明：
- 这个函数是做什么的（核心业务逻辑）
- 它会修改什么状态或返回什么
- 是否涉及权限检查、资金转移等关键操作

输出 JSON 格式：
```json
{{
    "function_id_1": "简洁的功能描述",
    "function_id_2": "简洁的功能描述"
}}
```

## 示例输出风格
- "初始化模块配置，创建共享对象"
- "用户存款，将 Coin 转入池子并记录余额"
- "检查管理员权限后更新手续费率"
- "计算用户份额，无权限检查"
- "闪电贷核心逻辑，借出资金并返回还款凭证"
"""
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        result = self.parse_json_response(response)

        if isinstance(result, dict):
            return result
        return {}
