"""
ReviewAgent - 交互式 Review Agent (v2.6.0)

结合 Phase 3 (VerifierAgent) 和 Phase 4 (WhiteHatAgent) 的能力，
支持与用户进行多轮对话式安全分析。

能力:
1. 多轮对话 - 用户可以自由提问，Agent 记住上下文
2. 工具辅助 - 自动检索代码、调用图、类型定义
3. 安全知识 - 注入 Move 语言安全知识，防误报分析
4. RAG 检索 - 搜索历史漏洞模式，提供类似案例
5. 多视角分析 - 安全审计/Move专家/业务分析 三重视角
6. 漏洞利用推理 - 分析攻击链可行性
"""

import asyncio
import json
import logging
import queue
from typing import Any, Callable, Dict, List, Optional

from .base_agent import BaseAgent, AgentRole, AgentMessage, AgentConfig
from .move_knowledge import get_relevant_knowledge

try:
    from src.prompts.sui_move_security_knowledge import (
        is_likely_false_positive,
    )
except ImportError:
    def is_likely_false_positive(vtype, desc):
        return False, ""

logger = logging.getLogger(__name__)


# =============================================================================
# System Prompt
# =============================================================================

REVIEW_AGENT_SYSTEM_PROMPT = """你是一位资深的 Sui Move 智能合约安全审计专家，正在与用户进行交互式 Review 对话。

## 你的职责
1. **分析漏洞真实性** - 判断漏洞是否为误报（False Positive），给出明确结论和依据
2. **评估严重性** - 分析漏洞严重性是否合理，提供调整建议
3. **代码分析** - 主动使用工具检索相关代码，为结论提供证据
4. **攻击链推理** - 分析漏洞的可利用性和攻击路径
5. **回答问题** - 回答用户关于代码、漏洞、Move 安全的任何问题

## 分析方法论 (三重视角)

### 安全审计视角
- 是否违反安全最佳实践？
- 是否匹配已知漏洞模式？
- 类似项目是否出现过此类问题？

### Move 技术专家视角
- Move 类型系统是否已经阻止了该漏洞？
- Sui 对象所有权模型是否提供了保护？
- 线性资源/能力系统是否消除了风险？

### 业务分析视角
- 攻击的经济可行性如何？成本/收益比？
- 攻击者需要什么前置条件？现实中是否可达？
- 对协议和用户的实际影响范围？

## Move/Sui 内置安全保护 (误报常见原因)

以下情况通常是误报：
- **算术溢出/下溢**: Move VM 在 +/-/*/% 运算溢出时自动 abort (位移 << >> 除外)
- **重入攻击**: Move 无动态调度，不可能重入
- **类型混淆**: Move 泛型类型系统在编译时检查
- **双花**: 线性资源只能 move 不能 copy
- **越界访问**: vector 自动边界检查
- **未初始化**: Move 要求所有变量初始化

以下情况需要特别注意 (不是误报):
- **位移溢出**: << 和 >> 不会 abort，可能静默溢出 (Cetus $223M 漏洞根因)
- **精度损失**: 除法精度损失不受 VM 保护
- **能力滥用**: copy/drop 能力赋予不当可能导致资产复制
- **共享对象竞争**: 多方同时操作 shared object
- **类型参数攻击**: 泛型参数可能被传入恶意类型

## 工具使用
你可以使用以下工具来检索代码和安全信息：
- `get_function_code(module, function)`: 获取函数实现
- `get_function_context(module, function)`: 函数 + 调用者 + 被调用者
- `get_callers(module, function)`: 谁调用了该函数
- `get_callees(module, function)`: 该函数调用了什么
- `get_type_definition(type_name)`: struct 类型定义
- `search_code(pattern)`: 在项目代码中搜索
- `get_module_structure(module)`: 模块结构概览
- `query_security_knowledge(topic)`: 查询 Move 安全知识库
- `search_vulnerability_patterns(query)`: 搜索历史漏洞案例 (RAG)
- `get_exploit_examples(vuln_type)`: 获取漏洞利用示例

## 回复规范
- 用中文回答
- 分析要具体、有代码引用
- 给出明确结论（是/否 误报），不要模棱两可
- 使用工具获取代码作为证据，不要凭空猜测
- 对用户的追问保持上下文连贯
"""


# =============================================================================
# ReviewAgent
# =============================================================================

class ReviewAgent(BaseAgent):
    """
    交互式 Review Agent - 结合 Phase 3/4 能力的对话式安全分析

    Usage:
        config = AgentConfig(provider="dashscope", model="qwen-plus")
        agent = ReviewAgent(config=config)
        agent.set_toolkit(toolkit)
        agent.set_finding_context(finding)

        response = agent.chat_sync("这个漏洞是否为误报？", history)
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(
                provider="dashscope",
                model="qwen-plus",
                temperature=0.3,
                max_tokens=32768,
                timeout=120,
            )

        super().__init__(
            role=AgentRole.ANALYST,
            role_prompt=REVIEW_AGENT_SYSTEM_PROMPT,
            config=config
        )
        self._actual_role = "reviewer"
        self._current_finding: Optional[Dict] = None
        self._finding_knowledge: str = ""
        self._progress_queue: Optional[queue.Queue] = None

    def set_progress_queue(self, q: Optional[queue.Queue]):
        """设置进度事件队列 (用于 SSE 流式响应)"""
        self._progress_queue = q

    def _emit_progress(self, event_type: str, content: str, **kwargs):
        """发送进度事件到队列"""
        if self._progress_queue:
            event = {"type": event_type, "content": content, **kwargs}
            self._progress_queue.put(event)

    async def call_llm_with_tools(
        self,
        prompt: str,
        tools: Optional[List[Dict]] = None,
        system_prompt: Optional[str] = None,
        max_tool_rounds: int = 5,
        json_mode: bool = False
    ) -> str:
        """带进度事件的工具调用循环"""
        if not self.toolkit or not tools:
            self._emit_progress("thinking", "正在分析...")
            result = await self.call_llm(prompt, system_prompt, json_mode, stateless=True)
            self._emit_progress("complete", "分析完成")
            return result

        system = system_prompt or self.role_prompt
        if json_mode:
            system += "\n\n请以JSON格式输出最终结果。"

        system += """

## 🚨 工具调用说明
如果你需要调用工具获取更多代码，请在调用工具的同时，用一两句话说明你的分析思路和为什么需要这些信息。
注意：直接使用工具调用功能，不要把 "content:" 或 "tool_calls:" 作为文本输出。"""

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}
        ]

        tool_result_cache: Dict[str, str] = {}
        self._emit_progress("thinking", "正在思考分析策略...")

        for round_num in range(max_tool_rounds):
            async with self._llm_lock:
                response = await asyncio.to_thread(
                    self._llm_provider.chat,
                    messages,
                    tools=tools
                )

            if hasattr(response, 'usage') and response.usage:
                self._track_token_usage(response.usage)

            if response.tool_calls:
                # 发送 AI 思考进度
                if response.content and response.content.strip():
                    self._emit_progress("thinking", response.content.strip()[:200])

                # 发送工具调用进度
                tool_descriptions = []
                for tc in response.tool_calls:
                    args = tc.arguments
                    if tc.name == "get_function_code":
                        desc = f"获取函数: {args.get('module', '?')}::{args.get('function', '?')}"
                    elif tc.name == "get_function_context":
                        desc = f"分析函数上下文: {args.get('module', '?')}::{args.get('function', '?')}"
                    elif tc.name == "get_callers":
                        desc = f"查找调用者: {args.get('function', '?')}"
                    elif tc.name == "get_callees":
                        desc = f"追踪调用链: {args.get('function', '?')}"
                    elif tc.name == "get_type_definition":
                        desc = f"查看类型定义: {args.get('type_name', '?')}"
                    elif tc.name == "search_code":
                        desc = f"搜索代码: {args.get('pattern', '?')}"
                    elif tc.name == "get_module_structure":
                        desc = f"分析模块结构: {args.get('module_name', '?')}"
                    elif tc.name == "query_security_knowledge":
                        desc = f"查询安全知识: {args.get('topic', '?')}"
                    elif tc.name == "search_vulnerability_patterns":
                        desc = f"搜索漏洞模式: {args.get('query', '?')}"
                    elif tc.name == "get_exploit_examples":
                        desc = f"获取利用示例: {args.get('vuln_type', '?')}"
                    else:
                        desc = f"调用工具: {tc.name}"
                    tool_descriptions.append(desc)

                self._emit_progress("tool_call", "; ".join(tool_descriptions),
                                    round=round_num + 1, total_rounds=max_tool_rounds)

                # 执行工具调用 (与 BaseAgent 相同逻辑)
                new_tool_calls = []
                cached_tool_calls = []
                for tc in response.tool_calls:
                    tool_key = f"{tc.name}:{json.dumps(tc.arguments, sort_keys=True)}"
                    if tool_key in tool_result_cache:
                        cached_tool_calls.append((tc, tool_key))
                    else:
                        new_tool_calls.append((tc, tool_key))

                if not new_tool_calls and cached_tool_calls:
                    messages.append({
                        "role": "assistant",
                        "content": response.content or "",
                        "tool_calls": [
                            {"id": tc.id, "name": tc.name, "args": tc.arguments}
                            for tc, _ in cached_tool_calls
                        ]
                    })
                    for tc, tool_key in cached_tool_calls:
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": tool_result_cache[tool_key]
                        })
                    continue

                all_tool_calls = new_tool_calls + cached_tool_calls
                messages.append({
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": [
                        {"id": tc.id, "name": tc.name, "args": tc.arguments}
                        for tc, _ in all_tool_calls
                    ]
                })

                for tc, tool_key in all_tool_calls:
                    if tool_key in tool_result_cache:
                        tool_output = tool_result_cache[tool_key]
                    else:
                        result = self.toolkit.call_tool(tc.name, tc.arguments, caller=self.role.value)
                        if result.success:
                            tool_output = json.dumps(result.data, ensure_ascii=False, default=str)
                        else:
                            tool_output = f"错误: {result.error}"
                        tool_result_cache[tool_key] = tool_output

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": tool_output
                    })
            else:
                # AI 不再调用工具，返回最终响应
                self._emit_progress("complete", "分析完成")
                return response.content

        # 达到最大轮次
        self._emit_progress("thinking", "正在整合分析结果...")
        messages.append({
            "role": "user",
            "content": "请停止工具调用。基于你已经收集到的所有代码信息，立即输出最终的分析结果。" +
                      ("\n请确保输出符合 JSON 格式。" if json_mode else "")
        })

        try:
            async with self._llm_lock:
                final_response = await asyncio.to_thread(
                    self._llm_provider.chat,
                    messages
                )
            if hasattr(final_response, 'usage') and final_response.usage:
                self._track_token_usage(final_response.usage)
            self._emit_progress("complete", "分析完成")
            return final_response.content
        except Exception as e:
            self._emit_progress("error", f"分析出错: {str(e)}")
            return response.content if response else ""

    def set_finding_context(self, finding: Optional[Dict]):
        """
        设置当前聚焦的漏洞上下文

        Args:
            finding: 漏洞信息 dict (包含 title, severity, description, code_snippet 等)
        """
        self._current_finding = finding
        if finding:
            self._finding_knowledge = get_relevant_knowledge(finding)
        else:
            self._finding_knowledge = ""

    def _build_chat_prompt(self, message: str, history: List[Dict[str, str]]) -> str:
        """构建完整的对话 prompt"""
        parts = []

        # 漏洞上下文
        if self._current_finding:
            finding = self._current_finding
            parts.append("--- 当前聚焦漏洞 ---")
            parts.append(f"标题: {finding.get('title', '未知')}")
            parts.append(f"严重性: {finding.get('severity', '未知')}")
            parts.append(f"状态: {finding.get('status', 'open')}")
            if finding.get('category'):
                parts.append(f"分类: {finding['category']}")
            parts.append(f"描述: {finding.get('description', '无')}")

            if finding.get('location'):
                loc = finding['location']
                parts.append(f"位置: {loc.get('file', '')}:{loc.get('line_start', '')}-{loc.get('line_end', '')}")

            if finding.get('code_snippet'):
                parts.append(f"\n漏洞代码:\n```move\n{finding['code_snippet']}\n```")

            if finding.get('proof'):
                parts.append(f"\n漏洞证明: {finding['proof']}")

            if finding.get('attack_scenario'):
                parts.append(f"\n攻击场景: {finding['attack_scenario']}")

            if finding.get('recommendation'):
                parts.append(f"\n修复建议: {finding['recommendation']}")

            # Move 安全知识注入
            if self._finding_knowledge:
                parts.append(f"\n--- Move 安全知识参考 ---\n{self._finding_knowledge}")

            # 误报预判
            vuln_type = finding.get('category', finding.get('title', ''))
            description = finding.get('description', '')
            is_fp, fp_reason = is_likely_false_positive(vuln_type, description)
            if is_fp:
                parts.append(f"\n⚠️ 知识库预判: 该漏洞可能是误报 - {fp_reason}")

            parts.append("---\n")

        # 对话历史
        if history:
            parts.append("--- 对话历史 ---")
            # 只保留最近 10 轮 (20 条消息)
            recent = history[-20:]
            for msg in recent:
                role_label = "用户" if msg["role"] == "user" else "AI"
                parts.append(f"{role_label}: {msg['content']}")
            parts.append("---\n")

        # 当前用户消息
        parts.append(f"用户提问: {message}")
        parts.append("\n请根据上述漏洞信息和对话历史，回答用户的问题。如需更多代码信息，请使用工具检索。")

        return "\n".join(parts)

    def _get_review_tools(self) -> List[Dict[str, Any]]:
        """获取 Review 可用的工具列表"""
        if not self.toolkit:
            return []

        # 使用 AgentToolkit 的安全工具子集
        review_tool_names = [
            "get_function_code",
            "get_function_context",
            "get_callers",
            "get_callees",
            "get_type_definition",
            "search_code",
            "get_module_structure",
            "query_security_knowledge",
            "search_vulnerability_patterns",
            "get_exploit_examples",
        ]
        return self.toolkit.get_tools_for_llm(tool_names=review_tool_names)

    def chat_sync(
        self,
        message: str,
        history: List[Dict[str, str]],
    ) -> str:
        """
        同步聊天接口 (用于 asyncio.to_thread 调用)

        Args:
            message: 用户消息
            history: 对话历史 [{"role": "user/assistant", "content": "..."}]

        Returns:
            AI 回复文本
        """
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.chat(message, history))
        finally:
            loop.close()

    async def chat(
        self,
        message: str,
        history: List[Dict[str, str]],
    ) -> str:
        """
        异步聊天接口

        Args:
            message: 用户消息
            history: 对话历史

        Returns:
            AI 回复文本
        """
        # 构建 prompt
        prompt = self._build_chat_prompt(message, history)

        # 获取工具
        tools = self._get_review_tools()

        # 构建系统提示词 (含知识注入)
        system_prompt = REVIEW_AGENT_SYSTEM_PROMPT
        if self._finding_knowledge:
            system_prompt += f"\n\n## 针对当前漏洞的 Move 安全知识\n{self._finding_knowledge}"

        if tools:
            # 使用工具辅助分析
            try:
                response = await self.call_llm_with_tools(
                    prompt=prompt,
                    tools=tools,
                    system_prompt=system_prompt,
                    max_tool_rounds=5,
                    json_mode=False
                )
                return response
            except Exception as e:
                logger.error(f"Tool-assisted chat failed: {e}, falling back to plain chat")
                # Fallback 到普通聊天
                return await self.call_llm(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    stateless=True
                )
        else:
            # 无工具，直接聊天
            return await self.call_llm(
                prompt=prompt,
                system_prompt=system_prompt,
                stateless=True
            )

    async def process(self, message: AgentMessage) -> AgentMessage:
        """BaseAgent 抽象方法实现 (Review 场景不使用 Agent 间通信)"""
        return AgentMessage(
            from_agent=self.role,
            to_agent=message.from_agent,
            message_type="response",
            content={"status": "not_implemented"}
        )
