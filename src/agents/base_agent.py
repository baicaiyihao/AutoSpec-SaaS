"""
BaseAgent - Agent基类

所有Agent的基类，定义通用接口和LLM调用逻辑。

支持多模型配置:
- 通过AgentConfig指定provider和model
- 支持OpenAI, Anthropic, Google, DeepSeek, ZhipuAI, DashScope, Ollama
- 支持fallback机制
"""

import asyncio
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from enum import Enum

from src.utils.json_parser import robust_parse_json

# 导入工具类型
from typing import Callable

# 导入多模型系统
from src.llm_providers import (
    BaseLLMProvider,
    LLMProviderFactory,
    LLMConfig,
    ProviderType
)


class AgentRole(Enum):
    """Agent角色枚举"""
    MANAGER = "manager"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    EXPERT = "expert"


@dataclass
class AgentMessage:
    """Agent间通信消息"""
    from_agent: AgentRole
    to_agent: AgentRole
    message_type: str  # "request" | "response" | "broadcast"
    content: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentConfig:
    """
    Agent配置

    支持两种模式:
    1. 传统模式 (model_name): 使用DashScope
    2. 多模型模式 (provider + model): 使用指定的Provider
    """
    # 传统配置 (向后兼容)
    model_name: str = "qwen-max"

    # 多模型配置
    provider: Optional[str] = None  # "openai", "anthropic", "deepseek", etc.
    model: Optional[str] = None     # 具体模型名

    # 通用配置
    temperature: float = 0.1
    max_tokens: int = 4096
    max_retries: int = 3
    timeout: int = 120

    # Fallback配置
    fallback_provider: Optional[str] = None
    fallback_model: Optional[str] = None

    # API配置 (可选，否则从环境变量读取)
    api_key: Optional[str] = None
    base_url: Optional[str] = None


class BaseAgent(ABC):
    """
    Agent基类

    所有Agent继承此类，实现特定的分析逻辑。

    多模型使用示例:
    ```python
    # 使用Claude
    config = AgentConfig(provider="anthropic", model="claude-sonnet-4-20250514")
    agent = MyAgent(config=config)

    # 使用DeepSeek
    config = AgentConfig(provider="deepseek", model="deepseek-chat")
    agent = MyAgent(config=config)

    # 使用GLM-4
    config = AgentConfig(provider="zhipu", model="glm-4-plus")
    agent = MyAgent(config=config)
    ```
    """

    def __init__(
        self,
        role: AgentRole,
        role_prompt: str,
        config: Optional[AgentConfig] = None
    ):
        self.role = role
        self.role_prompt = role_prompt
        self.config = config or AgentConfig()

        # 初始化LLM
        self._llm_provider: Optional[BaseLLMProvider] = None
        self._init_llm()

        # 🔥 LLM 调用锁 - 防止同一实例并发调用 provider
        self._llm_lock = asyncio.Lock()

        # 对话历史
        self.conversation_history: List[Dict[str, str]] = []

        # Agent状态
        self.state: Dict[str, Any] = {}

        # 🔥 工具箱 (可选，用于自主检索)
        self.toolkit: Optional[Any] = None  # AgentToolkit 实例

        # 🔥 v2.5.8: Token 使用量统计
        self._token_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "call_count": 0
        }

    def set_toolkit(self, toolkit: Any):
        """
        设置工具箱，让 Agent 能够自主调用工具检索信息

        Args:
            toolkit: AgentToolkit 实例
        """
        self.toolkit = toolkit

    def retrieve_context_for_finding(
        self,
        finding: Dict[str, Any],
        include_callers: bool = True,
        include_callees: bool = True,
        caller_depth: int = 2,
        callee_depth: int = 2
    ) -> Dict[str, Any]:
        """
        🔥 根据 finding 的 location 自动检索相关代码上下文

        替代直接传入整个源代码，让 Agent 只获取与漏洞相关的代码片段。

        Args:
            finding: 漏洞发现，需包含 location: {module, function}
            include_callers: 是否包含调用者
            include_callees: 是否包含被调用者
            caller_depth: 调用者检索深度
            callee_depth: 被调用者检索深度

        Returns:
            {
                "target_function": {...},   # 目标函数代码
                "callers": [...],           # 调用者列表
                "callees": [...],           # 被调用者列表
                "types": [...],             # 相关类型定义
                "context_summary": "..."    # 格式化的上下文摘要
            }
        """
        if not self.toolkit:
            return {"error": "No toolkit available", "context_summary": ""}

        location = finding.get("location", {})
        module = location.get("module", "")
        function = location.get("function", "")

        if not module or not function:
            # 尝试从 title 或 description 提取
            title = finding.get("title", "")
            desc = finding.get("description", "")
            # 简单提取：找 module::function 模式
            import re
            match = re.search(r'(\w+)::(\w+)', f"{title} {desc}")
            if match:
                module, function = match.groups()

        if not function:
            return {"error": "Cannot determine function location", "context_summary": ""}

        result = {
            "target_function": None,
            "callers": [],
            "callees": [],
            "types": [],
            "context_summary": ""
        }

        context_parts = []
        caller_tag = self.role.value  # 使用 agent 角色作为调用者标识

        # 1. 获取目标函数代码
        func_result = self.toolkit.call_tool("get_function_code", {
            "module": module,
            "function": function
        }, caller=caller_tag)
        if func_result.success:
            result["target_function"] = func_result.data
            body = func_result.data.get("body", "")
            sig = func_result.data.get("signature", "")
            context_parts.append(f"## 目标函数: {module}::{function}\n```move\n{body}\n```")

            # 从函数体提取可能的类型名
            type_matches = re.findall(r'(\w+(?:Pool|Vault|Position|Config|Cap|Info|State))', body)
            for type_name in set(type_matches):
                type_result = self.toolkit.call_tool("get_type_definition", {"type_name": type_name}, caller=caller_tag)
                if type_result.success:
                    result["types"].append(type_result.data)

        # 2. 获取调用者
        if include_callers:
            callers_result = self.toolkit.call_tool("get_callers", {
                "module": module,
                "function": function,
                "depth": caller_depth
            }, caller=caller_tag)
            if callers_result.success:
                callers = callers_result.data.get("callers", [])
                result["callers"] = callers
                if callers:
                    caller_names = [c.get("id", c.get("name", "?")) for c in callers[:5]]
                    context_parts.append(f"## 调用者 ({len(callers)} 个)\n" + "\n".join(f"- {n}" for n in caller_names))

        # 3. 获取被调用者
        if include_callees:
            callees_result = self.toolkit.call_tool("get_callees", {
                "module": module,
                "function": function,
                "depth": callee_depth
            }, caller=caller_tag)
            if callees_result.success:
                callees = callees_result.data.get("callees", [])
                result["callees"] = callees
                if callees:
                    callee_names = [c.get("id", c.get("name", "?")) for c in callees[:5]]
                    context_parts.append(f"## 被调用者 ({len(callees)} 个)\n" + "\n".join(f"- {n}" for n in callee_names))

                    # 获取关键被调用者的代码
                    for callee in callees[:3]:
                        callee_id = callee.get("id", "")
                        if "::" in callee_id:
                            parts = callee_id.split("::")
                            callee_func = parts[-1]
                            callee_mod = "::".join(parts[:-1])
                            callee_code = self.toolkit.call_tool("get_function_code", {
                                "module": callee_mod,
                                "function": callee_func
                            }, caller=caller_tag)
                            if callee_code.success:
                                body = callee_code.data.get("body", "")[:500]
                                context_parts.append(f"### {callee_id}\n```move\n{body}\n```")

        # 4. 获取类型定义
        if result["types"]:
            types_str = "\n".join([
                f"### {t.get('name', '?')}\n```move\n{t.get('body', '')}\n```"
                for t in result["types"][:3]
            ])
            context_parts.append(f"## 相关类型定义\n{types_str}")

        result["context_summary"] = "\n\n".join(context_parts)
        return result

    def _init_llm(self):
        """初始化LLM Provider (使用 config 中的配置)"""
        provider_type = ProviderType(self.config.provider.lower())
        llm_config = LLMConfig(
            provider=provider_type,
            model=self.config.model or self.config.model_name,
            api_key=self.config.api_key,
            base_url=self.config.base_url,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            timeout=self.config.timeout
        )
        self._llm_provider = LLMProviderFactory.create(llm_config)

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

    @abstractmethod
    async def process(self, message: AgentMessage) -> AgentMessage:
        """
        处理接收到的消息

        Args:
            message: 输入消息

        Returns:
            响应消息
        """
        pass

    async def call_llm(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        stateless: bool = False
    ) -> str:
        """
        调用LLM

        Args:
            prompt: 用户提示
            system_prompt: 系统提示 (默认使用角色提示)
            json_mode: 是否要求JSON输出
            stateless: 无状态模式 (不使用/不保存对话历史，适合并行调用)

        Returns:
            LLM响应文本
        """
        system = system_prompt or self.role_prompt

        if json_mode:
            system += "\n\n请以JSON格式输出结果。"

        # 🔥 stateless 模式不使用对话历史 (用于并行调用)
        if stateless:
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
        else:
            messages = [
                {"role": "system", "content": system},
                *self.conversation_history,
                {"role": "user", "content": prompt}
            ]

        # 带重试的 LLM 调用 (处理 429 rate limit)
        # 🔥 增强重试: 更多次数 + 更长退避 + 随机抖动
        import random
        max_retries = max(self.config.max_retries, 5)  # 至少5次重试
        base_delay = 3.0  # 基础延迟3秒
        max_delay = 30.0  # 最大延迟30秒

        for attempt in range(max_retries):
            try:
                # 🔥 stateless 模式不需要锁（不写 conversation_history，可以真正并发）
                # 只有 stateful 模式才需要锁保护 conversation_history
                async def _do_llm_call():
                    if self._llm_provider is not None:
                        response = await asyncio.to_thread(self._llm_provider.chat, messages)
                        # 🔥 v2.5.8: 追踪 token 使用量
                        if hasattr(response, 'usage') and response.usage:
                            self._track_token_usage(response.usage)
                        return response.content
                    else:
                        response = await asyncio.to_thread(self.llm.invoke, messages)
                        return response.content if hasattr(response, 'content') else str(response)

                if stateless:
                    # 🔥 stateless 模式：无锁并发
                    result = await _do_llm_call()
                else:
                    # stateful 模式：加锁保护 conversation_history
                    async with self._llm_lock:
                        result = await _do_llm_call()
                    self.conversation_history.append({"role": "user", "content": prompt})
                    self.conversation_history.append({"role": "assistant", "content": result})

                return result

            except Exception as e:
                error_str = str(e)
                # 检查是否是 429 rate limit 错误
                if "429" in error_str or "rate" in error_str.lower() or "1302" in error_str:
                    if attempt < max_retries - 1:
                        # 🔥 指数退避 + 随机抖动 (避免多Agent同时重试)
                        delay = min(base_delay * (2 ** attempt), max_delay)
                        jitter = random.uniform(0.5, 1.5)  # 0.5x ~ 1.5x 随机因子
                        actual_delay = delay * jitter
                        print(f"[{self.role.value}] ⏳ API 限流，{actual_delay:.1f}s 后重试 ({attempt + 1}/{max_retries})...")
                        await asyncio.sleep(actual_delay)
                        continue

                print(f"[{self.role.value}] LLM调用失败: {e}")
                raise

        # 所有重试都失败
        raise Exception(f"[{self.role.value}] API 限流，{max_retries}次重试均失败")

    async def call_llm_with_tools(
        self,
        prompt: str,
        tools: Optional[List[Dict]] = None,
        system_prompt: Optional[str] = None,
        max_tool_rounds: int = 5,  # 🔥 v2.5.14: 降低默认值
        json_mode: bool = False
    ) -> str:
        """
        🔥 带工具调用循环的 LLM 调用

        AI 可以自主决定调用哪些工具，获取结果后继续分析，
        直到 AI 认为分析完成（不再调用工具）。

        Args:
            prompt: 用户提示
            tools: 工具定义列表 (OpenAI 格式)
            system_prompt: 系统提示
            max_tool_rounds: 最大工具调用轮次
            json_mode: 最终输出是否要求 JSON 格式

        Returns:
            AI 最终响应文本
        """
        if not self.toolkit or not tools:
            # 无工具，退化为普通调用
            return await self.call_llm(prompt, system_prompt, json_mode, stateless=True)

        system = system_prompt or self.role_prompt
        if json_mode:
            system += "\n\n请以JSON格式输出最终结果。"

        # 🔥 要求 LLM 在调用工具前先输出分析思路
        system += """

## 🚨 工具调用说明
如果你需要调用工具获取更多代码，请在调用工具的同时，用一两句话说明你的分析思路和为什么需要这些信息。
注意：直接使用工具调用功能，不要把 "content:" 或 "tool_calls:" 作为文本输出。"""

        # 构建消息列表
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}
        ]

        # 🔥 v2.5.5: 工具结果缓存 (key -> result)
        # 重复调用时返回缓存结果而不是跳过
        tool_result_cache: Dict[str, str] = {}

        # 工具调用循环
        for round_num in range(max_tool_rounds):
            # 调用 LLM
            async with self._llm_lock:
                response = await asyncio.to_thread(
                    self._llm_provider.chat,
                    messages,
                    tools=tools
                )

            # 🔥 v2.5.8: 追踪 token 使用量
            if hasattr(response, 'usage') and response.usage:
                self._track_token_usage(response.usage)

            # 检查是否有工具调用
            if response.tool_calls:
                # 🔥 显示 AI 的分析思考过程 (在调用工具之前)
                if response.content and response.content.strip():
                    thinking = response.content.strip()
                    if len(thinking) > 200:
                        thinking_summary = thinking[:200] + "..."
                    else:
                        thinking_summary = thinking
                    print(f"    💭 [{self.role.value}] AI 分析: {thinking_summary}")
                else:
                    # 🔥 如果 content 为空，根据工具调用推断意图
                    intent_parts = []
                    for tc in response.tool_calls[:3]:
                        args = tc.arguments
                        if tc.name == "get_function_code":
                            intent_parts.append(f"查看 {args.get('function', '?')}")
                        elif tc.name == "get_callers":
                            intent_parts.append(f"查找 {args.get('function', '?')} 入口")
                        elif tc.name == "get_callees":
                            intent_parts.append(f"追踪 {args.get('function', '?')} 调用链")
                        elif tc.name == "get_type_definition":
                            intent_parts.append(f"查看 {args.get('type_name', '?')} 类型")
                    if intent_parts:
                        print(f"    💭 [{self.role.value}] 意图: {', '.join(intent_parts)}")

                print(f"    🔧 [{self.role.value}] Round {round_num + 1}: AI 请求调用 {len(response.tool_calls)} 个工具")

                # 🔥 v2.5.4: 分离新调用和缓存命中
                new_tool_calls = []
                cached_tool_calls = []
                for tc in response.tool_calls:
                    tool_key = f"{tc.name}:{json.dumps(tc.arguments, sort_keys=True)}"
                    if tool_key in tool_result_cache:
                        cached_tool_calls.append((tc, tool_key))
                    else:
                        new_tool_calls.append((tc, tool_key))

                if cached_tool_calls:
                    print(f"       📌 缓存命中: {len(cached_tool_calls)} 个 (跳过重复执行)")

                # 如果全部命中缓存，注入缓存结果并继续
                if not new_tool_calls and cached_tool_calls:
                    # 添加 AI 消息
                    messages.append({
                        "role": "assistant",
                        "content": response.content or "",
                        "tool_calls": [
                            {"id": tc.id, "name": tc.name, "args": tc.arguments}
                            for tc, _ in cached_tool_calls
                        ]
                    })
                    # 注入缓存结果 (v2.5.5: 移除 [缓存] 前缀，避免干扰 LLM 解析)
                    for tc, tool_key in cached_tool_calls:
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": tool_result_cache[tool_key]
                        })
                    print(f"    ⚠️ [{self.role.value}] 全部缓存命中，注入历史结果继续...")
                    continue

                # 添加 AI 消息（包含所有 tool_calls）
                all_tool_calls = new_tool_calls + cached_tool_calls
                messages.append({
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": [
                        {"id": tc.id, "name": tc.name, "args": tc.arguments}
                        for tc, _ in all_tool_calls
                    ]
                })

                # 执行新工具调用 + 注入缓存结果
                for tc, tool_key in all_tool_calls:
                    if tool_key in tool_result_cache:
                        # 🔥 缓存命中：直接注入历史结果
                        tool_output = tool_result_cache[tool_key]
                        print(f"       📌 Cache: {tc.name} → 使用缓存结果")
                    else:
                        # 新调用：执行并缓存
                        print(f"       🔧 Tool: {tc.name}({tc.arguments})")
                        result = self.toolkit.call_tool(tc.name, tc.arguments, caller=self.role.value)

                        if result.success:
                            tool_output = json.dumps(result.data, ensure_ascii=False, default=str)
                            print(f"          → 成功")
                        else:
                            tool_output = f"错误: {result.error}"
                            print(f"          → 失败: {result.error}")

                        # 🔥 缓存结果
                        tool_result_cache[tool_key] = tool_output

                    # 添加工具结果消息
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": tool_output
                    })
            else:
                # AI 不再调用工具，返回最终响应
                print(f"    ✅ [{self.role.value}] 分析完成 (共 {round_num + 1} 轮)")
                return response.content

        # 达到最大轮次 - 🔥 发送最终请求要求输出结果
        print(f"    ⚠️ [{self.role.value}] 达到最大工具调用轮次 ({max_tool_rounds})，请求最终输出...")

        # 添加最终提示，强制 LLM 停止工具调用并输出结果
        messages.append({
            "role": "user",
            "content": "请停止工具调用。基于你已经收集到的所有代码信息，立即输出最终的分析结果。" +
                      ("\n请确保输出符合 JSON 格式。" if json_mode else "")
        })

        # 最后一次调用 LLM（不带 tools 参数，强制文本输出）
        try:
            async with self._llm_lock:
                final_response = await asyncio.to_thread(
                    self._llm_provider.chat,
                    messages
                    # 不传 tools，强制输出
                )
            # 🔥 v2.5.8: 追踪 token 使用量
            if hasattr(final_response, 'usage') and final_response.usage:
                self._track_token_usage(final_response.usage)
            print(f"    ✅ [{self.role.value}] 最终输出获取成功")
            return final_response.content
        except Exception as e:
            print(f"    ⚠️ [{self.role.value}] 最终输出请求失败: {e}")
            return response.content if response else ""

    async def verify_with_tools(
        self,
        finding: Dict[str, Any],
        verification_prompt: str,
        function_index: str = "",
        analysis_context: str = "",
        max_tool_rounds: int = 3  # 🔥 v2.5.14: 已有预构建上下文，3轮足够
    ) -> Dict[str, Any]:
        """
        🔥 通用工具辅助验证方法 (所有 Agent 可用)

        AI 可以自主调用工具查看代码来验证漏洞。

        Args:
            finding: 漏洞发现 (来自 Phase 2)
            verification_prompt: 验证任务的具体 prompt (各 Agent 自定义)
            function_index: 函数索引 (让 AI 知道可以查询哪些函数)
            analysis_context: Phase 0/1 的分析上下文
            max_tool_rounds: 最大工具调用轮数 (默认 8)

        Returns:
            验证结果 (JSON 解析后的字典)

        Usage:
            # 在各 Agent 中使用
            result = await self.verify_with_tools(
                finding=finding,
                verification_prompt="请从安全角度验证...",
                function_index=toolkit.get_function_index(),
                analysis_context=toolkit.get_analysis_context()
            )
        """
        if not self.toolkit:
            raise ValueError(f"[{self.role.value}] verify_with_tools 需要设置 toolkit")

        # 获取初始代码上下文
        code_context = finding.get('code_context', '')
        evidence = finding.get('evidence', finding.get('proof', ''))
        location = finding.get('location', {})

        # 获取可用工具
        tools = self.toolkit.get_security_tools()

        # 🔥 判断是否有预构建上下文
        has_prebuilt = bool(code_context and len(code_context.strip()) > 100)

        # 构建完整 prompt
        full_prompt = f"""
## 漏洞信息
- ID: {finding.get('id')}
- 标题: {finding.get('title')}
- 严重性: {finding.get('severity')}
- 位置: {location}
- 描述: {finding.get('description')}
- 漏洞代码/证据: {evidence}

## 🔥 预构建的代码上下文
```move
{code_context if code_context else '无初始代码上下文，请使用工具获取'}
```

## 📝 工具使用指南
{"上面已经提供了漏洞函数及其调用链的代码，请优先基于这些代码进行验证。" if has_prebuilt else "请使用工具获取代码进行验证。"}
- **只有在以下情况才需要调用工具**：需要跨模块函数、类型定义、更深调用链
- **效率要求**：每轮最多调用 2 个工具，避免重复调用

{f"## Phase 0/1 分析上下文{chr(10)}{analysis_context}" if analysis_context else ""}

{f"## 可查询的函数{chr(10)}{function_index}" if function_index else ""}

## 可用工具 (按需使用)
- `get_function_code(module, function)`: 获取指定函数的完整实现
- `get_callers(module, function)`: 查看谁调用了该函数
- `get_callees(module, function)`: 查看该函数调用了什么
- `get_type_definition(type_name)`: 查看 struct 类型定义
- `search_code(pattern)`: 在代码中搜索模式

## 验证任务
{verification_prompt}
"""
        # 使用工具调用循环
        response = await self.call_llm_with_tools(
            prompt=full_prompt,
            tools=tools,
            max_tool_rounds=max_tool_rounds,
            json_mode=True
        )
        return self.parse_json_response(response)

    async def verify_lightweight(
        self,
        finding: Dict[str, Any],
        verification_prompt: str,
        minimal_context: str = "",
        function_index: str = "",
        max_tool_rounds: int = 3
    ) -> Dict[str, Any]:
        """
        🔥 轻量级子 Agent 验证 (v2.4.9)

        核心优化：
        1. 创建独立的 LLM 实例，不共享主 Agent 的锁
        2. 只使用最小上下文 (~5K tokens)，不累积历史
        3. 支持并行执行多个验证任务

        与 verify_with_tools 的区别：
        - verify_with_tools: 使用 self._llm_provider，受锁保护，上下文累积
        - verify_lightweight: 独立 LLM，无锁，最小上下文，每次调用隔离

        Args:
            finding: 漏洞信息 (只提取关键字段)
            verification_prompt: 验证任务描述
            minimal_context: 最小代码上下文 (目标函数 + 关键调用)
            function_index: 函数索引 (让 AI 知道可查询哪些函数)
            max_tool_rounds: 最大工具调用轮数

        Returns:
            验证结果 (JSON)
        """
        import random

        if not self.toolkit:
            raise ValueError(f"[{self.role.value}] verify_lightweight 需要设置 toolkit")

        # 🔥 创建独立的 LLM 实例 (不使用 self._llm_provider)
        provider_type = ProviderType(self.config.provider.lower())
        llm_config = LLMConfig(
            provider=provider_type,
            model=self.config.model or self.config.model_name,
            api_key=self.config.api_key,
            base_url=self.config.base_url,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            timeout=self.config.timeout
        )
        sub_agent_llm = LLMProviderFactory.create(llm_config)

        # 🔥 精简的系统 prompt
        system_prompt = f"""你是 {self.role.value} 验证子程序。专注验证单个漏洞。

工作原则：
1. 直接分析提供的代码，高效使用工具
2. 每轮最多调用 2 个工具
3. 收集足够信息后立即输出 JSON 结果
4. 不要重复获取相同信息

{verification_prompt}"""

        # 🔥 最小用户 prompt (只含必要信息)
        vuln_id = finding.get('id', finding.get('title', 'unknown'))[:50]
        severity = finding.get('severity', 'unknown')
        description = finding.get('description', '')[:500]
        location = finding.get('location', {})
        location_str = f"{location.get('module', '?')}::{location.get('function', '?')}" if isinstance(location, dict) else str(location)

        user_prompt = f"""## 漏洞
- ID: {vuln_id}
- 严重性: {severity}
- 位置: {location_str}
- 描述: {description}

## 代码上下文
```move
{minimal_context[:6000] if minimal_context else "请使用工具获取"}
```

{f"## 可查询函数{chr(10)}{function_index[:1500]}" if function_index else ""}

请验证此漏洞并输出 JSON 结果。"""

        # 🔥 全新的消息列表 (不带历史)
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        # 获取工具
        tools = self.toolkit.get_security_tools()

        # 工具调用去重
        called_tools: set = set()

        def get_tool_key(name: str, args: dict) -> str:
            return f"{name}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"

        # 🔥 轻量级工具调用循环 (使用独立 LLM，无锁)
        for round_num in range(max_tool_rounds):
            try:
                # 不需要锁，因为是独立的 LLM 实例
                # 🔥 修复: tools 必须作为关键字参数传递
                response = await asyncio.to_thread(
                    lambda: sub_agent_llm.chat(messages, tools=tools)
                )
                # 🔥 v2.5.8: 追踪子 Agent token 使用量
                if hasattr(response, 'usage') and response.usage:
                    self._track_token_usage(response.usage)
            except Exception as e:
                error_str = str(e)
                if "429" in error_str or "rate" in error_str.lower():
                    delay = 2.0 * (2 ** round_num) * random.uniform(0.5, 1.5)
                    print(f"      ⏳ [{self.role.value}] API 限流，{delay:.1f}s 后重试...")
                    await asyncio.sleep(delay)
                    continue
                return {"error": f"子 Agent 调用失败: {str(e)[:100]}", "verification_result": "error"}

            # 检查是否完成
            if response.finish_reason != "tool_calls" or not response.tool_calls:
                return self.parse_json_response(response.content or "")

            # 过滤重复工具调用
            unique_calls = []
            for tc in response.tool_calls:
                tool_key = get_tool_key(tc.name, tc.arguments)
                if tool_key not in called_tools:
                    called_tools.add(tool_key)
                    unique_calls.append(tc)

            if not unique_calls:
                # 强制输出
                messages.append({"role": "user", "content": "请立即输出 JSON 结果。"})
                try:
                    final_resp = await asyncio.to_thread(sub_agent_llm.chat, messages)
                    # 🔥 v2.5.8: 追踪子 Agent token 使用量
                    if hasattr(final_resp, 'usage') and final_resp.usage:
                        self._track_token_usage(final_resp.usage)
                    return self.parse_json_response(final_resp.content or "")
                except:
                    break

            # 记录并执行工具调用
            messages.append({
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [{"id": tc.id, "name": tc.name, "args": tc.arguments} for tc in unique_calls]
            })

            for tc in unique_calls:
                result = self.toolkit.call_tool(tc.name, tc.arguments, caller=f"Sub-{self.role.value}")
                tool_output = json.dumps(result.data, ensure_ascii=False)[:2000] if result.success else f"Error: {result.error}"
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": tool_output})

        # 最大轮次耗尽
        messages.append({"role": "user", "content": "请立即输出 JSON 结果。"})
        try:
            final_resp = await asyncio.to_thread(sub_agent_llm.chat, messages)
            # 🔥 v2.5.8: 追踪子 Agent token 使用量
            if hasattr(final_resp, 'usage') and final_resp.usage:
                self._track_token_usage(final_resp.usage)
            return self.parse_json_response(final_resp.content or "")
        except:
            return {"error": "子 Agent 轮次耗尽", "verification_result": "error"}

    def parse_json_response(self, response: str) -> Dict[str, Any]:
        """
        解析LLM的JSON响应（使用 json_parser 工具模块的 9 种修复策略）

        Args:
            response: LLM响应文本

        Returns:
            解析后的字典
        """
        return robust_parse_json(response, verbose=True)

    def reset_conversation(self):
        """重置对话历史"""
        self.conversation_history = []

    def get_state(self, key: str, default: Any = None) -> Any:
        """获取Agent状态"""
        return self.state.get(key, default)

    def set_state(self, key: str, value: Any):
        """设置Agent状态"""
        self.state[key] = value

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.value}>"
