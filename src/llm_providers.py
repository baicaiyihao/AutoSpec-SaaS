"""
LLM Providers - 统一的多模型接口

支持的模型提供商:
- OpenAI (GPT-4, GPT-4o, o1)
- Anthropic (Claude 3.5, Claude 4)
- Google (Gemini 2.0, Gemini 2.5)
- DeepSeek (DeepSeek-V3, DeepSeek-R1)
- ZhipuAI (GLM-4, GLM-4V)
- Alibaba DashScope (Qwen-Max, Qwen-Plus)
- Ollama (本地模型)

设计原则:
1. 统一接口 - 所有Provider实现相同的BaseLLMProvider
2. 延迟初始化 - 只在需要时创建客户端
3. 配置驱动 - 通过环境变量或配置文件管理API密钥
4. 容错设计 - 支持fallback到备用模型
"""

import os
import json
from pathlib import Path
from abc import ABC, abstractmethod

# 加载 .env 文件
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from enum import Enum


class ProviderType(Enum):
    """模型提供商类型"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    DEEPSEEK = "deepseek"
    ZHIPU = "zhipu"
    DASHSCOPE = "dashscope"
    OLLAMA = "ollama"
    OPENAI_COMPATIBLE = "openai_compatible"  # 兼容OpenAI API的服务


@dataclass
class LLMConfig:
    """LLM配置"""
    provider: ProviderType
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 120
    extra_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCall:
    """工具调用请求"""
    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class LLMResponse:
    """LLM响应"""
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    raw_response: Any = None
    tool_calls: List[ToolCall] = field(default_factory=list)  # 🔥 AI 请求的工具调用
    finish_reason: str = "stop"  # "stop" | "tool_calls" | "length"


class BaseLLMProvider(ABC):
    """
    LLM提供商基类

    所有提供商必须实现此接口。
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = None

    @property
    def client(self):
        """延迟初始化客户端"""
        if self._client is None:
            self._client = self._create_client()
        return self._client

    @abstractmethod
    def _create_client(self) -> Any:
        """创建底层客户端"""
        pass

    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> LLMResponse:
        """
        发送聊天请求

        Args:
            messages: 消息列表 [{"role": "user", "content": "..."}]
            **kwargs: 额外参数

        Returns:
            LLMResponse
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """检查服务是否可用"""
        pass

    def invoke(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """兼容langchain的invoke方法"""
        return self.chat(messages, **kwargs)


# =============================================================================
# OpenAI Provider
# =============================================================================

class OpenAIProvider(BaseLLMProvider):
    """OpenAI API (GPT-4, GPT-4o, o1等) - 支持 Function Calling"""

    def _create_client(self):
        try:
            from openai import OpenAI
            api_key = self.config.api_key or os.getenv("OPENAI_API_KEY")
            return OpenAI(
                api_key=api_key,
                base_url=self.config.base_url,
                timeout=self.config.timeout
            )
        except ImportError:
            raise ImportError("请安装openai: pip install openai")

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        # 构建请求参数
        request_params = {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            **self.config.extra_params
        }

        # 🔥 添加工具定义 (如果提供)
        tools = kwargs.get("tools")
        if tools:
            request_params["tools"] = tools
            # 允许 AI 选择是否调用工具
            request_params["tool_choice"] = kwargs.get("tool_choice", "auto")

        response = self.client.chat.completions.create(**request_params)

        # 解析响应
        message = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        # 🔥 解析工具调用
        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=args
                ))

        return LLMResponse(
            content=message.content or "",
            model=response.model,
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens
            },
            raw_response=response,
            tool_calls=tool_calls,
            finish_reason=finish_reason
        )

    def is_available(self) -> bool:
        api_key = self.config.api_key or os.getenv("OPENAI_API_KEY")
        return bool(api_key)


# =============================================================================
# Anthropic Provider
# =============================================================================

class AnthropicProvider(BaseLLMProvider):
    """
    Anthropic API (Claude系列)

    安装: pip install anthropic
    模型: claude-sonnet-4-5, claude-sonnet-4, claude-opus-4, claude-haiku-4-5 等
    """

    def _create_client(self):
        try:
            import anthropic
            api_key = self.config.api_key or os.getenv("ANTHROPIC_API_KEY")
            return anthropic.Anthropic(api_key=api_key)
        except ImportError:
            raise ImportError("请安装anthropic: pip install anthropic")

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        # 分离system message
        system = None
        chat_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system = msg["content"]
            else:
                chat_messages.append({"role": msg["role"], "content": msg["content"]})

        # 构建请求参数
        create_params = {
            "model": self.config.model or "claude-sonnet-4-5",
            "messages": chat_messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        # system 是可选的
        if system:
            create_params["system"] = system

        # temperature 对某些模型可能不支持
        if self.config.temperature > 0:
            create_params["temperature"] = kwargs.get("temperature", self.config.temperature)

        response = self.client.messages.create(**create_params)

        # 提取文本内容
        content = ""
        for block in response.content:
            if hasattr(block, 'text'):
                content += block.text

        return LLMResponse(
            content=content,
            model=response.model,
            usage={
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens
            },
            raw_response=response
        )

    def is_available(self) -> bool:
        api_key = self.config.api_key or os.getenv("ANTHROPIC_API_KEY")
        return bool(api_key)


# =============================================================================
# Google Gemini Provider
# =============================================================================

class GoogleProvider(BaseLLMProvider):
    """
    Google Gemini API (使用 google-genai SDK)

    安装: pip install google-genai
    模型: gemini-3-flash, gemini-3-pro, gemini-2.5-pro, gemini-2.5-flash 等
    """

    def _create_client(self):
        try:
            from google import genai
            api_key = self.config.api_key or os.getenv("GOOGLE_API_KEY")
            return genai.Client(api_key=api_key)
        except ImportError:
            raise ImportError("请安装google-genai: pip install google-genai")

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        # 转换消息格式为 contents
        contents = []
        system_instruction = None

        for msg in messages:
            if msg["role"] == "system":
                system_instruction = msg["content"]
            elif msg["role"] == "user":
                contents.append({"role": "user", "parts": [{"text": msg["content"]}]})
            elif msg["role"] == "assistant":
                contents.append({"role": "model", "parts": [{"text": msg["content"]}]})

        # 构建请求参数
        generate_params = {
            "model": self.config.model or "gemini-3-flash",
            "contents": contents,
        }

        # 添加生成配置
        config = {
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_output_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        if system_instruction:
            config["system_instruction"] = system_instruction

        generate_params["config"] = config

        response = self.client.models.generate_content(**generate_params)

        return LLMResponse(
            content=response.text,
            model=self.config.model,
            usage={
                "prompt_tokens": getattr(response.usage_metadata, 'prompt_token_count', 0) if hasattr(response, 'usage_metadata') else 0,
                "completion_tokens": getattr(response.usage_metadata, 'candidates_token_count', 0) if hasattr(response, 'usage_metadata') else 0,
                "total_tokens": getattr(response.usage_metadata, 'total_token_count', 0) if hasattr(response, 'usage_metadata') else 0,
            },
            raw_response=response
        )

    def is_available(self) -> bool:
        api_key = self.config.api_key or os.getenv("GOOGLE_API_KEY")
        return bool(api_key)


# =============================================================================
# DeepSeek Provider
# =============================================================================

class DeepSeekProvider(BaseLLMProvider):
    """DeepSeek API (兼容OpenAI格式)"""

    def _create_client(self):
        try:
            from openai import OpenAI
            api_key = self.config.api_key or os.getenv("DEEPSEEK_API_KEY")
            return OpenAI(
                api_key=api_key,
                base_url=self.config.base_url or "https://api.deepseek.com/v1",
                timeout=self.config.timeout
            )
        except ImportError:
            raise ImportError("请安装openai: pip install openai")

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        response = self.client.chat.completions.create(
            model=self.config.model or "deepseek-chat",
            messages=messages,
            temperature=kwargs.get("temperature", self.config.temperature),
            max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
            **self.config.extra_params
        )
        return LLMResponse(
            content=response.choices[0].message.content,
            model=response.model,
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens
            },
            raw_response=response
        )

    def is_available(self) -> bool:
        api_key = self.config.api_key or os.getenv("DEEPSEEK_API_KEY")
        return bool(api_key)


# =============================================================================
# ZhipuAI (GLM) Provider
# =============================================================================

class ZhipuProvider(BaseLLMProvider):
    """
    智谱AI GLM API (使用 zai-sdk)

    安装: pip install zai-sdk
    模型: glm-4.7, glm-4-plus, glm-4-long 等
    """

    def _create_client(self):
        try:
            from zai import ZhipuAiClient
            api_key = self.config.api_key or os.getenv("ZHIPU_API_KEY")
            # 🔥 禁用 SDK 内部重试，由我们的 BaseAgent.call_llm 统一处理重试
            return ZhipuAiClient(api_key=api_key, max_retries=0)
        except ImportError:
            raise ImportError("请安装zai-sdk: pip install zai-sdk")

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        call_params = {
            "model": self.config.model or "glm-4.7",
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        response = self.client.chat.completions.create(**call_params)

        # 提取内容
        message = response.choices[0].message
        content = message.content or ""

        return LLMResponse(
            content=content,
            model=response.model if hasattr(response, 'model') else self.config.model,
            usage={
                "prompt_tokens": getattr(response.usage, 'prompt_tokens', 0) if hasattr(response, 'usage') else 0,
                "completion_tokens": getattr(response.usage, 'completion_tokens', 0) if hasattr(response, 'usage') else 0,
                "total_tokens": getattr(response.usage, 'total_tokens', 0) if hasattr(response, 'usage') else 0
            },
            raw_response=response
        )

    def is_available(self) -> bool:
        api_key = self.config.api_key or os.getenv("ZHIPU_API_KEY")
        return bool(api_key)


# =============================================================================
# DashScope Provider (阿里云) - 使用 LangChain ChatTongyi
# =============================================================================

class DashScopeProvider(BaseLLMProvider):
    """
    阿里云DashScope API (Qwen, DeepSeek等) - 基于 LangChain ChatTongyi

    🔥 支持 Function Calling (通过 tools 参数)
    """

    def _create_client(self):
        try:
            from langchain_community.chat_models import ChatTongyi
            api_key = self.config.api_key or os.getenv("DASHSCOPE_API_KEY")
            if not api_key:
                raise ValueError("缺少DASHSCOPE_API_KEY")

            return ChatTongyi(
                model=self.config.model or "qwen-plus",
                temperature=self.config.temperature,
                dashscope_api_key=api_key,
                max_tokens=self.config.max_tokens,
            )
        except ImportError:
            raise ImportError("请安装langchain-community: pip install langchain-community")

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage

        # 🔥 检查是否有 tool 消息，如果有则使用原生 DashScope API
        has_tool_messages = any(msg.get("role") == "tool" for msg in messages)
        tools = kwargs.get("tools")

        if has_tool_messages or (tools and self._has_tool_calls_in_messages(messages)):
            # 使用原生 DashScope API 处理多轮工具调用
            # 从 kwargs 中移除 tools 避免重复传参
            kwargs_copy = {k: v for k, v in kwargs.items() if k != "tools"}
            return self._chat_with_native_api(messages, tools, **kwargs_copy)

        # 转换消息格式 (无工具调用时使用 LangChain)
        lc_messages = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                lc_messages.append(SystemMessage(content=content))
            elif role == "assistant":
                lc_messages.append(AIMessage(content=content))
            else:
                lc_messages.append(HumanMessage(content=content))

        # 🔥 如果提供了工具定义，绑定工具
        client = self.client
        if tools:
            # 转换为 LangChain 工具格式
            lc_tools = self._convert_tools_to_langchain(tools)
            if lc_tools:
                client = self.client.bind_tools(lc_tools)

        # 调用 LangChain ChatTongyi
        response = client.invoke(lc_messages)

        # 提取 token 使用量
        usage = {}
        if hasattr(response, 'response_metadata'):
            meta = response.response_metadata
            if 'token_usage' in meta:
                token_usage = meta['token_usage']
                usage = {
                    "prompt_tokens": token_usage.get("input_tokens", 0),
                    "completion_tokens": token_usage.get("output_tokens", 0),
                    "total_tokens": token_usage.get("total_tokens", 0)
                }

        # 🔥 解析工具调用
        tool_calls = []
        finish_reason = "stop"
        if hasattr(response, 'tool_calls') and response.tool_calls:
            finish_reason = "tool_calls"
            for tc in response.tool_calls:
                tool_calls.append(ToolCall(
                    id=tc.get("id", f"call_{len(tool_calls)}"),
                    name=tc.get("name", ""),
                    arguments=tc.get("args", {})
                ))

        return LLMResponse(
            content=response.content or "",
            model=self.config.model,
            usage=usage,
            raw_response=response,
            tool_calls=tool_calls,
            finish_reason=finish_reason
        )

    def _has_tool_calls_in_messages(self, messages: List[Dict]) -> bool:
        """检查消息中是否有 tool_calls"""
        return any(msg.get("tool_calls") for msg in messages)

    def _chat_with_native_api(self, messages: List[Dict], tools: List[Dict], **kwargs) -> LLMResponse:
        """
        🔥 使用原生 DashScope API 处理多轮工具调用

        LangChain 对 tool messages 的处理有问题，直接使用 DashScope SDK
        """
        try:
            from dashscope import Generation
        except ImportError:
            raise ImportError("请安装dashscope: pip install dashscope")

        api_key = self.config.api_key or os.getenv("DASHSCOPE_API_KEY")

        # 转换消息格式为 DashScope 原生格式
        ds_messages = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if role == "assistant" and msg.get("tool_calls"):
                # 带工具调用的 assistant 消息
                ds_msg = {
                    "role": "assistant",
                    "content": content or "",
                    "tool_calls": [
                        {
                            "id": tc.get("id", f"call_{i}"),
                            "type": "function",
                            "function": {
                                "name": tc.get("name", ""),
                                "arguments": json.dumps(tc.get("args", tc.get("arguments", {})), ensure_ascii=False)
                            }
                        }
                        for i, tc in enumerate(msg["tool_calls"])
                    ]
                }
                ds_messages.append(ds_msg)
            elif role == "tool":
                # 工具返回结果
                ds_messages.append({
                    "role": "tool",
                    "content": content,
                    "tool_call_id": msg.get("tool_call_id", "")
                })
            else:
                ds_messages.append({"role": role, "content": content})

        # 转换工具格式
        ds_tools = None
        if tools:
            ds_tools = []
            for tool in tools:
                if tool.get("type") == "function":
                    ds_tools.append(tool)
                elif "name" in tool:
                    ds_tools.append({
                        "type": "function",
                        "function": {
                            "name": tool.get("name", ""),
                            "description": tool.get("description", ""),
                            "parameters": tool.get("parameters", {})
                        }
                    })

        # 调用 DashScope API
        response = Generation.call(
            api_key=api_key,
            model=self.config.model or "qwen-plus",
            messages=ds_messages,
            tools=ds_tools,
            result_format="message",
            temperature=kwargs.get("temperature", self.config.temperature),
            max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
        )

        # 解析响应
        if response.status_code != 200:
            raise ValueError(f"DashScope API 错误: {response.code} - {response.message}")

        output = response.output
        message = output.choices[0].message

        # 解析工具调用
        tool_calls = []
        finish_reason = output.choices[0].finish_reason

        # 安全获取 tool_calls (DashScope 响应可能没有这个字段)
        try:
            msg_tool_calls = message.tool_calls if hasattr(message, 'tool_calls') else None
        except (KeyError, AttributeError):
            msg_tool_calls = None

        if msg_tool_calls:
            for tc in msg_tool_calls:
                try:
                    # tc 可能是对象或字典
                    if isinstance(tc, dict):
                        func = tc.get("function", {})
                        tc_id = tc.get("id", f"call_{len(tool_calls)}")
                        func_name = func.get("name", "") if isinstance(func, dict) else ""
                        func_args = func.get("arguments", "{}") if isinstance(func, dict) else "{}"
                    else:
                        tc_id = tc.id if hasattr(tc, 'id') else f"call_{len(tool_calls)}"
                        func_name = tc.function.name
                        func_args = tc.function.arguments

                    args = json.loads(func_args) if func_args else {}
                except (json.JSONDecodeError, AttributeError):
                    args = {}

                tool_calls.append(ToolCall(
                    id=tc_id,
                    name=func_name,
                    arguments=args
                ))

        # 提取 usage
        usage = {}
        if hasattr(response, 'usage'):
            usage = {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.total_tokens
            }

        return LLMResponse(
            content=message.content or "",
            model=self.config.model,
            usage=usage,
            raw_response=response,
            tool_calls=tool_calls,
            finish_reason=finish_reason
        )

    def _convert_tools_to_langchain(self, tools: List[Dict]) -> List[Dict]:
        """
        将 OpenAI 格式的 tools 转换为 LangChain 格式

        OpenAI 格式:
        [{"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}]

        LangChain 格式:
        [{"name": "...", "description": "...", "parameters": {...}}]
        """
        lc_tools = []
        for tool in tools:
            if tool.get("type") == "function":
                func = tool.get("function", {})
                lc_tools.append({
                    "name": func.get("name", ""),
                    "description": func.get("description", ""),
                    "parameters": func.get("parameters", {})
                })
            elif "name" in tool:
                # 已经是简化格式
                lc_tools.append(tool)
        return lc_tools

    def is_available(self) -> bool:
        api_key = self.config.api_key or os.getenv("DASHSCOPE_API_KEY")
        return bool(api_key)


# =============================================================================
# Ollama Provider (本地模型)
# =============================================================================

class OllamaProvider(BaseLLMProvider):
    """Ollama本地模型"""

    def _create_client(self):
        try:
            import ollama
            return ollama
        except ImportError:
            raise ImportError("请安装ollama: pip install ollama")

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        response = self.client.chat(
            model=self.config.model or "llama3.3",
            messages=messages,
            options={
                "temperature": kwargs.get("temperature", self.config.temperature),
                "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
            }
        )
        return LLMResponse(
            content=response["message"]["content"],
            model=self.config.model,
            usage={
                "prompt_tokens": response.get("prompt_eval_count", 0),
                "completion_tokens": response.get("eval_count", 0),
                "total_tokens": response.get("prompt_eval_count", 0) + response.get("eval_count", 0)
            },
            raw_response=response
        )

    def is_available(self) -> bool:
        try:
            import ollama
            ollama.list()
            return True
        except:
            return False


# =============================================================================
# OpenAI Compatible Provider (通用)
# =============================================================================

class OpenAICompatibleProvider(BaseLLMProvider):
    """兼容OpenAI API的通用Provider"""

    def _create_client(self):
        try:
            from openai import OpenAI
            return OpenAI(
                api_key=self.config.api_key,
                base_url=self.config.base_url,
                timeout=self.config.timeout
            )
        except ImportError:
            raise ImportError("请安装openai: pip install openai")

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        response = self.client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            temperature=kwargs.get("temperature", self.config.temperature),
            max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
            **self.config.extra_params
        )
        return LLMResponse(
            content=response.choices[0].message.content,
            model=response.model,
            usage={
                "prompt_tokens": getattr(response.usage, "prompt_tokens", 0),
                "completion_tokens": getattr(response.usage, "completion_tokens", 0),
                "total_tokens": getattr(response.usage, "total_tokens", 0)
            },
            raw_response=response
        )

    def is_available(self) -> bool:
        return bool(self.config.api_key and self.config.base_url)


# =============================================================================
# Provider Factory
# =============================================================================

class LLMProviderFactory:
    """LLM Provider工厂"""

    _providers = {
        ProviderType.OPENAI: OpenAIProvider,
        ProviderType.ANTHROPIC: AnthropicProvider,
        ProviderType.GOOGLE: GoogleProvider,
        ProviderType.DEEPSEEK: DeepSeekProvider,
        ProviderType.ZHIPU: ZhipuProvider,
        ProviderType.DASHSCOPE: DashScopeProvider,
        ProviderType.OLLAMA: OllamaProvider,
        ProviderType.OPENAI_COMPATIBLE: OpenAICompatibleProvider,
    }

    @classmethod
    def create(cls, config: LLMConfig) -> BaseLLMProvider:
        """创建Provider实例"""
        provider_class = cls._providers.get(config.provider)
        if not provider_class:
            raise ValueError(f"不支持的Provider: {config.provider}")
        return provider_class(config)

    @classmethod
    def create_from_env(
        cls,
        provider: Union[str, ProviderType],
        model: Optional[str] = None,
        **kwargs
    ) -> BaseLLMProvider:
        """从环境变量创建Provider"""
        if isinstance(provider, str):
            provider = ProviderType(provider.lower())

        # 默认模型
        default_models = {
            ProviderType.OPENAI: "gpt-4o",
            ProviderType.ANTHROPIC: "claude-sonnet-4-5",
            ProviderType.GOOGLE: "gemini-3-flash",
            ProviderType.DEEPSEEK: "deepseek-chat",
            ProviderType.ZHIPU: "glm-4.7",
            ProviderType.DASHSCOPE: "qwen-max",
            ProviderType.OLLAMA: "llama3.3",
        }

        config = LLMConfig(
            provider=provider,
            model=model or default_models.get(provider, ""),
            **kwargs
        )
        return cls.create(config)

    @classmethod
    def get_available_providers(cls) -> List[ProviderType]:
        """获取当前可用的Provider列表"""
        available = []
        for provider_type, provider_class in cls._providers.items():
            try:
                config = LLMConfig(provider=provider_type, model="test")
                instance = provider_class(config)
                if instance.is_available():
                    available.append(provider_type)
            except:
                pass
        return available


# =============================================================================
# Multi-Model Manager
# =============================================================================

@dataclass
class ModelAssignment:
    """Agent的模型分配"""
    agent_role: str
    provider: ProviderType
    model: str
    fallback_provider: Optional[ProviderType] = None
    fallback_model: Optional[str] = None


class MultiModelManager:
    """
    多模型管理器

    为不同Agent分配不同的模型，支持fallback机制。
    """

    def __init__(self):
        self._providers: Dict[str, BaseLLMProvider] = {}
        self._assignments: Dict[str, ModelAssignment] = {}

    def assign(
        self,
        agent_role: str,
        provider: Union[str, ProviderType],
        model: str,
        fallback_provider: Optional[Union[str, ProviderType]] = None,
        fallback_model: Optional[str] = None
    ):
        """为Agent分配模型"""
        if isinstance(provider, str):
            provider = ProviderType(provider.lower())
        if isinstance(fallback_provider, str):
            fallback_provider = ProviderType(fallback_provider.lower())

        self._assignments[agent_role] = ModelAssignment(
            agent_role=agent_role,
            provider=provider,
            model=model,
            fallback_provider=fallback_provider,
            fallback_model=fallback_model
        )

    def get_provider(self, agent_role: str) -> BaseLLMProvider:
        """获取Agent对应的Provider"""
        assignment = self._assignments.get(agent_role)
        if not assignment:
            raise ValueError(f"未找到Agent '{agent_role}' 的模型分配")

        cache_key = f"{assignment.provider.value}:{assignment.model}"

        if cache_key not in self._providers:
            config = LLMConfig(
                provider=assignment.provider,
                model=assignment.model
            )
            provider = LLMProviderFactory.create(config)

            # 检查可用性，尝试fallback
            if not provider.is_available() and assignment.fallback_provider:
                print(f"[MultiModel] {assignment.provider.value} 不可用，尝试 fallback...")
                fallback_config = LLMConfig(
                    provider=assignment.fallback_provider,
                    model=assignment.fallback_model or ""
                )
                provider = LLMProviderFactory.create(fallback_config)
                cache_key = f"{assignment.fallback_provider.value}:{assignment.fallback_model}"

            self._providers[cache_key] = provider

        return self._providers[cache_key]

    def configure_default(self):
        """配置默认的模型分配"""
        # 根据可用的API自动分配
        available = LLMProviderFactory.get_available_providers()

        if ProviderType.ANTHROPIC in available:
            # Claude作为Expert (最强推理能力)
            self.assign("expert", ProviderType.ANTHROPIC, "claude-sonnet-4-20250514")
        elif ProviderType.DEEPSEEK in available:
            self.assign("expert", ProviderType.DEEPSEEK, "deepseek-chat")
        elif ProviderType.DASHSCOPE in available:
            self.assign("expert", ProviderType.DASHSCOPE, "qwen-max")

        if ProviderType.DEEPSEEK in available:
            # DeepSeek作为Auditor (性价比高)
            self.assign("auditor", ProviderType.DEEPSEEK, "deepseek-chat")
        elif ProviderType.DASHSCOPE in available:
            self.assign("auditor", ProviderType.DASHSCOPE, "deepseek-v3.2")

        if ProviderType.DASHSCOPE in available:
            # Qwen作为Analyst和Manager
            self.assign("analyst", ProviderType.DASHSCOPE, "qwen-max")
            self.assign("manager", ProviderType.DASHSCOPE, "qwen-max")
        elif ProviderType.OPENAI in available:
            self.assign("analyst", ProviderType.OPENAI, "gpt-4o")
            self.assign("manager", ProviderType.OPENAI, "gpt-4o")


# 全局实例
_model_manager: Optional[MultiModelManager] = None


def get_model_manager() -> MultiModelManager:
    """获取全局MultiModelManager实例"""
    global _model_manager
    if _model_manager is None:
        _model_manager = MultiModelManager()
        _model_manager.configure_default()
    return _model_manager
