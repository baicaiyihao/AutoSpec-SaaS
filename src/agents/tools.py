"""
Agent 工具定义

为安全审计 Agent 提供代码上下文检索能力。

工具列表:
1. get_function_code - 获取函数实现
2. get_callers - 获取调用者
3. get_callees - 获取被调用者
4. get_type_definition - 获取类型定义
5. search_code - 搜索代码模式
6. get_project_overview - 获取项目概览
7. get_external_dependency - 获取外部依赖实现

设计原则:
- 返回原始代码，不做语义转述
- 控制返回内容大小，避免上下文爆炸
- 提供结构化输出，方便 Agent 解析
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING
import threading

if TYPE_CHECKING:
    from src.context import MoveProjectIndexer


@dataclass
class ToolResult:
    """工具调用结果"""
    success: bool
    data: Any
    error: Optional[str] = None
    source: str = "unknown"  # 数据来源: callgraph, semantic, pattern, index

    def to_prompt(self) -> str:
        """转换为 prompt 文本"""
        if not self.success:
            return f"[工具调用失败] {self.error}"

        lines = [f"[来源: {self.source}]"]

        if isinstance(self.data, str):
            lines.append(self.data)
        elif isinstance(self.data, dict):
            lines.append(self._dict_to_prompt(self.data))
        elif isinstance(self.data, list):
            lines.append("\n".join(str(item) for item in self.data))
        else:
            lines.append(str(self.data))

        return "\n".join(lines)

    def _dict_to_prompt(self, d: Dict) -> str:
        """将字典转为可读格式"""
        lines = []
        for k, v in d.items():
            if k == "warnings" and v:
                lines.append(f"⚠️ 警告: {', '.join(v)}")
            elif isinstance(v, str) and len(v) > 100:
                lines.append(f"## {k}\n```move\n{v}\n```")
            elif isinstance(v, list):
                lines.append(f"## {k}")
                for item in v[:10]:  # 限制数量
                    if isinstance(item, dict):
                        item_id = item.get('id', item.get('name', str(item)))
                        item_source = item.get('source', '')
                        source_tag = f" [{item_source}]" if item_source else ""
                        lines.append(f"- {item_id}{source_tag}")
                    else:
                        lines.append(f"- {item}")
            else:
                lines.append(f"**{k}**: {v}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """转为字典格式"""
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "source": self.source,
        }


@dataclass
class ToolDefinition:
    """工具定义"""
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema 格式
    handler: Callable[..., ToolResult]


class AgentToolkit:
    """
    Agent 工具箱

    整合上下文检索能力，提供给 Agent 使用。

    线程安全说明:
    - 初始化后，indexer 和 _tools 为只读，支持并发读取
    - set_contract_analysis() 使用锁保护，支持并发调用
    - call_tool() 是线程安全的（只读操作 + 锁保护的写入）

    用法:
    ```python
    from src.context import MoveProjectIndexer
    from src.agents.tools import AgentToolkit

    # 初始化
    indexer = MoveProjectIndexer("/path/to/project")
    indexer.index_project()

    toolkit = AgentToolkit(indexer)

    # 获取工具列表
    tools = toolkit.get_tool_definitions()

    # 调用工具
    result = toolkit.call_tool("get_function_code", {
        "module": "lending",
        "function": "borrow"
    })
    print(result.to_prompt())
    ```
    """

    def __init__(
        self,
        indexer: "MoveProjectIndexer",
        security_scanner: Optional[Any] = None,  # SecurityScanner 实例
        contract_analysis: Optional[Dict[str, Any]] = None  # 🔥 Phase 0/1 分析数据
    ):
        self.indexer = indexer
        self.security_scanner = security_scanner
        self.contract_analysis = contract_analysis or {}  # 🔥 存储分析数据

        # 线程锁 (保护 contract_analysis 的写入)
        self._lock = threading.Lock()

        # 注册工具 (初始化后只读)
        self._tools: Dict[str, ToolDefinition] = {}
        self._register_tools()

    def set_contract_analysis(self, contract_analysis: Dict[str, Any]):
        """
        🔥 更新 Phase 0/1 分析数据 (可在 Phase 1 完成后调用)

        线程安全: 使用锁保护写入操作

        Args:
            contract_analysis: 包含 analysis_hints, function_purposes 等
        """
        with self._lock:
            self.contract_analysis = contract_analysis

    def _register_tools(self):
        """注册所有工具"""

        # 1. 获取函数代码
        self._tools["get_function_code"] = ToolDefinition(
            name="get_function_code",
            description="获取指定函数的完整实现代码",
            parameters={
                "type": "object",
                "properties": {
                    "module": {
                        "type": "string",
                        "description": "模块名，如 'lending' 或 'lending::pool'"
                    },
                    "function": {
                        "type": "string",
                        "description": "函数名，如 'borrow'"
                    }
                },
                "required": ["module", "function"]
            },
            handler=self._get_function_code
        )

        # 2. 获取调用者
        self._tools["get_callers"] = ToolDefinition(
            name="get_callers",
            description="获取调用指定函数的所有函数列表",
            parameters={
                "type": "object",
                "properties": {
                    "module": {"type": "string", "description": "模块名"},
                    "function": {"type": "string", "description": "函数名"},
                    "depth": {
                        "type": "integer",
                        "description": "调用链深度，默认 2",
                        "default": 2
                    }
                },
                "required": ["module", "function"]
            },
            handler=self._get_callers
        )

        # 3. 获取被调用者
        self._tools["get_callees"] = ToolDefinition(
            name="get_callees",
            description="获取指定函数调用的所有函数列表",
            parameters={
                "type": "object",
                "properties": {
                    "module": {"type": "string", "description": "模块名"},
                    "function": {"type": "string", "description": "函数名"},
                    "depth": {
                        "type": "integer",
                        "description": "调用链深度，默认 2",
                        "default": 2
                    }
                },
                "required": ["module", "function"]
            },
            handler=self._get_callees
        )

        # 4. 获取类型定义
        self._tools["get_type_definition"] = ToolDefinition(
            name="get_type_definition",
            description="获取指定 struct 类型的完整定义",
            parameters={
                "type": "object",
                "properties": {
                    "type_name": {
                        "type": "string",
                        "description": "类型名，如 'Pool' 或 'lending::Pool'"
                    }
                },
                "required": ["type_name"]
            },
            handler=self._get_type_definition
        )

        # 5. 搜索代码
        self._tools["search_code"] = ToolDefinition(
            name="search_code",
            description="在代码中搜索指定模式",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "搜索模式（支持正则表达式）"
                    },
                    "regex": {
                        "type": "boolean",
                        "description": "是否使用正则表达式，默认 True",
                        "default": True
                    }
                },
                "required": ["pattern"]
            },
            handler=self._search_code
        )

        # 6. 获取项目概览
        self._tools["get_project_overview"] = ToolDefinition(
            name="get_project_overview",
            description="获取项目整体结构概览，包括模块、函数、类型等",
            parameters={
                "type": "object",
                "properties": {
                    "max_tokens": {
                        "type": "integer",
                        "description": "最大 token 数，默认 5000",
                        "default": 5000
                    }
                }
            },
            handler=self._get_project_overview
        )

        # 7. 获取函数完整上下文
        self._tools["get_function_context"] = ToolDefinition(
            name="get_function_context",
            description="获取函数的完整上下文：实现代码 + 调用者 + 被调用者 + 外部依赖",
            parameters={
                "type": "object",
                "properties": {
                    "module": {"type": "string", "description": "模块名"},
                    "function": {"type": "string", "description": "函数名"},
                    "depth": {
                        "type": "integer",
                        "description": "调用图深度，默认 2",
                        "default": 2
                    }
                },
                "required": ["module", "function"]
            },
            handler=self._get_function_context
        )

        # 8. 获取入口函数列表
        self._tools["get_entry_points"] = ToolDefinition(
            name="get_entry_points",
            description="获取项目中所有入口函数（public entry 函数）",
            parameters={
                "type": "object",
                "properties": {}
            },
            handler=self._get_entry_points
        )

        # ==========================================================================
        # 安全向量库工具 (需要 SecurityScanner)
        # ==========================================================================

        # 9. 获取漏洞利用案例
        self._tools["get_exploit_examples"] = ToolDefinition(
            name="get_exploit_examples",
            description="获取特定漏洞类型的历史利用案例和攻击模式。",
            parameters={
                "type": "object",
                "properties": {
                    "vuln_type": {
                        "type": "string",
                        "description": "漏洞类型，如 'overflow', 'access_control', 'flash_loan'"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "返回案例数量，默认 3",
                        "default": 3
                    }
                },
                "required": ["vuln_type"]
            },
            handler=self._get_exploit_examples
        )

        # ==========================================================================
        # 🔥 Phase 0/1 分析数据工具 (让后续阶段能够自主获取)
        # ==========================================================================

        # 12. 获取函数功能描述
        self._tools["get_function_purpose"] = ToolDefinition(
            name="get_function_purpose",
            description="获取指定函数的功能描述（来自 Phase 1.6 分析）。了解函数是做什么的。",
            parameters={
                "type": "object",
                "properties": {
                    "function_id": {
                        "type": "string",
                        "description": "函数 ID，如 '0x1::lending::borrow' 或 'borrow'"
                    }
                },
                "required": ["function_id"]
            },
            handler=self._get_function_purpose
        )

        # 13. 获取智能预分析提示
        self._tools["get_analysis_hints"] = ToolDefinition(
            name="get_analysis_hints",
            description="获取 Phase 1.5 智能预分析的结果，包括关键状态变量、条件阈值、跨函数数据流、状态变更点、潜在漏洞链等。",
            parameters={
                "type": "object",
                "properties": {
                    "hint_type": {
                        "type": "string",
                        "description": "获取特定类型的提示。可选: 'key_state_variables', 'condition_thresholds', 'cross_function_dataflow', 'state_change_points', 'potential_vuln_chains', 'all'",
                        "default": "all"
                    }
                }
            },
            handler=self._get_analysis_hints
        )

        # 15. 获取调用图摘要
        self._tools["get_callgraph_summary"] = ToolDefinition(
            name="get_callgraph_summary",
            description="获取项目调用图摘要，包括入口点、叶子节点、跨模块调用、高风险函数等。",
            parameters={
                "type": "object",
                "properties": {
                    "include_edges": {
                        "type": "boolean",
                        "description": "是否包含调用边详情，默认 False（仅返回摘要）",
                        "default": False
                    }
                }
            },
            handler=self._get_callgraph_summary
        )

        # 16. 获取模块结构
        self._tools["get_module_structure"] = ToolDefinition(
            name="get_module_structure",
            description="获取指定模块的结构，包括所有函数、结构体、常量等。",
            parameters={
                "type": "object",
                "properties": {
                    "module_name": {
                        "type": "string",
                        "description": "模块名，如 'lending' 或留空获取所有模块"
                    }
                }
            },
            handler=self._get_module_structure
        )

        # 17. 获取风险函数列表
        self._tools["get_risky_functions"] = ToolDefinition(
            name="get_risky_functions",
            description="获取标记为高风险的函数列表（涉及资金、权限、状态变更等）。",
            parameters={
                "type": "object",
                "properties": {
                    "risk_type": {
                        "type": "string",
                        "description": "风险类型过滤: 'funds' (资金相关), 'state' (状态变更), 'access' (权限相关), 'all'",
                        "default": "all"
                    }
                }
            },
            handler=self._get_risky_functions
        )

        # ==========================================================================
        # 🔥 v2.5.4: 安全知识库按需查询工具
        # ==========================================================================

        # 18. 查询安全知识库
        self._tools["query_security_knowledge"] = ToolDefinition(
            name="query_security_knowledge",
            description="""查询 Sui Move 安全知识库，获取特定安全模式/漏洞类型的详细信息。

常用查询主题:
- 'hot_potato' / '热土豆': 闪电贷强制还款模式
- 'capability' / '权限模式': AdminCap 等权限控制
- 'false_positive' / '误报': 常见误报判断指南
- 'flashloan' / '闪电贷': 闪电贷安全模式和真实风险
- 'overflow': 算术溢出保护机制
- 'reentrancy' / '重入': Move 的重入保护
- 'type_confusion' / '类型混淆': 泛型类型安全问题

使用场景: 当你需要判断某个发现是误报还是真实漏洞时，先查询相关安全知识。""",
            parameters={
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "查询主题，如 'hot_potato', 'flashloan', 'capability', 'false_positive'"
                    },
                    "include_examples": {
                        "type": "boolean",
                        "description": "是否包含代码示例，默认 True",
                        "default": True
                    }
                },
                "required": ["topic"]
            },
            handler=self._query_security_knowledge
        )

        # 19. 搜索历史漏洞模式 (RAG)
        self._tools["search_vulnerability_patterns"] = ToolDefinition(
            name="search_vulnerability_patterns",
            description="""搜索历史审计报告中的相似漏洞模式 (基于 RAG 向量检索)。

使用场景:
- 发现疑似漏洞后，查找历史类似案例
- 了解特定漏洞类型的常见攻击向量
- 获取修复建议和检测方法

返回: 相关审计案例、攻击模式、修复建议""",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "漏洞描述或代码片段，如 '闪电贷还款类型不匹配' 或 'repay with wrong coin type'"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "返回结果数量，默认 5",
                        "default": 5
                    },
                    "severity_filter": {
                        "type": "string",
                        "description": "严重性过滤: 'critical', 'high', 'medium', 'all'",
                        "default": "all"
                    }
                },
                "required": ["query"]
            },
            handler=self._search_vulnerability_patterns
        )

        # ==========================================================================
        # 🔥 v2.5.5: 自动安全模式检测工具
        # ==========================================================================

        # 20. 检查闪电贷安全性 (自动检测 Hot Potato + 类型验证)
        self._tools["check_flashloan_security"] = ToolDefinition(
            name="check_flashloan_security",
            description="""自动检查闪电贷实现的安全性。

检查项目:
1. Hot Potato 模式: Receipt 是否有 drop 能力？没有 = 强制还款 ✅
2. 类型验证: repay 函数是否验证还款币种与借款币种一致？
3. 金额验证: 是否验证还款金额 >= 借款金额 + 费用？
4. Pool ID 验证: 是否验证还款到正确的池子？

返回:
- hot_potato_safe: bool - Hot Potato 是否正确实现
- type_check_safe: bool - 类型检查是否存在
- security_summary: str - 安全性总结
- false_positive_indicators: list - 误报指标

使用场景: 当看到 "闪电贷无强制还款" 漏洞时，调用此工具自动判断是否误报。""",
            parameters={
                "type": "object",
                "properties": {
                    "receipt_type": {
                        "type": "string",
                        "description": "Receipt 类型名，如 'FlashReceipt' 或 'FlashLoanReceipt'",
                        "default": ""
                    },
                    "repay_function": {
                        "type": "string",
                        "description": "还款函数名，如 'repay_flashloan' 或 'repay'",
                        "default": ""
                    }
                }
            },
            handler=self._check_flashloan_security
        )

    # ==========================================================================
    # 工具实现
    # ==========================================================================

    # 🔥 Sui 标准库函数功能描述 - 帮助 AI 理解标准库函数的作用
    SUI_STDLIB_FUNCTIONS = {
        # event 模块
        "event::emit": "发送事件到链上，用于记录重要操作。事件会被索引并可被外部监听。",
        # transfer 模块
        "transfer::transfer": "将对象转移给指定地址，对象必须有 store 能力。",
        "transfer::public_transfer": "公开转移对象，对象必须有 key+store 能力。",
        "transfer::share_object": "将对象变为共享对象，任何人都可以访问。一旦共享不可撤销。",
        "transfer::freeze_object": "冻结对象，使其变为不可变。",
        # object 模块
        "object::new": "创建新的 UID，用于构造对象。",
        "object::id": "获取对象的 ID。",
        "object::id_from_address": "从地址创建 ID。",
        "object::uid_to_inner": "获取 UID 内部的 ID。",
        # tx_context 模块
        "tx_context::sender": "获取交易发送者地址。",
        "tx_context::epoch": "获取当前 epoch。",
        # clock 模块
        "clock::timestamp_ms": "获取当前时间戳（毫秒）。",
        # coin 模块
        "coin::from_balance": "将 Balance 转换为 Coin 对象。",
        "coin::into_balance": "将 Coin 对象转换为 Balance。",
        "coin::value": "获取 Coin 的数量。",
        "coin::split": "分割 Coin，返回指定数量的新 Coin。",
        "coin::join": "合并两个 Coin。",
        # balance 模块
        "balance::value": "获取 Balance 的数量。",
        "balance::split": "分割 Balance，返回指定数量的新 Balance。",
        "balance::join": "合并两个 Balance。",
        "balance::zero": "创建零余额。",
        "balance::create_for_testing": "【仅测试】创建任意数量的 Balance，生产环境不可用。",
        # type_name 模块
        "type_name::get": "获取类型的完整名称字符串。",
        "type_name::into_string": "将 TypeName 转换为字符串。",
        "type_name::with_defining_ids": "获取包含定义 ID 的类型名称。",
        # table/bag 模块
        "table::new": "创建新的 Table（类型化键值存储）。",
        "table::add": "向 Table 添加键值对。",
        "table::remove": "从 Table 移除并返回值。",
        "table::contains": "检查 Table 是否包含键。",
        "bag::new": "创建新的 Bag（异构键值存储）。",
        "bag::add": "向 Bag 添加键值对。",
        "bag::remove": "从 Bag 移除并返回值。",
        "bag::contains": "检查 Bag 是否包含键。",
        # linked_table 模块
        "linked_table::new": "创建新的 LinkedTable（有序键值存储）。",
        "linked_table::push_back": "在尾部添加元素。",
        "linked_table::pop_back": "移除并返回尾部元素。",
        "linked_table::contains": "检查是否包含键。",
        "linked_table::remove": "移除并返回指定键的值。",
        # vec_map/vec_set 模块
        "vec_map::empty": "创建空的 VecMap。",
        "vec_map::insert": "插入键值对。",
        "vec_map::contains": "检查是否包含键。",
        "vec_set::empty": "创建空的 VecSet。",
        "vec_set::insert": "插入元素。",
        "vec_set::contains": "检查是否包含元素。",
        # dynamic_field 模块
        "dynamic_field::add": "向对象添加动态字段。",
        "dynamic_field::remove": "移除动态字段。",
        "dynamic_field::exists_": "检查动态字段是否存在。",
        "dynamic_field::borrow": "借用动态字段的值。",
        "dynamic_field::borrow_mut": "可变借用动态字段的值。",
        # dynamic_object_field 模块
        "dynamic_object_field::add": "向对象添加动态对象字段（子对象）。",
        "dynamic_object_field::remove": "移除动态对象字段。",
        "dynamic_object_field::exists_": "检查动态对象字段是否存在。",
        # vector 模块
        "vector::empty": "创建空向量。",
        "vector::push_back": "在尾部添加元素。",
        "vector::pop_back": "移除并返回尾部元素。",
        "vector::length": "获取向量长度。",
        "vector::borrow": "借用指定索引的元素。",
        "vector::borrow_mut": "可变借用指定索引的元素。",
        # string 模块
        "string::utf8": "从字节创建 UTF-8 字符串。",
        "string::length": "获取字符串长度。",
        "string::is_empty": "检查字符串是否为空。",
    }

    # 🔥 Sui 标准库模块列表
    SUI_STDLIB_MODULES = {
        "event", "transfer", "object", "tx_context", "clock", "coin", "balance",
        "type_name", "linked_table", "table", "bag", "vec_map", "vec_set",
        "dynamic_field", "dynamic_object_field", "bcs", "hash", "ecdsa_k1",
        "vector", "option", "string", "ascii", "debug", "unit_test",
        "test_scenario", "test_utils",
    }

    def _get_function_code(
        self,
        module: str,
        function: str
    ) -> ToolResult:
        """获取函数代码（支持项目代码 + 外部依赖）"""
        # 🔥 检查是否为 Sui 标准库函数
        module_short = module.split("::")[-1] if "::" in module else module
        if module_short in self.SUI_STDLIB_MODULES:
            # 构造查找键
            func_key = f"{module_short}::{function}"
            description = self.SUI_STDLIB_FUNCTIONS.get(
                func_key,
                f"Sui 标准库函数，属于 {module_short} 模块。"
            )
            return ToolResult(
                success=True,
                data={
                    "id": f"sui::{module}::{function}",
                    "module": module,
                    "name": function,
                    "signature": f"fun {function}(...)",
                    "body": f"// Sui 标准库函数: {module}::{function}\n// 功能: {description}",
                    "visibility": "stdlib",
                    "file_path": "sui-framework",
                    "risk_indicators": {},
                    "is_stdlib": True,
                    "description": description
                },
                source="stdlib"
            )

        # 构造函数 ID
        if "::" in module:
            func_id = f"{module}::{function}"
        else:
            # 尝试查找匹配的完整 ID
            func_id = self._find_function_id(module, function)

        # 1. 先在项目代码中查找
        if func_id:
            for chunk in self.indexer.chunks:
                # 🔥 修复: 精确匹配函数 ID，或者模块名+函数名都匹配
                if chunk.id == func_id:
                    return ToolResult(
                        success=True,
                        data={
                            "id": chunk.id,
                            "module": chunk.module,
                            "name": chunk.name,
                            "signature": chunk.signature,
                            "body": chunk.body,
                            "visibility": chunk.visibility,
                            "file_path": chunk.file_path,
                            "risk_indicators": chunk.risk_indicators
                        },
                        source="index"
                    )

        # 🔥 修复: 模块匹配 - 只在模块名匹配时才返回
        # 避免 event::emit 被错误匹配到 config::emit
        for chunk in self.indexer.chunks:
            if chunk.name == function:
                # 检查模块名是否匹配 (支持部分匹配如 cetus_clmm::pool 匹配 pool)
                chunk_module = chunk.module.split("::")[-1]  # 取最后一级模块名
                if chunk_module == module or chunk.module == module:
                    return ToolResult(
                        success=True,
                        data={
                            "id": chunk.id,
                            "module": chunk.module,
                            "name": chunk.name,
                            "signature": chunk.signature,
                            "body": chunk.body,
                            "visibility": chunk.visibility,
                            "file_path": chunk.file_path,
                            "risk_indicators": chunk.risk_indicators
                        },
                        source="index"
                    )

        # 2. 在外部依赖中查找（Sui 标准库等）
        if self.indexer.dependency_resolver:
            # 🔥 智能匹配 Sui 标准库路径
            # LLM 可能给出不完整的路径如 "coin::from_balance"
            # 需要尝试多种可能的路径格式
            search_paths = [
                f"{module}::{function}",           # 原始路径
                f"sui::{module}::{function}",      # 添加 sui:: 前缀
                f"std::{module}::{function}",      # 添加 std:: 前缀
            ]

            for query_path in search_paths:
                impl = self.indexer.dependency_resolver.find_function(query_path, function)
                if impl:
                    return ToolResult(
                        success=True,
                        data={
                            "id": f"external::{query_path}",
                            "module": module,
                            "name": function,
                            "signature": self._extract_signature_from_impl(impl),
                            "body": impl,
                            "visibility": "external",
                            "file_path": f"~/.move (Sui stdlib)",
                            "risk_indicators": {}
                        },
                        source="dependency"
                    )

        # 🔥 v2.5.12: 找不到函数时，自动尝试正确的模块
        suggestions = []
        for chunk in self.indexer.chunks:
            if chunk.name == function:
                suggestions.append(chunk)

        if suggestions:
            # 🔥 自动使用第一个匹配的模块重试
            best_match = suggestions[0]
            print(f"       → 自动修正: {module}::{function} → {best_match.module}::{function}")
            return ToolResult(
                success=True,
                data={
                    "id": best_match.id,
                    "module": best_match.module,
                    "name": best_match.name,
                    "signature": best_match.signature,
                    "body": best_match.body,
                    "visibility": best_match.visibility,
                    "file_path": best_match.file_path,
                    "risk_indicators": best_match.risk_indicators,
                    "_auto_corrected": True,  # 标记为自动修正
                    "_original_query": f"{module}::{function}"
                },
                source="index"
            )

        return ToolResult(
            success=False,
            data=None,
            error=f"函数未找到: {module}::{function}。提示: 使用 get_function_index 查看可用函数列表",
            source="index"
        )

    def _extract_signature_from_impl(self, impl: str) -> str:
        """从函数实现中提取签名"""
        # 提取第一行（函数签名）
        lines = impl.strip().split('\n')
        if lines:
            sig = lines[0].strip()
            # 截取到 { 之前
            if '{' in sig:
                sig = sig[:sig.index('{')].strip()
            return sig
        return ""

    def _find_function_id(self, module: str, function: str) -> Optional[str]:
        """查找匹配的函数 ID

        🔥 修复: 更严格的模块匹配，避免部分匹配错误
        如 event 不应匹配 test_event
        """
        for chunk in self.indexer.chunks:
            if chunk.name == function:
                # 🔥 修复: 严格的模块匹配
                # chunk.id 格式: "package::module::function" 或 "module::function"
                chunk_module = chunk.module.split("::")[-1]  # 取最后一级模块名

                # 完全匹配模块名或最后一级模块名
                if chunk.module == module or chunk_module == module:
                    return chunk.id

                # 支持带包名的完整路径匹配
                if f"::{module}::" in chunk.id:
                    return chunk.id
        return None

    def _get_callers(
        self,
        module: str,
        function: str,
        depth: int = 2
    ) -> ToolResult:
        """获取调用者"""
        func_id = self._find_function_id(module, function)
        if not func_id:
            func_id = f"{module}::{function}"

        if self.indexer.callgraph_query and self.indexer.callgraph_status == "ok":
            node = self.indexer.callgraph_query.get_function(func_id)
            if not node:
                # 🔥 v2.5.6: 提供建议，帮助 Agent 找到正确的函数路径
                suggestions = []
                for chunk in self.indexer.chunks:
                    if chunk.name == function:
                        suggestions.append(f"{chunk.module}::{chunk.name}")

                if suggestions:
                    suggestion_str = ", ".join(suggestions[:3])
                    return ToolResult(
                        success=False,
                        data={"suggestions": suggestions[:3]},
                        error=f"函数在调用图中未找到: {func_id}。该函数存在于: {suggestion_str}",
                        source="callgraph"
                    )

                return ToolResult(
                    success=False,
                    data=None,
                    error=f"函数在调用图中未找到: {func_id}",
                    source="callgraph"
                )

            # 获取调用者 (called_by)
            caller_ids = node.get("called_by", [])
            enriched_callers = []
            for caller_id in caller_ids[:depth * 5]:
                chunk = next((c for c in self.indexer.chunks if c.id == caller_id), None)
                if chunk:
                    enriched_callers.append({
                        "id": caller_id,
                        "name": chunk.name,
                        "visibility": chunk.visibility,
                        "file_path": chunk.file_path,
                        "source": "callgraph",
                    })
                else:
                    enriched_callers.append({"id": caller_id, "source": "callgraph"})

            return ToolResult(
                success=True,
                data={
                    "target": func_id,
                    "callers": enriched_callers,
                    "depth": depth,
                    "callgraph_status": self.indexer.callgraph_status,
                },
                source="callgraph"
            )
        else:
            return ToolResult(
                success=False,
                data=None,
                error=f"调用图不可用 (状态: {self.indexer.callgraph_status})",
                source="callgraph"
            )

    def _get_callees(
        self,
        module: str,
        function: str,
        depth: int = 2
    ) -> ToolResult:
        """获取被调用者"""
        func_id = self._find_function_id(module, function)
        if not func_id:
            func_id = f"{module}::{function}"

        if self.indexer.callgraph_query and self.indexer.callgraph_status == "ok":
            node = self.indexer.callgraph_query.get_function(func_id)
            if not node:
                # 🔥 v2.5.6: 提供建议，帮助 Agent 找到正确的函数路径
                suggestions = []
                for chunk in self.indexer.chunks:
                    if chunk.name == function:
                        suggestions.append(f"{chunk.module}::{chunk.name}")

                if suggestions:
                    suggestion_str = ", ".join(suggestions[:3])
                    return ToolResult(
                        success=False,
                        data={"suggestions": suggestions[:3]},
                        error=f"函数在调用图中未找到: {func_id}。该函数存在于: {suggestion_str}",
                        source="callgraph"
                    )

                return ToolResult(
                    success=False,
                    data=None,
                    error=f"函数在调用图中未找到: {func_id}",
                    source="callgraph"
                )

            # 获取被调用者 (calls)
            callee_ids = node.get("calls", [])
            enriched_callees = []
            for callee_id in callee_ids[:depth * 5]:
                chunk = next((c for c in self.indexer.chunks if c.id == callee_id), None)
                if chunk:
                    enriched_callees.append({
                        "id": callee_id,
                        "name": chunk.name,
                        "visibility": chunk.visibility,
                        "file_path": chunk.file_path,
                        "source": "callgraph",
                    })
                else:
                    enriched_callees.append({"id": callee_id, "source": "callgraph"})

            return ToolResult(
                success=True,
                data={
                    "target": func_id,
                    "callees": enriched_callees,
                    "depth": depth,
                    "callgraph_status": self.indexer.callgraph_status,
                },
                source="callgraph"
            )
        else:
            return ToolResult(
                success=False,
                data=None,
                error=f"调用图不可用 (状态: {self.indexer.callgraph_status})",
                source="callgraph"
            )

    def _get_type_definition(self, type_name: str) -> ToolResult:
        """获取类型定义（支持项目代码 + 外部依赖 + 常量）"""
        import re

        # 🔥 智能处理泛型类型: Balance<VOTE> → Balance, Coin<T> → Coin
        clean_name = re.sub(r'<[^>]*>', '', type_name).strip()

        # 支持 "Pool" 或 "lending::Pool" 或 "sui::balance::Balance" 格式
        # 取最后一个部分作为类型名
        search_name = clean_name.split("::")[-1] if "::" in clean_name else clean_name

        # 1. 先在项目代码中查找 struct
        for module_info in self.indexer.modules.values():
            for struct in module_info.structs:
                if struct["name"] == search_name:
                    return ToolResult(
                        success=True,
                        data={
                            "name": struct["name"],
                            "module": module_info.name,
                            "file_path": module_info.path,
                            "body": struct["body"],
                            "abilities": struct.get("abilities", [])
                        },
                        source="index"
                    )

        # 1.5 🔥 v2.5.4: 在项目代码中查找常量 (错误码如 ETypeNotFoundInPool)
        for module_info in self.indexer.modules.values():
            for const in module_info.constants:
                if const["name"] == search_name:
                    return ToolResult(
                        success=True,
                        data={
                            "name": const["name"],
                            "module": module_info.name,
                            "file_path": module_info.path,
                            "body": const["signature"],
                            "type": const.get("type", ""),
                            "value": const.get("value", ""),
                            "is_constant": True
                        },
                        source="index"
                    )

        # 2. 在外部依赖中查找（Sui 标准库等）
        if self.indexer.dependency_resolver:
            struct_def = self._find_external_struct(search_name)
            if struct_def:
                return ToolResult(
                    success=True,
                    data=struct_def,
                    source="dependency"
                )

        # 🔥 v2.5.5: 检查是否是字符串字面量中的内容 (避免 AI 误解)
        # 例如 "CTF{MoveCTF-Task2}" 中的 CTF, MoveCTF, Task2 或 b"WLP" 中的 WLP
        for module_info in self.indexer.modules.values():
            # 使用 getattr 安全访问，兼容旧版 indexer
            if search_name in getattr(module_info, 'string_literals', set()):
                return ToolResult(
                    success=True,
                    data={
                        "name": search_name,
                        "is_string_literal": True,
                        "note": f"'{search_name}' 是代码中字符串字面量的内容，不是类型或常量定义。"
                    },
                    source="string_literal"
                )

        return ToolResult(
            success=False,
            data=None,
            error=f"类型未找到: {type_name} (搜索: {search_name})",
            source="index"
        )

    def _find_external_struct(self, struct_name: str) -> Optional[dict]:
        """在外部依赖中查找 struct 定义"""
        import re
        from pathlib import Path

        for dep_name, dep in self.indexer.dependency_resolver.dependencies.items():
            if not dep.local_path:
                continue

            dep_path = Path(dep.local_path)

            # 搜索 .move 文件
            for move_file in dep_path.rglob("*.move"):
                try:
                    with open(move_file, "r", encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    continue

                # 查找 struct 定义
                # 支持格式:
                # - struct Name { ... }
                # - public struct Name has key, store { ... }
                # - public struct Coin<phantom T> has key, store { ... }  (带泛型)
                pattern = rf'(?:public\s+)?struct\s+{re.escape(struct_name)}\s*(?:<[^>]+>)?\s*(?:has\s+[\w,\s]+)?\s*\{{'
                match = re.search(pattern, content)
                if match:
                    # 提取完整的 struct 定义
                    start = match.start()
                    brace_count = 0
                    end = start

                    for i, char in enumerate(content[start:], start=start):
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                end = i + 1
                                break

                    struct_body = content[start:end].strip()

                    # 提取 abilities
                    abilities_match = re.search(r'has\s+([\w,\s]+)\s*\{', struct_body)
                    abilities = []
                    if abilities_match:
                        abilities = [a.strip() for a in abilities_match.group(1).split(',')]

                    return {
                        "name": struct_name,
                        "module": move_file.stem,
                        "file_path": f"~/.move ({dep_name})",
                        "body": struct_body,
                        "abilities": abilities
                    }

        return None

    def _search_code(self, pattern: str, regex: bool = True) -> ToolResult:
        """搜索代码"""
        results = self.indexer.search_code(pattern, regex=regex)

        # 扩展结果信息
        enriched_results = []
        for r in results[:20]:
            chunk = next((c for c in self.indexer.chunks if c.id == r.get("id")), None)
            if chunk:
                enriched_results.append({
                    **r,
                    "visibility": chunk.visibility,
                    "file_path": chunk.file_path,
                    "source": "index",
                })
            else:
                enriched_results.append({**r, "source": "index"})

        return ToolResult(
            success=True,
            data={
                "pattern": pattern,
                "match_count": len(results),
                "matches": enriched_results,
            },
            source="index"
        )

    def _get_project_overview(self, max_tokens: int = 5000) -> ToolResult:
        """获取项目概览"""
        overview = self.indexer.get_project_overview(max_tokens=max_tokens)
        return ToolResult(
            success=True,
            data={
                "overview": overview,
                "module_count": len(self.indexer.modules),
                "function_count": len(self.indexer.chunks),
                "callgraph_status": self.indexer.callgraph_status,
            },
            source="index"
        )

    def _get_function_context(
        self,
        module: str,
        function: str,
        depth: int = 2
    ) -> ToolResult:
        """获取函数完整上下文"""
        func_id = self._find_function_id(module, function)
        if not func_id:
            func_id = f"{module}::{function}"

        ctx = self.indexer.get_function_context(
            func_id,
            depth=depth,
            include_external=True
        )

        if ctx["target"]:
            # 来源混合：index + callgraph
            source = "index+callgraph" if self.indexer.callgraph_status == "ok" else "index"
            return ToolResult(
                success=True,
                data=ctx,
                source=source
            )
        else:
            return ToolResult(
                success=False,
                data=None,
                error=f"函数未找到: {func_id}",
                source="index"
            )

    def _get_entry_points(self) -> ToolResult:
        """获取入口函数"""
        entry_points = self.indexer.get_entry_points()

        # 扩展入口点信息
        enriched_entries = []
        for ep in entry_points:
            chunk = next((c for c in self.indexer.chunks if c.id == ep["id"]), None)
            enriched_entries.append({
                **ep,
                "file_path": chunk.file_path if chunk else "",
                "risk_indicators": chunk.risk_indicators if chunk else {},
                "source": "index",
            })

        return ToolResult(
            success=True,
            data={
                "entry_points": enriched_entries,
                "count": len(entry_points),
                "callgraph_status": self.indexer.callgraph_status,
            },
            source="index"
        )

    # ==========================================================================
    # 公共接口
    # ==========================================================================

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """
        获取所有工具定义 (OpenAI/Anthropic function calling 格式)

        Returns:
            工具定义列表
        """
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters
            }
            for tool in self._tools.values()
        ]

    def call_tool(self, name: str, arguments: Dict[str, Any], caller: str = "") -> ToolResult:
        """
        调用工具 (带统一错误处理)

        Args:
            name: 工具名称
            arguments: 工具参数
            caller: 调用者标识 (用于日志)

        Returns:
            工具调用结果 (永远不会抛异常，错误通过 ToolResult.error 返回)
        """
        # 1. 检查工具是否存在
        if name not in self._tools:
            return ToolResult(
                success=False,
                data=None,
                error=f"未知工具: {name}",
                source="toolkit"
            )

        tool = self._tools[name]

        # 2. 验证必需参数
        schema = tool.parameters
        required_params = schema.get("required", [])
        missing_params = [p for p in required_params if p not in arguments]
        if missing_params:
            return ToolResult(
                success=False,
                data=None,
                error=f"缺少必需参数: {missing_params}",
                source="toolkit"
            )

        # 3. 打印工具调用日志
        caller_tag = f"[{caller}] " if caller else ""
        args_str = ", ".join(f"{k}={v}" for k, v in arguments.items())
        print(f"    🔧 {caller_tag}Tool: {name}({args_str})")

        # 4. 执行工具调用 (统一异常捕获)
        try:
            result = tool.handler(**arguments)

            # 打印结果摘要
            if result.success:
                if isinstance(result.data, dict):
                    if "callers" in result.data:
                        print(f"       → 找到 {len(result.data['callers'])} 个调用者")
                    elif "callees" in result.data:
                        print(f"       → 找到 {len(result.data['callees'])} 个被调用者")
                    elif "body" in result.data:
                        print(f"       → 获取到 {len(result.data.get('body', ''))} 字符")
                    elif "count" in result.data:
                        print(f"       → 返回 {result.data['count']} 项")
                    else:
                        print(f"       → 成功")
            else:
                print(f"       → 失败: {result.error}")
            return result

        except KeyError as e:
            error_msg = f"参数错误 - 缺少键: {e}"
            print(f"       → {error_msg}")
            return ToolResult(success=False, data=None, error=error_msg, source="toolkit")

        except TypeError as e:
            error_msg = f"类型错误: {e}"
            print(f"       → {error_msg}")
            return ToolResult(success=False, data=None, error=error_msg, source="toolkit")

        except ValueError as e:
            error_msg = f"值错误: {e}"
            print(f"       → {error_msg}")
            return ToolResult(success=False, data=None, error=error_msg, source="toolkit")

        except Exception as e:
            error_msg = f"工具调用异常: {type(e).__name__}: {e}"
            print(f"       → {error_msg}")
            return ToolResult(success=False, data=None, error=error_msg, source="toolkit")

    def get_function_index(self, max_functions: int = 100) -> str:
        """
        🔥 生成函数索引摘要，让 AI 知道有哪些函数可以查询

        Returns:
            格式化的函数列表字符串
        """
        lines = ["## 可用函数索引\n"]
        lines.append("以下是项目中的所有函数，你可以使用 `get_function_code` 工具查看任意函数的实现。")
        lines.append("🔥 **重要**: 查询时请使用完整的模块名，例如 `get_function_code(module='config', function='check_pool_manager_role')`\n")

        # 按模块分组
        modules: Dict[str, List] = {}
        for chunk in self.indexer.chunks[:max_functions]:
            module = chunk.module
            if module not in modules:
                modules[module] = []
            modules[module].append(chunk)

        for module_name, chunks in modules.items():
            # 🔥 v2.5.12: 提取简短模块名 (去掉 cetus_clmm:: 前缀)
            short_module = module_name.split("::")[-1] if "::" in module_name else module_name
            lines.append(f"\n### 📦 {module_name}")
            lines.append(f"   查询示例: `get_function_code(module='{short_module}', function='...')`")
            for chunk in chunks:
                # 格式: - function_name [visibility] (risk: X)
                risk_score = chunk.risk_indicators.get("risk_score", 0) if chunk.risk_indicators else 0
                risk_tag = f" ⚠️ risk:{risk_score}" if risk_score > 50 else ""
                vis_tag = f"[{chunk.visibility}]" if chunk.visibility != "private" else "[private]"
                lines.append(f"  - `{chunk.name}` {vis_tag}{risk_tag}")

        lines.append(f"\n共 {len(self.indexer.chunks)} 个函数")
        return "\n".join(lines)

    def get_analysis_context(self) -> str:
        """
        🔥 生成 Phase 0/1 分析上下文摘要，作为 AI 的背景知识

        Returns:
            格式化的分析上下文
        """
        lines = ["## 合约分析上下文\n"]

        # 1. 函数功能概览
        purposes = self.contract_analysis.get("function_purposes", {})
        if purposes:
            lines.append("### 函数功能说明")
            for func_id, purpose in list(purposes.items())[:20]:
                func_name = func_id.split("::")[-1]
                lines.append(f"  - `{func_name}`: {purpose[:100]}")
            lines.append("")

        # 2. 智能预分析提示
        hints = self.contract_analysis.get("analysis_hints", {})
        if hints:
            lines.append("### 关键分析提示")

            # 关键状态变量
            if hints.get("key_state_variables"):
                lines.append("**关键状态变量:**")
                for var in hints["key_state_variables"][:5]:
                    if isinstance(var, dict):
                        lines.append(f"  - {var.get('name', '?')}: {var.get('description', '')[:50]}")
                    else:
                        lines.append(f"  - {var}")

            # 潜在漏洞链
            if hints.get("potential_vuln_chains"):
                lines.append("\n**潜在漏洞链:**")
                for chain in hints["potential_vuln_chains"][:3]:
                    if isinstance(chain, dict):
                        lines.append(f"  - {chain.get('description', str(chain))[:80]}")
                    else:
                        lines.append(f"  - {chain[:80]}")

            lines.append("")

        # 3. 调用图摘要
        if self.indexer.callgraph:
            cg = self.indexer.callgraph
            nodes = len(cg.get("nodes", []))
            edges = len(cg.get("edges", []))
            lines.append(f"### 调用图: {nodes} 节点, {edges} 边")

        return "\n".join(lines)

    def get_security_tools(self) -> List[Dict[str, Any]]:
        """
        🔥 获取安全审计相关的工具子集 (供 Phase 2/3/4 使用)

        包含代码检索 + 安全知识查询工具
        """
        security_tool_names = [
            # 代码检索
            "get_function_code",
            "get_callers",
            "get_callees",
            "get_type_definition",
            "search_code",
            "get_function_context",
            "get_function_purpose",
            "get_analysis_hints",
            # 🔥 v2.5.4: 安全知识按需查询
            "query_security_knowledge",      # 查询 Sui Move 安全知识
            "search_vulnerability_patterns", # 搜索历史漏洞模式 (RAG)
            # 🔥 v2.5.5: 自动安全模式检测
            "check_flashloan_security",      # 自动检测闪电贷安全性 (Hot Potato + 类型验证)
            # 🔥 v2.5.24: 漏洞利用分析工具 (供 WhiteHat Agent)
            "get_exploit_examples",          # 获取漏洞利用示例
            "get_risky_functions",           # 获取高风险函数列表
            "get_callgraph_summary",         # 获取调用图摘要
            "get_module_structure",          # 获取模块结构概览
        ]
        return self.get_tools_for_llm(tool_names=security_tool_names)

    def get_tools_for_llm(self, provider: str = "openai", tool_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        获取适配特定 LLM Provider 的工具格式

        Args:
            provider: LLM 提供商 ("openai", "anthropic", "dashscope")
            tool_names: 可选，只返回指定名称的工具

        Returns:
            工具定义列表
        """
        # 过滤工具
        tools = self._tools.values()
        if tool_names:
            tools = [t for t in tools if t.name in tool_names]

        if provider == "anthropic":
            # Anthropic 格式
            return [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.parameters
                }
                for tool in tools
            ]
        else:
            # OpenAI / DashScope 格式
            return [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters
                    }
                }
                for tool in tools
            ]

    # ==========================================================================
    # 安全向量库工具实现
    # ==========================================================================

    def _search_vulnerability_patterns(
        self,
        query: str,
        top_k: int = 5,
        severity_filter: str = "all"
    ) -> ToolResult:
        """搜索漏洞模式"""
        if not self.security_scanner or not self.security_scanner.vector_db:
            return ToolResult(
                success=False,
                data=None,
                error="安全向量库未初始化。请确保 SecurityScanner 已配置向量库。",
                source="vector_db"
            )

        try:
            # 使用向量库进行语义搜索 (多获取一些以便过滤)
            fetch_k = top_k * 3 if severity_filter != "all" else top_k
            results = self.security_scanner.vector_db.similarity_search(query, k=fetch_k)

            patterns = []
            for doc in results:
                severity = doc.metadata.get("severity", "").lower()

                # 严重性过滤
                if severity_filter != "all":
                    if severity_filter == "critical" and severity != "critical":
                        continue
                    elif severity_filter == "high" and severity not in ["critical", "high"]:
                        continue
                    elif severity_filter == "medium" and severity not in ["critical", "high", "medium"]:
                        continue

                patterns.append({
                    "content": doc.page_content,
                    "pattern_id": doc.metadata.get("pattern_id", ""),
                    "severity": doc.metadata.get("severity", ""),
                    "issue_tags": doc.metadata.get("issue_tags", ""),
                    "source": doc.metadata.get("source", "")
                })

                # 达到 top_k 数量后停止
                if len(patterns) >= top_k:
                    break

            return ToolResult(
                success=True,
                data={
                    "query": query,
                    "count": len(patterns),
                    "patterns": patterns
                },
                source="vector_db"
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data=None,
                error=f"向量搜索失败: {e}",
                source="vector_db"
            )

    def _get_exploit_examples(
        self,
        vuln_type: str,
        top_k: int = 3
    ) -> ToolResult:
        """获取漏洞利用案例"""
        if not self.security_scanner or not self.security_scanner.vector_db:
            return ToolResult(
                success=False,
                data=None,
                error="安全向量库未初始化",
                source="vector_db"
            )

        try:
            # 构建查询：搜索该类型的利用案例
            query = f"{vuln_type} exploit attack vulnerability how to exploit"
            results = self.security_scanner.vector_db.similarity_search(query, k=top_k)

            examples = []
            for doc in results:
                examples.append({
                    "pattern_id": doc.metadata.get("pattern_id", ""),
                    "severity": doc.metadata.get("severity", ""),
                    "content": doc.page_content,
                    "tags": doc.metadata.get("issue_tags", "")
                })

            return ToolResult(
                success=True,
                data={
                    "vuln_type": vuln_type,
                    "count": len(examples),
                    "examples": examples
                },
                source="vector_db"
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data=None,
                error=f"获取利用案例失败: {e}",
                source="vector_db"
            )

    # ==========================================================================
    # 🔥 v2.5.4: 安全知识库按需查询实现
    # ==========================================================================

    def _query_security_knowledge(
        self,
        topic: str,
        include_examples: bool = True
    ) -> ToolResult:
        """
        查询 Sui Move 安全知识库

        Args:
            topic: 查询主题 ('hot_potato', 'flashloan', 'capability', 'false_positive', etc.)
            include_examples: 是否包含代码示例
        """
        # 知识库索引 (topic -> 知识内容)
        KNOWLEDGE_BASE = {
            # Hot Potato / 闪电贷
            "hot_potato": """## Hot Potato 模式 (闪电贷强制还款)
**别名**: 热土豆, receipt_pattern, flash_receipt, 强制还款

**原理**: 没有任何能力 (no drop, no copy, no store, no key) 的结构体必须被显式消费

**安全保证**: 借款人必须调用 repay 函数，否则交易在 Move VM 层面失败

**示例代码**:
```move
// ✅ 安全: Receipt 没有 drop，必须被 repay 消费
public struct FlashReceipt {  // 没有任何 ability！
    pool_id: ID,
    amount: u64,
    type_name: TypeName,  // 关键：记录借出的币种
}

// 借款返回 Receipt (必须被消费)
public fun flashloan<A>(pool: &mut Pool, amount: u64): (Coin<A>, FlashReceipt)

// 还款消费 Receipt
public fun repay<A>(pool: &mut Pool, receipt: FlashReceipt, coin: Coin<A>)
```

**常见误报**:
- "闪电贷无强制还款" → 如果 Receipt 没有 drop，这是误报

**真实漏洞关注点**:
⚠️ **还款类型混淆**: repay 函数必须验证 `type_name::get<A>() == receipt.type_name`
- 如果只检查 `contains_type<A>(pool)` 而不检查类型匹配 → 可以借 CoinA 还 CoinB → 严重漏洞！
""",

            "flashloan": """## 闪电贷安全审计要点
**别名**: 闪电贷, flash_loan, flash-loan, 闪贷

**Hot Potato 模式** (见 'hot_potato' 主题)

**真实漏洞检查清单**:
1. ⚠️ **类型混淆**: 还款币种是否与借款币种一致？
   - Receipt 应存储 `type_name: TypeName` (借出币种)
   - repay 应验证 `type_name::get<RepaidCoin>() == receipt.type_name`
   - 漏洞: 仅检查 `contains_type` 不够！

2. 还款金额: `repaid_amount >= borrowed_amount + fee`

3. 池 ID 验证: 还款到正确的池子

4. 重入检查: 闪电贷期间是否有其他操作可执行？

**漏洞案例**:
```move
// 🔴 漏洞代码 - 没有验证类型匹配
public fun repay<A>(pool: &mut Pool, receipt: FlashReceipt, coin: Coin<A>) {
    assert!(contains_type<A>(pool), ETypeNotInPool);  // 只检查池里有该币
    // ❌ 缺少: assert!(type_name::get<A>() == receipt.type_name)
    deposit(pool, coin);
}
// 攻击: 借 CoinA，还 CoinB → CoinA 池被掏空
```
""",

            "capability": """## Capability 权限模式

**原理**: 持有 Capability 对象 = 拥有权限

**标准用法**: `_: &AdminCap` 或 `cap: &TreasuryCap<T>` 作为函数参数

**安全保证**: 调用者必须持有该 Cap 才能调用函数

**示例**:
```move
// ✅ 安全: 只有持有 AdminCap 的人才能调用
public fun admin_function(_: &AdminCap, config: &mut Config) { ... }

// ⚠️ 不安全: 没有权限检查
public fun admin_function(config: &mut Config) { ... }
```

**审计要点**:
- 敏感函数 (set_xxx, update_xxx, withdraw) 是否需要 Cap？
- Cap 是否被错误地 share_object() 或 public_transfer()？
""",

            "false_positive": """## 常见误报判断指南

| 漏洞描述 | 判断 | 原因 |
|---------|------|------|
| "整数溢出绕过验证" | ❌ 误报 | Move VM 溢出会 abort，不会回绕 |
| "重入攻击风险" | ❌ 误报 | Move 没有动态调度 |
| "双花攻击" | ❌ 误报 (除非有 copy) | 线性类型系统保护 |
| "init 可被多次调用" | ❌ 误报 | Sui 运行时保护 |
| "TxContext 可伪造" | ❌ 误报 | VM 注入 |
| "闪电贷无强制还款" | ⚠️ 检查 Receipt | Hot Potato 没有 drop = 强制消费 |
| "public 函数无权限" | ⚠️ 检查 Cap 参数 | Capability 模式 |

**判断流程**:
1. 看到 "无权限" → 检查是否有 Cap 参数 或 public(package)
2. 看到 "溢出" → 普通算术最多 DoS，位运算才是真风险
3. 看到 "闪电贷" → 检查 Receipt 的 ability，关注类型匹配
""",

            "overflow": """## 算术溢出保护
**别名**: 溢出, integer_overflow, 整数溢出, arithmetic_overflow, overflow_check, 溢出检查

**Move VM 保护**: 所有算术运算 (+, -, *, /) 自动检查溢出，溢出会 abort

**不会静默回绕**: 与 Solidity 0.7 不同，Move 不会让 MAX + 1 = 0

**例外 - 位运算不检查**:
```move
// ⚠️ 位运算不检查溢出！
let shifted = value << 64;  // 危险：可能产生意外结果
```

**审计要点**:
- 普通算术溢出 → 最多是 DoS (交易 abort)
- 位运算溢出 → 真实风险，需要检查
""",

            "reentrancy": """## 重入攻击保护

**Move 原生保护**: 没有动态调度 (dynamic dispatch)

**所有函数调用在编译时确定**: 无法在运行时改变调用目标

**没有 Solidity 的 fallback/receive**: 没有原生代币转账触发的回调

**结论**: 传统重入攻击在 Move 中不存在

**注意**: 共享对象的并发访问仍需考虑，但这不是传统意义上的重入
""",

            "type_confusion": """## 泛型类型混淆漏洞
**别名**: 类型混淆, 泛型混淆, generic_type_safety, type-safety, phantom_type, 类型安全

**问题模式**:
```move
// 函数接受泛型 Coin<T>
public fun process<T>(pool: &mut Pool, coin: Coin<T>) {
    // ❌ 只检查 T 在池里存在，不检查是否是预期类型
    assert!(pool.contains_type<T>(), ETypeNotInPool);
    // ...
}
```

**漏洞场景**:
- 闪电贷借 CoinA，还 CoinB → 池子混乱
- Swap 时传入错误的币种

**正确做法**:
```move
// ✅ 验证类型匹配
assert!(type_name::get<T>() == expected_type_name, ETypeMismatch);
```
""",

            # 🔥 v2.5.5: 新增主题
            "ownership": """## 对象所有权安全

**Sui 对象所有权类型**:
1. **Owned Object**: 属于单一地址，只有所有者可操作
2. **Shared Object**: 任何人可访问，需要内部 ACL
3. **Immutable Object**: 不可变，任何人可读

**常见误报**:
- "未验证对象所有者" → Sui 运行时自动验证 Owned Object 的所有权
- 对于 `&mut T` 参数，调用者必须是对象所有者

**真实风险**:
1. **Shared Object 无 ACL**: 共享对象需要内部权限检查
```move
// ⚠️ 共享对象需要额外的权限检查
public fun update(shared_config: &mut Config) {
    // 任何人都能调用！需要 Cap 或 sender 检查
}
```

2. **key+store 对象可被转移**: 有 store 能力的对象可被包装或转移
```move
// ⚠️ 有 store 能力 = 可被自由转移
struct MyObject has key, store { ... }
```

**审计要点**:
- Shared Object 是否有适当的访问控制？
- 敏感对象是否不应该有 store 能力？
""",

            "access_control": """## 访问控制模式

**Sui Move 访问控制方式**:

1. **Capability 模式** (推荐):
```move
// ✅ 只有持有 AdminCap 才能调用
public fun admin_only(_: &AdminCap, ...) { ... }
```

2. **Sender 检查**:
```move
// ✅ 检查调用者地址
assert!(tx_context::sender(ctx) == config.admin, EUnauthorized);
```

3. **对象所有权** (自动):
```move
// ✅ Owned Object 自动验证所有权
public fun transfer_my_nft(nft: MyNFT, ...) { ... }
```

**常见误报**:
- "public 函数无权限检查" → 检查是否有 Cap 参数或是 Owned Object
- "任意用户可调用" → 检查函数参数是否包含权限对象

**真实风险**:
- 敏感操作 (提款、配置更新) 缺少 Cap 或 sender 检查
- AdminCap 被 share_object() 导致任何人成为管理员
""",

            "slippage_control": """## 滑点控制
**别名**: 滑点, slippage, slippage_protection, price_impact, 价格影响, min_amount_out

**什么是滑点**:
交易执行价格与预期价格的差异，在 AMM/DEX 中尤为重要

**风险场景**:
1. 价格在交易执行前被操纵 (三明治攻击)
2. 大额交易导致价格滑动

**正确实现**:
```move
// ✅ 带滑点保护的 swap
public fun swap_with_slippage(
    pool: &mut Pool,
    coin_in: Coin<A>,
    min_amount_out: u64,  // 最小接收量
    ctx: &mut TxContext
): Coin<B> {
    let amount_out = do_swap(pool, coin_in);
    assert!(coin::value(&amount_out) >= min_amount_out, ESlippageExceeded);
    amount_out
}
```

**审计要点**:
- swap/remove_liquidity 是否有 `min_amount_out` 参数？
- add_liquidity 是否有 `min_lp_out` 参数？
- 这些参数是否被正确使用？

**常见漏洞**:
```move
// ❌ 无滑点保护
public fun swap(pool: &mut Pool, coin_in: Coin<A>): Coin<B> {
    // 用户可能收到比预期少很多的代币
}
```
""",

            "tick_price": """## Tick-Price 映射 (CLMM)
**别名**: tick, tick_spacing, clmm, sqrt_price, concentrated_liquidity, 集中流动性, tick-price

**什么是 CLMM**:
集中流动性做市商 (Concentrated Liquidity Market Maker)，如 Uniswap V3、Cetus

**Tick 概念**:
- 价格空间被离散化为 tick
- 每个 tick 对应一个价格: `price = 1.0001^tick`
- 流动性提供者选择价格区间 [tick_lower, tick_upper]

**常见问题**:
1. **Tick 越界**: tick 超出有效范围 [-887272, 887272]
2. **Tick 间距**: 不同手续费档位有不同的 tick 间距
3. **价格精度**: tick 到 sqrt_price 的转换精度

**审计要点**:
```move
// ✅ 验证 tick 范围
assert!(tick >= MIN_TICK && tick <= MAX_TICK, ETickOutOfRange);

// ✅ 验证 tick 间距
assert!(tick % tick_spacing == 0, EInvalidTickSpacing);
```

**常见漏洞**:
- `get_sqrt_price_at_tick` 函数覆盖不完整
- tick 边界条件处理错误
- 价格计算精度损失
""",

            # 🔥 v2.5.6: 新增主题
            "dynamic_field": """## 动态字段 (Dynamic Field)

**什么是动态字段**:
Sui 允许在运行时向对象添加/删除字段，绕过静态类型系统

**两种类型**:
1. **dynamic_field**: 值存储在字段中
2. **dynamic_object_field**: 值是独立对象（有自己的 ID）

**常见用法**:
```move
// 添加动态字段
dynamic_field::add(&mut obj.id, key, value);

// 检查是否存在
dynamic_field::exists_(&obj.id, key);

// 借用字段
let val = dynamic_field::borrow<K, V>(&obj.id, key);

// 移除字段
let val = dynamic_field::remove<K, V>(&mut obj.id, key);
```

**安全考量**:
1. **类型安全**: 使用 `exists_with_type` 检查类型
```move
// ✅ 检查存在性和类型
assert!(
    dynamic_field::exists_with_type<vector<u8>, u64>(&obj.id, key),
    EFieldNotFound
);
```

2. **字段覆盖**: add 前应检查是否已存在
```move
// ⚠️ 如果字段已存在会 abort
dynamic_field::add(&mut obj.id, key, value);  // 重复添加会失败
```

3. **孤儿字段**: 对象销毁前应清理动态字段

**常见误报**:
- "动态字段可被篡改" → 需要 &mut UID，有对象所有权保护
""",

            "string_length_limit": """## 字符串长度限制

**为什么需要限制**:
无限长字符串会导致:
1. 存储成本攻击: 攻击者创建超长字符串消耗存储
2. Gas 消耗攻击: 处理超长字符串消耗大量 gas
3. DoS 攻击: 让交易因超出限制而失败

**最佳实践**:
```move
// ✅ 限制字符串长度
const MAX_NAME_LENGTH: u64 = 256;
const MAX_URL_LENGTH: u64 = 2048;

public fun set_name(obj: &mut Object, name: String) {
    assert!(string::length(&name) <= MAX_NAME_LENGTH, ENameTooLong);
    obj.name = name;
}
```

**常见场景**:
1. **URL 字段**: 限制 2048 字符左右
2. **名称字段**: 限制 64-256 字符
3. **描述字段**: 限制 1024-4096 字符

**审计要点**:
- 用户可控的字符串输入是否有长度限制？
- 空字符串是否被允许？

**风险等级**:
- 无限制 → MEDIUM (资源消耗攻击)
- 有限制 → 安全
""",

            "precision": """## 精度与舍入

**Move 中的数值类型**:
- u8, u16, u32, u64, u128, u256 (无符号整数)
- 没有原生浮点数支持

**常见精度问题**:
1. **除法截断**: Move 除法向下取整
```move
let result = 10 / 3;  // result = 3, 不是 3.33...
```

2. **乘除顺序**: 先乘后除减少精度损失
```move
// ❌ 先除后乘，精度损失
let bad = (amount / 100) * fee_rate;

// ✅ 先乘后除，保留精度
let good = (amount * fee_rate) / 100;
```

3. **定点数表示**: 用大整数模拟小数
```move
// 18 位小数精度 (类似 ERC20)
const PRECISION: u128 = 1_000_000_000_000_000_000;
let scaled_amount = (amount as u128) * PRECISION;
```

**审计要点**:
- 费用计算是否可能因舍入而为 0？
- 大金额运算是否可能溢出？
- 精度损失是否会累积？

**常见漏洞**:
```move
// ❌ 小金额手续费可能为 0
let fee = amount * fee_rate / 10000;  // 如果 amount * fee_rate < 10000，fee = 0
```
""",

            "module_layering": """## 模块分层设计模式

**什么是模块分层**:
Move 项目常采用分层架构：低层模块提供基础功能，高层模块添加业务逻辑和权限控制。

**典型分层结构**:
```
高层模块 (有权限检查)              低层模块 (无权限检查)
├── config.move                   ├── acl.move
│   └── add_role(&AdminCap, ...)  │   └── add_role(acl, member, role)
├── pool.move                     ├── xxx_math.move
│   └── swap(&PoolCap, ...)       │   └── compute_xxx(a, b)
└── factory.move                  └── xxx_utils.move
    └── create(...)                   └── helper_xxx(...)
```

**为什么低层模块不做权限检查**:
1. **职责分离**: 低层只负责数据操作，不关心调用者身份
2. **复用性**: 可被多个高层模块复用
3. **权限由调用者保证**: 高层 wrapper 负责验证权限后再调用

**如何识别低层模块**:
- 模块名特征: `acl`, `math`, `utils`, `helper`, `lib`, `core`, `types`, `errors`
- 或后缀模式: `xxx_math`, `xxx_utils`, `xxx_acl`
- 函数接收数据引用 (`&mut ACL`) 而非 Capability

**审计判断流程**:
1. 发现"无权限检查"漏洞
2. **使用 `get_callers(module, function)` 查看调用者**
3. 如果调用者是高层 wrapper 且有权限检查 → **误报**
4. 如果没有 wrapper 或 wrapper 也无权限 → **真实漏洞**

**示例**:
```move
// acl.move - 低层模块 (无权限检查是正确设计!)
public fun add_role(acl: &mut ACL, member: address, role: u8) { ... }

// config.move - 高层模块 (wrapper 有权限检查)
public fun add_role(_: &AdminCap, config: &mut GlobalConfig, member: address, role: u8) {
    acl::add_role(&mut config.acl, member, role);  // ✅ 通过 Capability 保护
}
```

**常见误报**:
| 漏洞描述 | 判断 | 验证方法 |
|---------|------|----------|
| "acl::add_role 无权限" | 检查 callers | `get_callers(acl, add_role)` → 看 config 是否有 Cap |
| "math::compute 任意调用" | 通常误报 | 纯计算函数，无状态修改风险 |
| "utils::helper 缺少验证" | 检查 callers | 由调用者保证参数有效性 |
""",

            # 🔥 v2.5.6: 新增知识主题
            "shared_object": """## Sui 共享对象 (Shared Object)

**什么是共享对象**:
在 Sui 中，对象可以是 owned (被特定地址拥有) 或 shared (任何人都可以访问)。

**共享对象特点**:
1. 通过 `transfer::share_object(obj)` 创建
2. 任何人都可以在交易中引用
3. 需要通过共识排序 (比 owned 对象慢)

**安全考量**:
- 共享对象本身不是漏洞
- 共享对象需要内部访问控制机制
- 常见模式: 共享对象 + Capability 权限控制

**常见误报**:
| 漏洞描述 | 判断 |
|---------|------|
| "共享对象可被任意访问" | 检查是否有内部权限控制 |
| "share_object 后任意修改" | 检查修改函数是否需要 Capability |

**示例**:
```move
// 正确模式: 共享对象 + 权限控制
public struct Pool has key { id: UID, ... }
public struct AdminCap has key, store { id: UID }

fun init(ctx: &mut TxContext) {
    transfer::share_object(Pool { ... });  // 共享池
    transfer::transfer(AdminCap { ... }, sender(ctx));  // 只有创建者有 AdminCap
}

// 修改需要 AdminCap
public fun update_fee(_: &AdminCap, pool: &mut Pool, fee: u64) { ... }
```
""",

            "public_package": """## public(package) 可见性

**什么是 public(package)**:
Move 2024 引入的新可见性修饰符，函数只能被同一 package 内的其他模块调用。

**与 public 的区别**:
- `public`: 任何人都可以调用
- `public(package)`: 只有同包模块可以调用

**安全意义**:
- `public(package)` 提供包级封装
- 外部攻击者无法直接调用
- 是有效的访问控制机制

**常见误报**:
| 漏洞描述 | 判断 |
|---------|------|
| "public(package) 函数无权限检查" | 通常误报 - 外部无法调用 |
| "任意调用敏感操作" | 检查可见性，如果是 public(package) 则需要分析包内调用链 |

**示例**:
```move
// 只能被同包模块调用，外部无法直接访问
public(package) fun internal_transfer(from: &mut Vault, to: address, amount: u64) {
    // 无需 Capability 检查，因为只有包内可信代码能调用
}

// 公开入口，有权限检查
public entry fun transfer(_: &VaultCap, vault: &mut Vault, to: address, amount: u64) {
    internal_transfer(vault, to, amount);  // 调用 package 内部函数
}
```
""",

            "timestamp_validation": """## 时间戳验证
**别名**: timestamp, 时间戳, clock, time_validation, 时间验证, timestamp_check, clock_validation

**Sui 时间戳来源**:
Sui 通过 `Clock` 共享对象提供时间戳：`clock::timestamp_ms(clock)`

**安全特性**:
- Clock 是系统维护的共享对象
- 用户无法操纵时间戳
- 精度为毫秒级

**常见误报**:
| 漏洞描述 | 判断 |
|---------|------|
| "时间戳可被操纵" | 误报 - Sui Clock 由验证者维护 |
| "未验证时间戳来源" | 如果使用 Clock 对象则安全 |

**真实风险点**:
- 使用用户传入的时间参数 (而非 Clock)
- 时间精度转换错误 (ms vs s)
- 时间区间边界条件 (< vs <=)

**示例**:
```move
// 安全: 使用系统 Clock
public fun claim_reward(clock: &Clock, ...) {
    let now = clock::timestamp_ms(clock);  // 系统时间，不可操纵
    assert!(now >= unlock_time, ENotUnlocked);
}

// 危险: 使用用户传入的时间
public fun claim_reward(user_time: u64, ...) {  // ⚠️ 用户可伪造
    assert!(user_time >= unlock_time, ENotUnlocked);
}
```
""",

            "time_manipulation": """## 时间操纵攻击

**Sui 中的时间安全**:
与 EVM 不同，Sui 的时间戳由 Clock 共享对象提供，用户无法直接操纵。

**常见误报场景**:
1. "时间戳可被矿工/验证者操纵" - Sui 共识机制保证时间可靠
2. "前端可传入伪造时间" - 如果使用 Clock 对象则安全

**真实风险**:
- 函数参数接受时间而非使用 Clock
- 跨链/外部预言机时间不一致
- 大额奖励在精确时间点释放 (边界条件)

**审计方法**:
1. 检查时间来源是否为 `clock::timestamp_ms(clock)`
2. 如果是函数参数，检查是否有验证逻辑
3. 检查时间比较的边界条件

**示例**:
```move
// Sui 中安全的时间使用
public fun vesting_release(clock: &Clock, vesting: &mut Vesting) {
    let now = clock::timestamp_ms(clock) / 1000;  // 转为秒
    let vested = calculate_vested(vesting, now);  // 计算已释放量
    ...
}
```
""",

            "arithmetic_safety": """## 算术安全

**Move 的算术安全特性**:
Move 原生支持溢出检查，算术操作溢出时会 abort。

**什么是安全的**:
- `+`, `-`, `*`, `/` 在溢出/下溢/除零时自动 abort
- 类型转换 `as` 在值超出范围时 abort
- 不需要像 Solidity 那样使用 SafeMath

**常见误报**:
| 漏洞描述 | 判断 |
|---------|------|
| "加法可能溢出" | Move 会自动检查并 abort |
| "乘法溢出风险" | Move 会自动检查并 abort |
| "未使用 SafeMath" | Move 不需要 SafeMath |

**真实风险**:
- `wrapping_add/sub/mul` 允许溢出 (需特别审查)
- 精度损失 (非安全问题但影响业务)
- 除法截断导致的零值

**审计重点**:
1. 检查是否使用 `wrapping_*` 函数 (有意允许溢出)
2. 关注除法结果是否可能为零
3. 检查类型转换顺序 (先转大类型再计算)

**示例**:
```move
// Move 自动溢出检查 (安全)
let sum = a + b;  // 溢出时 abort

// 故意允许溢出 (需要审查)
let wrapped = wrapping_add(a, b);  // 溢出时环绕

// 精度损失风险 (非安全问题)
let fee = amount * rate / 10000;  // 如果 amount * rate < 10000，fee = 0
```
""",

            "hash_collision": """## 哈希碰撞

**Move/Sui 中的哈希安全**:
Sui 使用强密码学哈希函数 (如 SHA3-256, Blake2b)，碰撞攻击在实践中不可行。

**常见误报**:
| 漏洞描述 | 判断 |
|---------|------|
| "PoolKey 哈希碰撞" | 使用类型系统 (TypeName) + 参数组合，碰撞概率极低 |
| "ID 冲突" | Sui UID 基于随机数生成，碰撞不可行 |

**何时需要关注**:
- 自定义简单哈希函数
- 用户可控的哈希输入
- 哈希截断到小空间

**Sui 特有安全性**:
- `object::new(ctx)` 生成唯一 UID
- `type_name::get<T>()` 基于类型路径，不同类型必不相同
- 使用多个字段组合的 key (如 Pool 用 coin_a + coin_b + tick_spacing)

**示例**:
```move
// 安全: 使用类型名组合
struct PoolKey has copy, drop, store {
    coin_a: TypeName,
    coin_b: TypeName,
    tick_spacing: u32,
}

// 不同类型的 coin_a/coin_b 必然产生不同的 PoolKey
// 即使有人试图构造碰撞，类型系统保证安全
```
""",

            # 🔥 v2.5.7: 新增主题
            "one_time_witness": """## One-Time Witness (OTW) 模式
**别名**: otw, witness, 一次性见证

**什么是 One-Time Witness**:
Sui Move 中用于确保某些操作只能执行一次的机制，通常用于:
- 创建单例对象 (如配置、Treasury)
- 发布代币 (CoinMetadata)
- 初始化协议状态

**OTW 的特性** (由 Move VM 强制):
1. 类型名与模块名相同 (大写)
2. 只有 `drop` 能力，没有 `copy`、`store`、`key`
3. 只能在 `init()` 函数中创建
4. 用后即销毁，无法保存或复用

**常见误报**:
| 漏洞描述 | 判断 |
|---------|------|
| "OTW 可被重复使用" | 不可能，OTW 只有 drop 能力 |
| "init 可被重复调用" | 不可能，init 只在发布时调用一次 |
| "代币可被重复发行" | 如果使用 OTW 创建，则不可能 |

**安全检查点**:
- 检查是否正确使用 `sui::types::is_one_time_witness` 验证
- 检查 OTW 是否在使用后被 drop

**示例**:
```move
module example::my_token {
    // OTW 结构体: 与模块名相同，只有 drop
    struct MY_TOKEN has drop {}

    fun init(witness: MY_TOKEN, ctx: &mut TxContext) {
        // witness 只能在这里使用一次
        let (treasury, metadata) = coin::create_currency(
            witness,  // OTW 用后销毁
            6, ...
        );
        // witness 已销毁，无法再次使用
    }
}
```
""",

            "vector_safety": """## Vector 安全
**别名**: vector_bounds, vector_borrow, 数组安全

**Move 的 Vector 安全特性**:
Move 的 vector 操作在越界时会自动 abort，无需手动检查。

**什么是安全的**:
- `vector::borrow(v, i)` - 越界时 abort
- `vector::borrow_mut(v, i)` - 越界时 abort
- `vector::pop_back(v)` - 空 vector 时 abort
- `vector::remove(v, i)` - 越界时 abort

**常见误报**:
| 漏洞描述 | 判断 |
|---------|------|
| "数组越界访问" | Move 自动检查并 abort |
| "vector::borrow 可能 panic" | 这是安全行为，不是漏洞 |
| "未检查 vector 长度" | Move 会自动检查 |

**真实风险场景**:
1. 业务逻辑依赖特定索引存在 (需要检查 length)
2. 空 vector 导致后续计算失败
3. 大量元素导致 gas 耗尽

**审计重点**:
1. 检查 vector 为空时的业务逻辑
2. 关注 vector 操作的 gas 成本
3. 检查循环中是否可能无限增长

**示例**:
```move
// 安全: Move 自动越界检查
let item = vector::borrow(&items, index);  // 越界时 abort

// 业务逻辑需要检查
if (vector::length(&rewards) > 0) {
    let last = vector::pop_back(&mut rewards);  // 安全
}
```
"""
        }

        # 别名映射
        TOPIC_ALIASES = {
            "热土豆": "hot_potato",
            "闪电贷": "flashloan",
            "权限模式": "capability",
            "cap": "capability",
            "误报": "false_positive",
            "溢出": "overflow",
            "integer_overflow": "overflow",  # 🔥 v2.5.6: Agent 常用别名
            "整数溢出": "overflow",
            "重入": "reentrancy",
            "类型混淆": "type_confusion",
            # 🔥 v2.5.5: 新增别名
            "所有权": "ownership",
            "对象所有权": "ownership",
            "访问控制": "access_control",
            "权限检查": "access_control",
            "滑点": "slippage_control",
            "slippage": "slippage_control",
            "tick": "tick_price",
            "clmm": "tick_price",
            "tick-price-mapping": "tick_price",
            # 🔥 v2.5.6: 新增别名
            "动态字段": "dynamic_field",
            "dynamic_object_field": "dynamic_field",
            "字符串长度": "string_length_limit",
            "url长度": "string_length_limit",
            "精度": "precision",
            "舍入": "precision",
            "rounding": "precision",
            # 模块分层设计
            "模块分层": "module_layering",
            "分层设计": "module_layering",
            "低层模块": "module_layering",
            "wrapper": "module_layering",
            "acl": "module_layering",
            # 🔥 v2.5.6: 新增主题别名
            "共享对象": "shared_object",
            "share_object": "shared_object",
            "shared": "shared_object",
            "公开包": "public_package",
            "包可见性": "public_package",
            "时间戳验证": "timestamp_validation",
            "timestamp": "timestamp_validation",
            "时间验证": "timestamp_validation",
            "时间操纵": "time_manipulation",
            "时间攻击": "time_manipulation",
            "算术安全": "arithmetic_safety",
            "溢出安全": "arithmetic_safety",
            "safeMath": "arithmetic_safety",
            "哈希碰撞": "hash_collision",
            "碰撞攻击": "hash_collision",
            # 🔥 v2.5.7: 新增主题别名
            "otw": "one_time_witness",
            "witness": "one_time_witness",
            "一次性见证": "one_time_witness",
            "vector::borrow": "vector_safety",
            "vector_bounds": "vector_safety",
            "vector_borrow": "vector_safety",
            "数组越界": "vector_safety",
            "数组安全": "vector_safety",
        }

        # 🔥 v2.5.7: 从知识库内容中自动提取别名 (类似 Move 的 use as 语法)
        # 格式: **别名**: alias1, alias2, alias3
        import re
        CONTENT_ALIASES = {}  # alias -> topic
        for kb_topic, kb_content in KNOWLEDGE_BASE.items():
            # 解析 **别名**: xxx, yyy, zzz
            alias_match = re.search(r'\*\*别名\*\*:\s*(.+?)(?:\n|$)', kb_content)
            if alias_match:
                aliases_str = alias_match.group(1)
                for alias in aliases_str.split(','):
                    alias = alias.strip().lower()
                    if alias and alias != kb_topic:
                        CONTENT_ALIASES[alias] = kb_topic

        # 合并手动别名和内容别名 (手动优先)
        ALL_ALIASES = {**CONTENT_ALIASES, **TOPIC_ALIASES}

        # 解析主题
        topic_lower = topic.lower().strip()
        resolved_topic = ALL_ALIASES.get(topic_lower, topic_lower)
        inference_method = "exact_alias" if topic_lower in ALL_ALIASES else "exact_match"

        # 🔥 v2.5.7: 智能推断 - 如果精确匹配失败，尝试模糊匹配
        if resolved_topic not in KNOWLEDGE_BASE:
            from difflib import get_close_matches

            # 方法1: 字符串模糊匹配 (包含从内容提取的别名)
            all_keys = list(KNOWLEDGE_BASE.keys()) + list(ALL_ALIASES.keys())
            fuzzy_matches = get_close_matches(topic_lower, all_keys, n=3, cutoff=0.6)

            if fuzzy_matches:
                best_match = fuzzy_matches[0]
                resolved_topic = ALL_ALIASES.get(best_match, best_match)
                inference_method = f"fuzzy_match ('{best_match}')"

        if resolved_topic in KNOWLEDGE_BASE:
            content = KNOWLEDGE_BASE[resolved_topic]

            # 如果不需要示例，移除代码块
            if not include_examples:
                import re
                content = re.sub(r'```move.*?```', '[代码示例已省略]', content, flags=re.DOTALL)

            return ToolResult(
                success=True,
                data={
                    "topic": resolved_topic,
                    "original_query": topic,
                    "inference_method": inference_method,  # 🔥 v2.5.7: 返回推断方法
                    "content": content,
                    "available_topics": list(KNOWLEDGE_BASE.keys())
                },
                source="security_knowledge"
            )
        else:
            # 🔥 v2.5.7: 提供更有帮助的错误信息，包括相似主题建议
            from difflib import get_close_matches
            suggestions = get_close_matches(topic_lower, list(KNOWLEDGE_BASE.keys()), n=3, cutoff=0.4)
            suggestion_msg = f" 您可能想查询: {suggestions}" if suggestions else ""

            return ToolResult(
                success=False,
                data=None,
                error=f"未找到主题 '{topic}'。{suggestion_msg} 可用主题: {list(KNOWLEDGE_BASE.keys())}",
                source="security_knowledge"
            )

    # ==========================================================================
    # 🔥 Phase 0/1 分析数据工具实现
    # ==========================================================================

    def _get_function_purpose(self, function_id: str) -> ToolResult:
        """获取函数功能描述"""
        purposes = self.contract_analysis.get("function_purposes", {})

        if not purposes:
            return ToolResult(
                success=False,
                data=None,
                error="函数功能描述尚未生成（Phase 1.6 未执行）",
                source="contract_analysis"
            )

        # 尝试直接匹配
        if function_id in purposes:
            return ToolResult(
                success=True,
                data={
                    "function_id": function_id,
                    "purpose": purposes[function_id]
                },
                source="contract_analysis"
            )

        # 尝试部分匹配（只匹配函数名）
        for fid, purpose in purposes.items():
            if fid.endswith(f"::{function_id}") or fid.split("::")[-1] == function_id:
                return ToolResult(
                    success=True,
                    data={
                        "function_id": fid,
                        "purpose": purpose
                    },
                    source="contract_analysis"
                )

        return ToolResult(
            success=False,
            data=None,
            error=f"未找到函数 {function_id} 的功能描述",
            source="contract_analysis"
        )

    def _get_analysis_hints(self, hint_type: str = "all") -> ToolResult:
        """获取智能预分析提示"""
        hints = self.contract_analysis.get("analysis_hints", {})

        if not hints:
            return ToolResult(
                success=False,
                data=None,
                error="智能预分析尚未执行（Phase 1.5 未执行）",
                source="contract_analysis"
            )

        if hint_type == "all":
            return ToolResult(
                success=True,
                data=hints,
                source="contract_analysis"
            )

        # 获取特定类型
        valid_types = [
            "key_state_variables",
            "condition_thresholds",
            "cross_function_dataflow",
            "state_change_points",
            "potential_vuln_chains",
            "analysis_summary"
        ]

        if hint_type in valid_types:
            return ToolResult(
                success=True,
                data={
                    "hint_type": hint_type,
                    "data": hints.get(hint_type, [])
                },
                source="contract_analysis"
            )

        return ToolResult(
            success=False,
            data=None,
            error=f"无效的 hint_type: {hint_type}。可选: {valid_types}",
            source="contract_analysis"
        )

    def _get_callgraph_summary(self, include_edges: bool = False) -> ToolResult:
        """获取调用图摘要"""
        if not self.indexer.callgraph:
            return ToolResult(
                success=False,
                data=None,
                error="调用图不可用",
                source="callgraph"
            )

        cg = self.indexer.callgraph
        nodes = cg.get("nodes", [])
        edges = cg.get("edges", [])
        meta = cg.get("meta", {})

        # 提取入口点
        entry_points = [n for n in nodes if "public" in n.get("visibility", "") or "entry" in n.get("visibility", "")]

        # 提取叶子节点（没有调用其他函数的节点）
        callers = set(e.get("from", "") for e in edges)
        callees = set(e.get("to", "") for e in edges)
        leaf_nodes = [n for n in nodes if n.get("id", "") not in callers]

        # 提取跨模块调用
        cross_module = []
        for edge in edges:
            from_id = edge.get("from", "")
            to_id = edge.get("to", "")
            from_mod = from_id.split("::")[1] if "::" in from_id and len(from_id.split("::")) > 2 else ""
            to_mod = to_id.split("::")[1] if "::" in to_id and len(to_id.split("::")) > 2 else ""
            if from_mod and to_mod and from_mod != to_mod:
                cross_module.append({"from": from_id, "to": to_id})

        # 提取高风险函数
        risky_functions = [
            n for n in nodes
            if n.get("risk_indicators", {})
        ]

        result = {
            "mode": meta.get("mode", "unknown"),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "entry_points": [{"id": n.get("id"), "visibility": n.get("visibility")} for n in entry_points[:20]],
            "leaf_nodes": [n.get("id") for n in leaf_nodes[:20]],
            "cross_module_calls": cross_module[:20],
            "risky_functions": [{"id": n.get("id"), "risk": n.get("risk_indicators", {})} for n in risky_functions[:10]]
        }

        if include_edges:
            result["edges"] = edges[:100]  # 限制数量

        return ToolResult(
            success=True,
            data=result,
            source="callgraph"
        )

    def _get_module_structure(self, module_name: str = "") -> ToolResult:
        """获取模块结构"""
        modules = self.indexer.modules

        if module_name:
            # 查找特定模块
            for name, info in modules.items():
                if module_name in name:
                    return ToolResult(
                        success=True,
                        data={
                            "module": name,
                            "path": info.path,
                            "functions": [
                                {"name": c.name, "visibility": c.visibility, "signature": c.signature}
                                for c in self.indexer.chunks if c.module == name
                            ],
                            "structs": info.structs,
                            "constants": getattr(info, 'constants', [])
                        },
                        source="index"
                    )

            return ToolResult(
                success=False,
                data=None,
                error=f"未找到模块: {module_name}",
                source="index"
            )

        # 返回所有模块概览
        overview = []
        for name, info in modules.items():
            func_count = len([c for c in self.indexer.chunks if c.module == name])
            overview.append({
                "module": name,
                "function_count": func_count,
                "struct_count": len(info.structs)
            })

        return ToolResult(
            success=True,
            data={
                "module_count": len(modules),
                "modules": overview
            },
            source="index"
        )

    def _get_risky_functions(self, risk_type: str = "all") -> ToolResult:
        """获取高风险函数列表"""
        risky = []

        for chunk in self.indexer.chunks:
            indicators = chunk.risk_indicators or {}

            if not indicators:
                continue

            # 根据 risk_type 过滤
            if risk_type == "funds":
                if indicators.get("handles_funds") or indicators.get("coin_transfer"):
                    risky.append({
                        "id": chunk.id,
                        "name": chunk.name,
                        "visibility": chunk.visibility,
                        "indicators": indicators
                    })
            elif risk_type == "state":
                if indicators.get("modifies_state") or indicators.get("state_mutation"):
                    risky.append({
                        "id": chunk.id,
                        "name": chunk.name,
                        "visibility": chunk.visibility,
                        "indicators": indicators
                    })
            elif risk_type == "access":
                if indicators.get("access_control") or indicators.get("capability_check"):
                    risky.append({
                        "id": chunk.id,
                        "name": chunk.name,
                        "visibility": chunk.visibility,
                        "indicators": indicators
                    })
            else:  # all
                risky.append({
                    "id": chunk.id,
                    "name": chunk.name,
                    "visibility": chunk.visibility,
                    "indicators": indicators
                })

        return ToolResult(
            success=True,
            data={
                "risk_type": risk_type,
                "count": len(risky),
                "functions": risky[:50]  # 限制数量
            },
            source="index"
        )

    # ==========================================================================
    # 🔥 v2.5.5: 自动安全模式检测工具实现
    # ==========================================================================

    def _check_flashloan_security(
        self,
        receipt_type: str = "",
        repay_function: str = ""
    ) -> ToolResult:
        """
        自动检查闪电贷实现的安全性

        检测:
        1. Hot Potato: Receipt 没有 drop 能力 = 强制还款
        2. 类型验证: repay 函数是否检查 type_name 匹配
        """
        import re

        findings = {
            "hot_potato_safe": False,
            "type_check_safe": False,
            "type_confusion_vulnerable": False,  # 🔥 v2.5.5: 显式初始化
            "amount_check_safe": False,
            "pool_id_check_safe": False,
            "receipt_struct": None,
            "repay_function_code": None,
            "security_summary": "",
            "false_positive_indicators": [],
            "real_vulnerability_indicators": []
        }

        # 自动发现 Receipt 类型 (如果未指定)
        receipt_patterns = ["Receipt", "FlashReceipt", "FlashLoanReceipt", "Loan"]
        found_receipts = []

        for module_info in self.indexer.modules.values():
            for struct in module_info.structs:
                struct_name = struct.get("name", "")
                struct_body = struct.get("body", "")
                abilities = struct.get("abilities", [])

                # 匹配 Receipt 类型
                if receipt_type:
                    if struct_name.lower() == receipt_type.lower():
                        found_receipts.append({
                            "name": struct_name,
                            "body": struct_body,
                            "abilities": abilities,
                            "module": module_info.name
                        })
                else:
                    for pattern in receipt_patterns:
                        if pattern.lower() in struct_name.lower():
                            found_receipts.append({
                                "name": struct_name,
                                "body": struct_body,
                                "abilities": abilities,
                                "module": module_info.name
                            })
                            break

        # 检查 Hot Potato 模式
        for receipt in found_receipts:
            findings["receipt_struct"] = receipt
            abilities = receipt.get("abilities", [])

            # 解析 abilities
            if isinstance(abilities, str):
                abilities = [a.strip() for a in abilities.split(",")]

            # Hot Potato: 没有 drop 能力
            has_drop = any("drop" in a.lower() for a in abilities)

            if not has_drop:
                findings["hot_potato_safe"] = True
                findings["false_positive_indicators"].append(
                    f"✅ {receipt['name']} 没有 drop 能力 (Hot Potato 模式)，强制还款已保证"
                )
            else:
                findings["real_vulnerability_indicators"].append(
                    f"🔴 {receipt['name']} 有 drop 能力！可以跳过还款"
                )
            break  # 只检查第一个找到的 Receipt

        # 查找 repay 函数
        repay_patterns = ["repay", "repay_flashloan", "repay_flash", "return_loan"]
        found_repay = None

        for chunk in self.indexer.chunks:
            func_name = chunk.name.lower()

            if repay_function:
                if func_name == repay_function.lower():
                    found_repay = chunk
                    break
            else:
                for pattern in repay_patterns:
                    if pattern in func_name:
                        found_repay = chunk
                        break
                if found_repay:
                    break

        if found_repay:
            findings["repay_function_code"] = {
                "name": found_repay.name,
                "body": found_repay.body[:2000],
                "module": found_repay.module
            }

            code = found_repay.body

            # 检查类型验证
            type_check_patterns = [
                r'type_name::get<.*>\s*\(\)\s*.*==.*type_name',  # type_name::get<A>() == type_name
                r'type_name\s*==\s*type_name::get',
                r'assert!.*type_name.*==',
                r'ETypeMismatch',
            ]

            for pattern in type_check_patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    findings["type_check_safe"] = True
                    findings["false_positive_indicators"].append(
                        f"✅ repay 函数有类型验证 (匹配: {pattern[:30]})"
                    )
                    break

            if not findings["type_check_safe"]:
                # 检查是否只有 contains_type 检查 (不够!)
                if "contains_type" in code and "type_name::get" not in code:
                    findings["real_vulnerability_indicators"].append(
                        "🔴 只有 contains_type 检查，没有验证借/还币种匹配 (类型混淆风险)"
                    )
                    findings["type_confusion_vulnerable"] = True

            # 检查金额验证
            amount_patterns = [
                r'assert!.*coin::value.*>=',
                r'assert!.*amount.*==',
                r'ERepayAmountMismatch',
                r'repay_amount',
            ]

            for pattern in amount_patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    findings["amount_check_safe"] = True
                    break

            # 检查 Pool ID 验证
            pool_id_patterns = [
                r'object::id\(pool\)\s*==',
                r'pool_id\s*==',
                r'EPoolIdMismatch',
            ]

            for pattern in pool_id_patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    findings["pool_id_check_safe"] = True
                    break

        # 生成安全总结
        checks_passed = sum([
            findings["hot_potato_safe"],
            findings["type_check_safe"],
            findings["amount_check_safe"],
            findings["pool_id_check_safe"]
        ])

        if checks_passed == 4:
            findings["security_summary"] = "✅ 闪电贷实现安全: Hot Potato + 类型/金额/Pool ID 验证均存在"
        elif findings["hot_potato_safe"] and findings["type_check_safe"]:
            findings["security_summary"] = "✅ 核心安全保护存在: Hot Potato 强制还款 + 类型验证"
        elif findings["hot_potato_safe"] and findings.get("type_confusion_vulnerable"):
            # Hot Potato 存在但有类型混淆风险
            findings["security_summary"] = "⚠️ Hot Potato 存在，但可能有类型混淆风险 (需人工验证还款类型是否被正确校验)"
        elif findings["hot_potato_safe"]:
            findings["security_summary"] = "⚠️ Hot Potato 存在 (强制还款)，但可能缺少类型验证"
        else:
            findings["security_summary"] = "🔴 闪电贷可能不安全: 需要人工审查"

        # 判断 "闪电贷无强制还款" 是否为误报
        if findings["hot_potato_safe"]:
            findings["is_no_enforcement_false_positive"] = True
            findings["false_positive_reason"] = "Receipt 没有 drop 能力，Hot Potato 模式强制还款"
        else:
            findings["is_no_enforcement_false_positive"] = False

        return ToolResult(
            success=True,
            data=findings,
            source="security_pattern_check"
        )
