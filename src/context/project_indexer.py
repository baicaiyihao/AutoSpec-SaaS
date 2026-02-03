"""
Move 项目索引器

整合现有的 callgraph、dependency_resolver 能力，提供：
1. 项目概览生成 (Layer 1)
2. 代码分块用于向量化 (Layer 2)
3. 智能上下文检索 (Layer 2)

设计原则：
- 复用现有的 CallGraphBuilder 和 DependencyResolver
- 不做语义转述，只提供结构化信息
- Agent 直接看原始代码

Usage:
    from src.context.project_indexer import MoveProjectIndexer

    indexer = MoveProjectIndexer("/path/to/move-project")
    indexer.index_project()

    # 获取项目概览 (2-5k tokens)
    overview = indexer.get_project_overview()

    # 获取函数上下文
    context = indexer.get_function_context("pool::borrow", depth=2)
"""

import os
import re
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Any

# 复用现有模块
from src.context.callgraph import (
    CallGraphBuilder,
    CallGraphQuery,
    FunctionContextBuilder,
    FunctionNode,
    RiskIndicators,
)
from src.context.dependency_resolver import DependencyResolver


@dataclass
class ModuleInfo:
    """模块信息"""
    name: str
    path: str
    address: str = ""
    structs: List[Dict] = field(default_factory=list)
    functions: List[Dict] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    constants: List[Dict] = field(default_factory=list)  # 🔥 v2.5.4: 常量定义
    string_literals: Set[str] = field(default_factory=set)  # 🔥 v2.5.5: 字符串字面量
    raw_content: str = ""

    def get_public_functions(self) -> List[Dict]:
        """获取公开函数"""
        return [f for f in self.functions
                if f.get("visibility") in ["public", "public(friend)", "entry"]]


@dataclass
class CodeChunk:
    """代码块 (用于向量化)"""
    id: str                      # module::function
    chunk_type: str              # function, struct, module
    module: str
    name: str
    signature: str
    body: str
    visibility: str = "private"  # public, entry, private, public(friend)
    file_path: str = ""          # 相对文件路径
    line_number: int = 0         # 起始行号
    related_types: List[str] = field(default_factory=list)
    risk_indicators: Dict = field(default_factory=dict)
    description: str = ""        # 自然语言描述 (用于混合检索)

    def to_embedding_text(self) -> str:
        """生成用于 embedding 的文本"""
        parts = [
            f"Module: {self.module}",
            f"Function: {self.name}",
            f"Signature: {self.signature}",
        ]
        if self.description:
            parts.append(f"Description: {self.description}")
        parts.append(f"Code:\n{self.body}")
        return "\n".join(parts)


class MoveProjectIndexer:
    """
    Move 项目索引器

    整合 CallGraphBuilder 和 DependencyResolver，提供：
    1. 项目结构索引
    2. 概览生成
    3. 上下文检索
    """

    def __init__(self, project_path: str, callgraph_cache_dir: Optional[str] = None):
        """
        Args:
            project_path: Move 项目根目录
            callgraph_cache_dir: 调用图缓存目录 (可选)
        """
        self.project_path = Path(project_path)
        self.callgraph_cache_dir = callgraph_cache_dir

        # 索引数据
        self.modules: Dict[str, ModuleInfo] = {}
        self.chunks: List[CodeChunk] = []
        self.callgraph: Optional[Dict] = None
        self.callgraph_query: Optional[CallGraphQuery] = None
        self.dependency_resolver: Optional[DependencyResolver] = None

        # 状态标记
        self.callgraph_status: str = "not_built"  # ok, empty, failed, not_built

        # 配置
        self.max_chunk_tokens = 2000

    def index_project(self, build_callgraph: bool = True) -> None:
        """
        索引整个项目

        Args:
            build_callgraph: 是否构建调用图
        """
        print(f"[Indexer] 开始索引项目: {self.project_path}")

        # 1. 解析依赖
        self._init_dependency_resolver()

        # 2. 只遍历 sources 目录下的 .move 文件 (忽略 tests 目录)
        sources_dir = self.project_path / "sources"
        if not sources_dir.exists():
            sources_dir = self.project_path

        move_files = list(sources_dir.rglob("*.move"))
        print(f"[Indexer] 找到 {len(move_files)} 个源文件 (sources 目录)")

        for move_file in move_files:
            self._index_file(move_file)

        # 3. 构建调用图
        if build_callgraph:
            self._build_callgraph()

        # 4. 生成代码块
        self._generate_chunks()

        print(f"[Indexer] 索引完成: {len(self.modules)} 个模块, {len(self.chunks)} 个代码块")

    def _init_dependency_resolver(self) -> None:
        """初始化依赖解析器"""
        try:
            self.dependency_resolver = DependencyResolver(str(self.project_path))
            print(f"[Indexer] 依赖解析器初始化成功")
        except Exception as e:
            print(f"[Indexer] 依赖解析器初始化失败: {e}")

    def _index_file(self, file_path: Path) -> None:
        """解析单个 Move 文件"""
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[Indexer] 读取文件失败 {file_path}: {e}")
            return

        # 提取模块信息 (支持 Move 1.0 和 Move 2.0 语法)
        # Move 1.0: module address::name {
        # Move 2.0: module address::name;
        module_match = re.search(
            r'module\s+(?:(\w+)::)?(\w+)\s*[{;]',
            content
        )
        if not module_match:
            return

        address = module_match.group(1) or ""
        module_name = module_match.group(2)
        full_name = f"{address}::{module_name}" if address else module_name

        module_info = ModuleInfo(
            name=full_name,
            path=str(file_path.relative_to(self.project_path)),
            address=address,
            structs=self._extract_structs(content),
            functions=self._extract_functions(content),
            imports=self._extract_imports(content),
            constants=self._extract_constants(content),  # 🔥 v2.5.4: 提取常量定义
            string_literals=self._extract_string_literals(content),  # 🔥 v2.5.5: 提取字符串字面量
            raw_content=content,
        )

        self.modules[full_name] = module_info

    def _extract_structs(self, content: str) -> List[Dict]:
        """提取 struct 定义"""
        structs = []
        # 🔥 v2.5.3: 支持有/无 abilities 的 struct
        # 有 abilities: struct Foo has key, store { ... }
        # 无 abilities: struct FlashReceipt { ... }  (Hot Potato 模式)
        pattern_with_abilities = r'(?:public\s+)?struct\s+(\w+)(?:<[^>]+>)?\s+has\s+([\w,\s]+)\s*\{'
        pattern_no_abilities = r'(?:public\s+)?struct\s+(\w+)(?:<[^>]+>)?\s*\{'

        processed_names = set()

        # 先匹配有 abilities 的 struct
        for match in re.finditer(pattern_with_abilities, content):
            name = match.group(1)
            abilities = [a.strip() for a in match.group(2).split(',')]
            start = match.start()

            brace_count = 0
            end = start
            for i, c in enumerate(content[start:]):
                if c == '{':
                    brace_count += 1
                elif c == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = start + i + 1
                        break

            processed_names.add(name)
            structs.append({
                "name": name,
                "abilities": abilities,
                "signature": f"struct {name} has {', '.join(abilities)}",
                "body": content[start:end],
            })

        # 再匹配无 abilities 的 struct (Hot Potato 等)
        for match in re.finditer(pattern_no_abilities, content):
            name = match.group(1)
            if name in processed_names:
                continue  # 跳过已处理的

            start = match.start()
            abilities = []  # 无 abilities = Hot Potato!

            brace_count = 0
            end = start
            for i, c in enumerate(content[start:]):
                if c == '{':
                    brace_count += 1
                elif c == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = start + i + 1
                        break

            structs.append({
                "name": name,
                "abilities": abilities,
                "signature": f"struct {name}",
                "body": content[start:end],
                "is_hot_potato": True,  # 🔥 标记无 abilities
            })

        return structs

    def _extract_constants(self, content: str) -> List[Dict]:
        """提取常量定义 (const)

        支持格式:
        - const E_OVERFLOW: u64 = 1;
        - const FEE_PRECISION: u64 = 10000;
        - const MAX_U64: u64 = 18446744073709551615;

        这对于理解错误码和配置参数很重要
        """
        constants = []

        # 匹配 const 定义
        # const NAME: TYPE = VALUE;
        pattern = r'const\s+(\w+)\s*:\s*(\w+)\s*=\s*([^;]+);'

        for match in re.finditer(pattern, content):
            name = match.group(1)
            const_type = match.group(2)
            value = match.group(3).strip()

            constants.append({
                "name": name,
                "type": const_type,
                "value": value,
                "signature": f"const {name}: {const_type} = {value}",
            })

        return constants

    def _extract_string_literals(self, content: str) -> Set[str]:
        """提取字符串字面量中的标识符 (v2.5.5)

        用于避免 AI 把字符串内容当作类型名查询。
        例如: "CTF{MoveCTF-Task2}" 中的 CTF, MoveCTF, Task2
              b"WLP" 中的 WLP

        只提取看起来像标识符的部分 (首字母大写或全大写)
        """
        literals = set()

        # 匹配普通字符串 "..." 和字节字符串 b"..."
        patterns = [
            r'"([^"]*)"',      # "string"
            r"b\"([^\"]*)\"",  # b"bytes"
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content):
                string_content = match.group(1)
                # 提取看起来像标识符的部分 (连续字母数字，首字母大写)
                # 例如从 "CTF{MoveCTF-Task2}" 提取 CTF, MoveCTF, Task2
                identifiers = re.findall(r'\b([A-Z][A-Za-z0-9]*)\b', string_content)
                literals.update(identifiers)

        return literals

    def _extract_functions(self, content: str) -> List[Dict]:
        """提取函数定义"""
        functions = []

        # 匹配函数定义
        pattern = r'(public(?:\s*\(friend\))?\s+|entry\s+|public\s+entry\s+)?fun\s+(\w+)(<[^>]+>)?\s*\(([^)]*)\)(?:\s*:\s*([^{]+))?\s*\{'

        for match in re.finditer(pattern, content):
            visibility_raw = match.group(1) or ""
            name = match.group(2)
            type_params = match.group(3) or ""
            params = match.group(4)
            return_type = (match.group(5) or "").strip()

            # 确定可见性 (正确处理 public entry 组合)
            is_public = "public" in visibility_raw
            is_entry = "entry" in visibility_raw
            is_friend = "friend" in visibility_raw

            if is_friend:
                visibility = "public(friend)"
            elif is_public and is_entry:
                visibility = "public entry"
            elif is_public:
                visibility = "public"
            elif is_entry:
                visibility = "entry"
            else:
                visibility = "private"

            # 构建签名
            sig_parts = []
            if visibility != "private":
                sig_parts.append(visibility)
            sig_parts.append(f"fun {name}{type_params}({params})")
            if return_type:
                sig_parts.append(f": {return_type}")
            signature = " ".join(sig_parts)

            # 提取函数体
            start = match.start()
            brace_count = 0
            end = start
            in_body = False
            for i, c in enumerate(content[start:]):
                if c == '{':
                    brace_count += 1
                    in_body = True
                elif c == '}':
                    brace_count -= 1
                    if in_body and brace_count == 0:
                        end = start + i + 1
                        break

            functions.append({
                "name": name,
                "visibility": visibility,
                "signature": signature,
                "params": params,
                "return_type": return_type,
                "body": content[start:end],
            })

        return functions

    def _extract_imports(self, content: str) -> List[str]:
        """提取 use 语句"""
        imports = []
        pattern = r'use\s+([\w:]+)(?:::\{([^}]+)\})?;'

        for match in re.finditer(pattern, content):
            module = match.group(1)
            items = match.group(2)
            if items:
                for item in items.split(','):
                    imports.append(f"{module}::{item.strip()}")
            else:
                imports.append(module)

        return imports

    def _build_callgraph(self) -> None:
        """构建调用图"""
        try:
            # 确定 sources 目录
            sources_dir = self.project_path / "sources"
            if not sources_dir.exists():
                sources_dir = self.project_path

            # 使用现有的 CallGraphBuilder
            builder = CallGraphBuilder(
                root=str(sources_dir),
                include_types=True,
            )
            self.callgraph = builder.build()

            # 初始化查询器
            self.callgraph_query = CallGraphQuery(self.callgraph)

            node_count = len(self.callgraph.get('nodes', []))
            edge_count = len(self.callgraph.get('edges', []))

            if node_count == 0:
                print(f"[Indexer] ⚠️ 调用图为空 - 可能原因:")
                print(f"         - 项目结构未被识别 (检查 sources/ 目录)")
                print(f"         - 正则匹配失败 (复杂语法/动态调用)")
                print(f"         - 将使用降级策略: 函数间调用关系不可用")
                self.callgraph_status = "empty"
            else:
                print(f"[Indexer] 调用图构建完成: {node_count} 节点, {edge_count} 边")
                self.callgraph_status = "ok"

        except Exception as e:
            print(f"[Indexer] ⚠️ 调用图构建失败: {e}")
            print(f"         将使用降级策略: 无调用关系分析")
            self.callgraph_status = "failed"
            self.callgraph = None
            self.callgraph_query = None

    def _generate_chunks(self) -> None:
        """生成代码块用于向量化"""
        for module_name, module_info in self.modules.items():
            # 为每个函数生成 chunk
            for func in module_info.functions:
                chunk = CodeChunk(
                    id=f"{module_name}::{func['name']}",
                    chunk_type="function",
                    module=module_name,
                    name=func["name"],
                    signature=func["signature"],
                    body=func["body"],
                    visibility=func.get("visibility", "private"),
                    file_path=module_info.path,
                    related_types=self._get_related_types(func, module_info),
                    description=self._generate_description(func, module_name),
                )

                # 添加风险指标 (如果有调用图)
                if self.callgraph_query:
                    node = self.callgraph_query.get_function(chunk.id)
                    if node and "risk_indicators" in node:
                        chunk.risk_indicators = node["risk_indicators"]

                self.chunks.append(chunk)

    def _get_related_types(self, func: Dict, module_info: ModuleInfo) -> List[str]:
        """获取函数相关的类型"""
        related = []
        func_text = func["params"] + " " + func.get("return_type", "")

        for struct in module_info.structs:
            if struct["name"] in func_text:
                related.append(struct["name"])

        return related

    def _generate_description(self, func: Dict, module_name: str) -> str:
        """生成函数的自然语言描述 (基于命名推断)"""
        name = func["name"]
        visibility = func["visibility"]

        # 基于函数名推断功能
        descriptions = []

        if visibility == "entry":
            descriptions.append("Entry point function")
        elif visibility == "public":
            descriptions.append("Public function")

        # 常见模式
        if name.startswith("create_") or name.startswith("new_"):
            descriptions.append("creates a new object")
        elif name.startswith("destroy_") or name.startswith("delete_"):
            descriptions.append("destroys/deletes an object")
        elif name.startswith("get_") or name.startswith("is_") or name.startswith("has_"):
            descriptions.append("getter/query function")
        elif name.startswith("set_") or name.startswith("update_"):
            descriptions.append("setter/update function")
        elif name in ["borrow", "repay", "liquidate", "deposit", "withdraw"]:
            descriptions.append(f"DeFi {name} operation")
        elif name in ["swap", "add_liquidity", "remove_liquidity"]:
            descriptions.append(f"AMM {name} operation")
        elif name in ["mint", "burn", "transfer"]:
            descriptions.append(f"Token {name} operation")

        return f"{module_name}::{name} - " + ", ".join(descriptions) if descriptions else ""

    # =========================================================================
    # 项目概览生成 (Layer 1)
    # =========================================================================

    def get_project_overview(self, max_tokens: int = 5000) -> str:
        """
        生成项目概览

        Returns:
            项目概览文本 (2-5k tokens)
        """
        parts = []

        # 1. 目录结构
        parts.append("## 项目结构\n```")
        parts.append(self._generate_directory_tree())
        parts.append("```\n")

        # 2. 依赖关系
        if self.dependency_resolver:
            parts.append("## 依赖关系\n")
            for name, dep in self.dependency_resolver.dependencies.items():
                parts.append(f"- {name}: {dep.git_url or dep.local_path}")
            parts.append("")

        # 3. 模块概览
        parts.append("## 模块概览\n")
        for module_name, module_info in self.modules.items():
            parts.append(f"### {module_name}")
            parts.append(f"文件: {module_info.path}\n")

            # Struct 签名
            if module_info.structs:
                parts.append("**对象类型:**")
                for struct in module_info.structs:
                    abilities = ", ".join(struct["abilities"])
                    parts.append(f"- `{struct['name']}` ({abilities})")
                parts.append("")

            # 公开函数签名
            public_funcs = module_info.get_public_functions()
            if public_funcs:
                parts.append("**公开函数:**")
                for func in public_funcs:
                    parts.append(f"- `{func['signature']}`")
                parts.append("")

        return "\n".join(parts)

    def _generate_directory_tree(self, max_depth: int = 3) -> str:
        """生成目录树"""
        lines = []

        def walk(path: Path, prefix: str = "", depth: int = 0):
            if depth > max_depth:
                return
            items = sorted(path.iterdir(), key=lambda x: (x.is_file(), x.name))
            for i, item in enumerate(items):
                is_last = i == len(items) - 1
                connector = "└── " if is_last else "├── "

                if item.is_dir() and item.name not in ["__pycache__", ".git", "target", "build"]:
                    lines.append(f"{prefix}{connector}{item.name}/")
                    new_prefix = prefix + ("    " if is_last else "│   ")
                    walk(item, new_prefix, depth + 1)
                elif item.suffix == ".move":
                    lines.append(f"{prefix}{connector}{item.name}")
                elif item.name == "Move.toml":
                    lines.append(f"{prefix}{connector}{item.name}")

        walk(self.project_path)
        return "\n".join(lines)

    # =========================================================================
    # 上下文检索 (Layer 2 & 3)
    # =========================================================================

    def get_function_context(
        self,
        func_id: str,
        depth: int = 2,
        include_external: bool = True,
    ) -> Dict[str, Any]:
        """
        获取函数上下文

        Args:
            func_id: 函数ID (module::function)
            depth: 调用图遍历深度
            include_external: 是否包含外部依赖实现

        Returns:
            {
                "target": 目标函数信息,
                "callers": 调用者列表,
                "callees": 被调用者列表,
                "external_deps": 外部依赖实现,
                "related_types": 相关类型定义,
                "metadata": 元信息 (来源、状态等),
            }
        """
        context = {
            "target": None,
            "callers": [],
            "callees": [],
            "external_deps": [],
            "related_types": [],
            "metadata": {
                "callgraph_status": self.callgraph_status,
                "callgraph_source": self.callgraph.get("meta", {}).get("mode", "unknown") if self.callgraph else "none",
                "warnings": [],
            },
        }

        # 1. 获取目标函数
        for chunk in self.chunks:
            if chunk.id == func_id:
                context["target"] = {
                    "id": chunk.id,
                    "module": chunk.module,
                    "name": chunk.name,
                    "signature": chunk.signature,
                    "body": chunk.body,
                    "visibility": chunk.visibility,
                    "file_path": chunk.file_path,
                    "risk_indicators": chunk.risk_indicators,
                }
                break

        if not context["target"]:
            context["metadata"]["warnings"].append(f"目标函数未找到: {func_id}")
            return context

        # 2. 从调用图获取调用关系
        if self.callgraph_query and self.callgraph_status == "ok":
            node = self.callgraph_query.get_function(func_id)
            if node:
                # 获取调用者 (called_by)
                caller_ids = node.get("called_by", [])
                for caller_id in caller_ids[:depth * 5]:  # 限制数量
                    caller_chunk = next((c for c in self.chunks if c.id == caller_id), None)
                    if caller_chunk:
                        context["callers"].append({
                            "id": caller_id,
                            "module": caller_chunk.module,
                            "name": caller_chunk.name,
                            "signature": caller_chunk.signature,
                            "visibility": caller_chunk.visibility,
                            "file_path": caller_chunk.file_path,
                            "body": caller_chunk.body,
                            "source": "callgraph",
                        })

                # 获取被调用者 (calls)
                callee_ids = node.get("calls", [])
                for callee_id in callee_ids[:depth * 5]:  # 限制数量
                    callee_chunk = next((c for c in self.chunks if c.id == callee_id), None)
                    if callee_chunk:
                        context["callees"].append({
                            "id": callee_id,
                            "module": callee_chunk.module,
                            "name": callee_chunk.name,
                            "signature": callee_chunk.signature,
                            "visibility": callee_chunk.visibility,
                            "file_path": callee_chunk.file_path,
                            "body": callee_chunk.body,
                            "source": "callgraph",
                        })
        else:
            # 降级: 无调用图，添加警告
            context["metadata"]["warnings"].append(
                f"调用图不可用 (状态: {self.callgraph_status})，调用关系分析受限"
            )

        # 3. 获取外部依赖实现
        if include_external and self.dependency_resolver:
            # 分析函数体中的外部调用
            target_body = context["target"]["body"]
            external_calls = self._find_external_calls(target_body)

            for ext_call in external_calls:
                impl = self.dependency_resolver.find_function(ext_call, "")
                if impl:
                    context["external_deps"].append({
                        "call": ext_call,
                        "implementation": impl,
                    })

        # 4. 获取相关类型定义
        # 从函数签名和体中提取类型名，然后查找定义
        type_names = self._extract_type_names(context["target"]["body"])
        for module_info in self.modules.values():
            for struct in module_info.structs:
                if struct["name"] in type_names:
                    context["related_types"].append({
                        "name": struct["name"],
                        "definition": struct["body"],
                    })

        return context

    def _find_external_calls(self, code: str) -> List[str]:
        """查找代码中的外部模块调用"""
        external_calls = []

        # 匹配 module::function 模式
        pattern = r'(\w+)::(\w+)::(\w+)\s*[(<]'
        for match in re.finditer(pattern, code):
            call = f"{match.group(1)}::{match.group(2)}::{match.group(3)}"
            if call not in external_calls:
                external_calls.append(call)

        return external_calls

    def _extract_type_names(self, code: str) -> Set[str]:
        """从代码中提取类型名"""
        # 匹配大写开头的标识符 (通常是类型名)
        pattern = r'\b([A-Z][a-zA-Z0-9_]*)\b'
        return set(re.findall(pattern, code))

    def get_entry_points(self) -> List[Dict]:
        """获取所有入口点 (public/entry 函数)"""
        entry_points = []

        for module_name, module_info in self.modules.items():
            for func in module_info.functions:
                if func["visibility"] in ["public", "entry"]:
                    entry_points.append({
                        "id": f"{module_name}::{func['name']}",
                        "module": module_name,
                        "name": func["name"],
                        "signature": func["signature"],
                        "visibility": func["visibility"],
                    })

        return entry_points

    def search_code(self, query: str, regex: bool = False) -> List[Dict]:
        """
        在代码库中搜索

        Args:
            query: 搜索查询
            regex: 是否使用正则表达式

        Returns:
            匹配的代码块列表
        """
        results = []

        pattern = re.compile(query) if regex else None

        for chunk in self.chunks:
            if regex:
                if pattern.search(chunk.body):
                    results.append({
                        "id": chunk.id,
                        "signature": chunk.signature,
                        "body": chunk.body,
                    })
            else:
                if query.lower() in chunk.body.lower():
                    results.append({
                        "id": chunk.id,
                        "signature": chunk.signature,
                        "body": chunk.body,
                    })

        return results

    # =========================================================================
    # 序列化
    # =========================================================================

    def save_index(self, output_path: str) -> None:
        """保存索引到文件"""
        data = {
            "project_path": str(self.project_path),
            "modules": {k: asdict(v) if hasattr(v, '__dataclass_fields__') else v
                       for k, v in self.modules.items()},
            "chunks": [asdict(c) for c in self.chunks],
            "callgraph": self.callgraph,
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def load_index(self, input_path: str) -> None:
        """从文件加载索引"""
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.project_path = Path(data["project_path"])

        # 重建 modules
        for name, info in data["modules"].items():
            self.modules[name] = ModuleInfo(**info)

        # 重建 chunks
        self.chunks = [CodeChunk(**c) for c in data["chunks"]]

        # 重建调用图查询器
        if data.get("callgraph"):
            self.callgraph = data["callgraph"]
            self.callgraph_query = CallGraphQuery(self.callgraph)
