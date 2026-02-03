"""
Sui Move 调用图生成器 (LSP 增强版)

基于 move-analyzer LSP 服务器 + 名字匹配，生成函数级调用图 JSON。
当 LSP 不可用时，自动回退到 regex 模式。

Usage:
    python -m src.context.callgraph \
        --root cetus-contracts/sources \
        --out data/callgraph/cetus.json \
        --include-types \
        --summary-length 100

输出:
    - data/callgraph/<project_name>.json
"""

import argparse
import os
import re
import json
import hashlib
import subprocess
import threading
import time
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple, Any
from pathlib import Path

# 尝试导入项目配置
try:
    from src.config import CALLGRAPH_DIR, BASE_DIR
except ImportError:
    BASE_DIR = Path(__file__).resolve().parent.parent.parent
    CALLGRAPH_DIR = os.path.join(BASE_DIR, "data", "callgraph")

# 导入依赖解析器
try:
    from src.context.dependency_resolver import DependencyResolver
except ImportError:
    DependencyResolver = None


# ============================================================================
# LSP 客户端 (与 move-analyzer 通信)
# ============================================================================

class LSPClient:
    """与 move-analyzer LSP 服务器通信的客户端"""

    def __init__(self, command: List[str] = None):
        self.command = command or ["move-analyzer"]
        self.process: Optional[subprocess.Popen] = None
        self.request_id = 0
        self._lock = threading.Lock()
        self._responses: Dict[int, Any] = {}
        self._reader_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._running = False
        self._initialized = False

    def start(self) -> bool:
        """启动 LSP 服务器"""
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self._running = True

            # 启动响应读取线程
            self._reader_thread = threading.Thread(target=self._read_responses, daemon=True)
            self._reader_thread.start()

            # 启动 stderr 读取线程 (静默)
            self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
            self._stderr_thread.start()

            return True
        except FileNotFoundError:
            print("[LSP] move-analyzer 未找到，回退到 regex 模式")
            return False
        except Exception as e:
            print(f"[LSP] 启动失败: {e}，回退到 regex 模式")
            return False

    def stop(self):
        """停止 LSP 服务器"""
        self._running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                pass

    def _send_message(self, message: Dict[str, Any]) -> None:
        """发送 LSP 消息"""
        if not self.process or not self.process.stdin:
            return

        content = json.dumps(message)
        header = f"Content-Length: {len(content)}\r\n\r\n"

        self.process.stdin.write(header.encode())
        self.process.stdin.write(content.encode())
        self.process.stdin.flush()

    def _read_responses(self):
        """后台线程：读取 LSP 响应"""
        while self._running and self.process and self.process.stdout:
            try:
                header_line = b""
                while self._running:
                    byte = self.process.stdout.read(1)
                    if not byte:
                        break
                    header_line += byte
                    if header_line.endswith(b"\r\n\r\n"):
                        break

                if not header_line:
                    continue

                header_str = header_line.decode()
                content_length = 0
                for line in header_str.split("\r\n"):
                    if line.startswith("Content-Length:"):
                        content_length = int(line.split(":")[1].strip())
                        break

                if content_length == 0:
                    continue

                content = self.process.stdout.read(content_length)
                response = json.loads(content.decode())

                if "id" in response:
                    with self._lock:
                        self._responses[response["id"]] = response

            except Exception:
                if self._running:
                    pass  # 静默处理

    def _read_stderr(self):
        """后台线程：读取 stderr (静默)"""
        while self._running and self.process and self.process.stderr:
            try:
                self.process.stderr.readline()
            except Exception:
                break

    def _send_request(self, method: str, params: Dict[str, Any], timeout: int = 10) -> Optional[Dict[str, Any]]:
        """发送请求并等待响应"""
        self.request_id += 1
        request_id = self.request_id

        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }

        self._send_message(message)

        for _ in range(timeout * 10):
            with self._lock:
                if request_id in self._responses:
                    response = self._responses.pop(request_id)
                    return response
            time.sleep(0.1)

        return None

    def _send_notification(self, method: str, params: Dict[str, Any]) -> None:
        """发送通知"""
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        self._send_message(message)

    def initialize(self, root_path: str) -> bool:
        """初始化 LSP 服务器"""
        root_uri = Path(root_path).absolute().as_uri()

        response = self._send_request("initialize", {
            "processId": None,
            "rootUri": root_uri,
            "capabilities": {
                "textDocument": {
                    "documentSymbol": {
                        "hierarchicalDocumentSymbolSupport": True
                    }
                }
            }
        }, timeout=30)

        if not response or "error" in response:
            return False

        self._send_notification("initialized", {})
        self._initialized = True
        return True

    def open_document(self, file_path: str) -> None:
        """打开文档"""
        uri = Path(file_path).absolute().as_uri()
        content = Path(file_path).read_text()

        self._send_notification("textDocument/didOpen", {
            "textDocument": {
                "uri": uri,
                "languageId": "move",
                "version": 1,
                "text": content
            }
        })

    def get_document_symbols(self, file_path: str) -> List[Dict[str, Any]]:
        """获取文档符号"""
        uri = Path(file_path).absolute().as_uri()

        response = self._send_request("textDocument/documentSymbol", {
            "textDocument": {"uri": uri}
        })

        if not response or "error" in response:
            return []

        return response.get("result", [])


# ============================================================================
# LSP 辅助函数
# ============================================================================

def parse_use_aliases(code: str) -> Dict[str, str]:
    """
    🔥 v2.5.5: 解析 use 语句中的导入函数映射

    返回: {function_name_or_alias -> full::module::path::original}

    处理以下格式:
    1. use cetus_clmm::config::{checked_package_version}
       -> {"checked_package_version": "cetus_clmm::config::checked_package_version"}
    2. use cetus_clmm::config::{check as verify}
       -> {"verify": "cetus_clmm::config::check"}
    3. use sui::transfer::share_object;
       -> {"share_object": "sui::transfer::share_object"}
    4. use sui::transfer as tx;
       -> {"tx": "sui::transfer"} (模块别名，不是函数)
    """
    aliases = {}

    # 匹配 use module::path::{item1, item2 as alias, ...};
    use_pattern = re.compile(
        r'use\s+(\w+(?:::\w+)*)::\{([^}]+)\};',
        re.MULTILINE
    )

    for match in use_pattern.finditer(code):
        base_path = match.group(1)  # e.g., "cetus_clmm::config"
        items = match.group(2)

        for item in items.split(','):
            item = item.strip()
            if not item:
                continue

            if ' as ' in item:
                # 别名: func as alias
                original, alias = item.split(' as ')
                original = original.strip()
                alias = alias.strip()
                # 🔥 只添加小写开头的函数名
                if alias and alias[0].islower():
                    aliases[alias] = f"{base_path}::{original}"
            else:
                # 🔥 普通导入: 也要添加到映射
                if item and item[0].islower():
                    aliases[item] = f"{base_path}::{item}"

    # 匹配简单的 use module::func; (无别名)
    simple_import_pattern = re.compile(
        r'use\s+(\w+(?:::\w+)+);',
        re.MULTILINE
    )
    for match in simple_import_pattern.finditer(code):
        full_path = match.group(1)
        # 检查是否已经被上面的模式处理过 (包含 {})
        if '{' in full_path:
            continue
        parts = full_path.split('::')
        if len(parts) >= 2:
            func_name = parts[-1]
            # 🔥 只添加小写开头的函数名
            if func_name and func_name[0].islower():
                aliases[func_name] = full_path

    # 匹配 use module::func as alias;
    alias_pattern = re.compile(
        r'use\s+(\w+(?:::\w+)*)\s+as\s+(\w+);',
        re.MULTILINE
    )
    for match in alias_pattern.finditer(code):
        full_path = match.group(1)
        alias = match.group(2)
        parts = full_path.split('::')
        if len(parts) >= 2 and alias and alias[0].islower():
            # 🔥 使用完整路径
            aliases[alias] = full_path

    return aliases


def find_function_end(code: str, start_line: int) -> int:
    """
    从函数开始行找到函数结束行（通过匹配大括号）
    start_line: 0-indexed
    """
    lines = code.split('\n')
    brace_count = 0
    found_open = False

    for i in range(start_line, len(lines)):
        line = lines[i]
        for char in line:
            if char == '{':
                brace_count += 1
                found_open = True
            elif char == '}':
                brace_count -= 1
                if found_open and brace_count == 0:
                    return i

    return start_line


def _is_test_function(name: str, file_content: str, start_line: int) -> bool:
    """
    🔥 v2.5.5: 检测是否为测试函数

    过滤条件:
    1. 函数名以 test_ 开头
    2. 函数名以 _test 或 _for_test 结尾
    3. 函数上方有 #[test] 或 #[test_only] 属性
    """
    # 1. 检查函数名模式
    if name.startswith("test_"):
        return True
    if name.endswith("_test") or name.endswith("_for_test"):
        return True

    # 2. 检查属性 (向上查找 10 行内的属性)
    if file_content:
        lines = file_content.split('\n')
        # 🔥 修复: 从 start_line - 1 开始向上查找 (start_line 是函数声明行)
        search_start = max(0, start_line - 10)
        for i in range(start_line - 1, search_start - 1, -1):
            if i < 0 or i >= len(lines):
                continue
            line = lines[i].strip()
            # 空行跳过
            if not line:
                continue
            # 遇到其他函数声明就停止 (不是当前函数的属性)
            if line.startswith("fun ") or line.startswith("public ") or line.startswith("entry "):
                break
            # 遇到 } 就停止 (上一个函数的结束)
            if line == "}":
                break
            # 检查 test 属性
            if "#[test_only]" in line or "#[test]" in line:
                return True

    return False


def extract_functions_from_symbols(symbols: List[Dict], parent_module: str = "", file_content: str = "") -> List[Dict]:
    """从 LSP documentSymbol 响应中提取函数信息"""
    functions = []

    for sym in symbols:
        kind = sym.get("kind", 0)
        name = sym.get("name", "")

        # Module (kind=2)
        if kind == 2:
            children = sym.get("children", [])
            functions.extend(extract_functions_from_symbols(children, name, file_content))

        # Function (kind=12) or Method (kind=6)
        elif kind in (6, 12):
            loc = sym.get("location", sym.get("range", {}))
            if isinstance(loc, dict) and "range" in loc:
                start = loc["range"]["start"]
            elif isinstance(loc, dict) and "start" in loc:
                start = loc["start"]
            else:
                start = {"line": 0, "character": 0}

            start_line = start.get("line", 0)
            end_line = find_function_end(file_content, start_line) if file_content else start_line

            # 🔥 v2.5.5: 过滤测试函数
            if _is_test_function(name, file_content, start_line):
                continue

            functions.append({
                "name": name,
                "module": parent_module,
                "start_line": start_line,
                "end_line": end_line,
                "character": start.get("character", 0)
            })

        # 递归处理其他子符号
        else:
            children = sym.get("children", [])
            if children:
                functions.extend(extract_functions_from_symbols(children, parent_module or name, file_content))

    return functions


def find_function_calls_in_code(code: str, start_line: int, end_line: int, current_func: str) -> List[Tuple[int, int, str]]:
    """
    在代码段中查找函数调用
    返回: [(line, character, function_name), ...]
    """
    lines = code.split('\n')
    calls = []

    call_patterns = [
        re.compile(r'\b(\w+)::(\w+)\s*[\(<]'),  # module::function(
        re.compile(r'(?<![:\.\w])(\w+)\s*\('),   # standalone function(
    ]

    # 🔥 v2.5.4: 使用全局 KEYWORDS，包含属性关键字 (allow, lint, test, test_only)
    # 避免 #[allow(lint(self_transfer))] 被误识别为函数调用
    keywords = KEYWORDS | {
        'friend', 'borrow', 'borrow_mut', 'freeze',  # 额外补充
        'drop', 'store', 'key',  # 能力关键字
    }

    for line_no in range(start_line, min(end_line + 1, len(lines))):
        line = lines[line_no]

        if re.match(r'\s*(public\s+)?(entry\s+)?fun\s+', line):
            continue

        if line.strip().startswith('//'):
            continue

        # 模式1: module::function (跨模块调用)
        # 🔥 v2.5.6: 跨模块调用不需要检查 func_name == current_func
        # 因为 module::func 语法明确指定了不同模块，不会是函数定义自身
        # 例如: config::remove_role 调用 acl::remove_role 应该被捕获
        for match in call_patterns[0].finditer(line):
            module = match.group(1)
            func_name = match.group(2)

            # 只过滤关键字，不过滤同名函数 (跨模块调用是合法的)
            if func_name in keywords:
                continue

            func_start = match.start(2)
            calls.append((line_no, func_start, f"{module}::{func_name}"))

        # 模式2: standalone function
        for match in call_patterns[1].finditer(line):
            func_name = match.group(1)

            if func_name in keywords or func_name == current_func:
                continue

            char = match.start(1)
            if char >= 2 and line[char-2:char] == '::':
                continue

            calls.append((line_no, char, func_name))

    return calls


# ============================================================================
# 数据结构
# ============================================================================

@dataclass
class Span:
    start: int
    end: int

    def to_dict(self) -> Dict[str, int]:
        return {"start": self.start, "end": self.end}


@dataclass
class RiskIndicators:
    overflow: int = 0
    access_control: int = 0
    state_modification: int = 0
    division: int = 0
    external_call: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "overflow": self.overflow,
            "access_control": self.access_control,
            "state_modification": self.state_modification,
            "division": self.division,
            "external_call": self.external_call,
        }

    def total_score(self) -> int:
        """计算总风险分数"""
        weights = {
            "overflow": 10,
            "access_control": 15,
            "state_modification": 8,
            "division": 12,
            "external_call": 5,
        }
        return sum(getattr(self, k) * v for k, v in weights.items())


@dataclass
class FunctionNode:
    id: str
    type: str = "function"
    module_path: str = ""
    module_address: str = ""
    module_name: str = ""
    name: str = ""
    visibility: str = "private"
    span: Optional[Span] = None
    signature: str = ""
    summary: str = ""
    type_params: List[str] = field(default_factory=list)
    phantom_params: List[str] = field(default_factory=list)
    abilities: List[str] = field(default_factory=list)
    linear_resources: List[str] = field(default_factory=list)
    receipts: List[str] = field(default_factory=list)
    uses: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)
    # 🔥 新增：内部调用 vs 外部调用分类
    internal_calls: List[str] = field(default_factory=list)  # 项目内跨模块调用 (有定义)
    external_calls: List[str] = field(default_factory=list)  # 外部库调用 (无定义)
    # 🔥 新增：调用行号映射 (用于构建 edge)
    calls_with_lines: List[Tuple[str, int]] = field(default_factory=list)  # [(call_id, line), ...]
    risk_indicators: Optional[RiskIndicators] = None
    risk_score: int = 0

    def to_dict(self) -> dict:
        result = {
            "id": self.id,
            "type": self.type,
            "module_path": self.module_path,
            "module_address": self.module_address,
            "module_name": self.module_name,
            "name": self.name,
            "visibility": self.visibility,
            "span": self.span.to_dict() if self.span else None,
            "signature": self.signature,
            "summary": self.summary,
            "type_params": self.type_params,
            "phantom_params": self.phantom_params,
            "abilities": self.abilities,
            "linear_resources": self.linear_resources,
            "receipts": self.receipts,
            "uses": self.uses,
            "calls": self.calls,
            "called_by": self.called_by,
            # 🔥 新增字段
            "internal_calls": self.internal_calls,
            "external_calls": self.external_calls,
            "risk_indicators": self.risk_indicators.to_dict() if self.risk_indicators else None,
            "risk_score": self.risk_score,
        }
        return result


@dataclass
class TypeNode:
    id: str
    type: str = "struct"
    module_path: str = ""
    module_name: str = ""
    name: str = ""
    span: Optional[Span] = None
    abilities: List[str] = field(default_factory=list)
    has_uid: bool = False
    fields: List[str] = field(default_factory=list)
    type_params: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "module_path": self.module_path,
            "module_name": self.module_name,
            "name": self.name,
            "span": self.span.to_dict() if self.span else None,
            "abilities": self.abilities,
            "has_uid": self.has_uid,
            "fields": self.fields,
            "type_params": self.type_params,
        }


@dataclass
class Edge:
    from_id: str
    to_id: str
    edge_type: str = "calls"
    call_site_line: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "from": self.from_id,
            "to": self.to_id,
            "type": self.edge_type,
            "call_site_line": self.call_site_line,
        }


# ============================================================================
# 正则模式
# ============================================================================

# 模块声明 (支持两种语法)
# 旧语法: module address::name {
# 新语法 (Move 2024): module address::name;
MODULE_PATTERN = re.compile(
    r'module\s+(?:(?P<address>\w+)::)?(?P<name>\w+)\s*[;\{]',
    re.MULTILINE
)

# 函数声明 (支持各种修饰符)
FUNCTION_PATTERN = re.compile(
    r'(?P<attributes>(?:#\[[^\]]+\]\s*)*)'
    r'(?P<visibility>public(?:\s*\(\s*(?:friend|package)\s*\))?\s+)?'
    r'(?P<entry>entry\s+)?'
    r'fun\s+(?P<name>\w+)'
    r'\s*(?:<(?P<type_params>[^>]+)>)?'
    r'\s*\((?P<params>[^)]*)\)'
    r'(?:\s*:\s*(?P<return_type>[^{]+))?'
    r'\s*\{',
    re.MULTILINE | re.DOTALL
)

# 结构体声明
STRUCT_PATTERN = re.compile(
    r'(?P<visibility>public\s+)?struct\s+(?P<name>\w+)'
    r'(?:\s*<(?P<type_params>[^>]+)>)?'
    r'\s+has\s+(?P<abilities>[\w\s,]+)'
    r'\s*\{(?P<fields>[^}]*)\}',
    re.MULTILINE | re.DOTALL
)

# use 语句
USE_PATTERN = re.compile(
    r'use\s+(?P<path>[\w:]+)(?:::(?P<item>\{[^}]+\}|\w+))?;',
    re.MULTILINE
)

# 函数调用 - 跨模块调用 (module::function)
CALL_PATTERN = re.compile(
    r'(?P<module>\w+)::(?P<function>\w+)\s*(?:<[^>]*>)?\s*\(',
    re.MULTILINE
)

# 函数调用 - 模块内直接调用 (不带模块前缀)
# 匹配: function_name( 或 function_name<T>(
# 排除: 关键字、类型转换、控制流等
# 排除: 方法调用 (.method()) - 这些是类型方法，不是模块内函数
# 注意: 需要在 _parse_calls 中额外排除当前函数名 (排除函数定义匹配)
INTERNAL_CALL_PATTERN = re.compile(
    r'(?<![:\w.])(?P<function>[a-z_][a-z0-9_]*)\s*(?:<[^>]*>)?\s*\(',
    re.MULTILINE
)

# 需要排除的关键字（不是函数调用）
KEYWORDS = {
    'if', 'else', 'while', 'loop', 'return', 'abort', 'break', 'continue',
    'let', 'mut', 'move', 'copy', 'as', 'use', 'fun', 'public', 'entry',
    'struct', 'module', 'const', 'has', 'assert', 'spec', 'requires', 'ensures',
    'vector', 'option', 'some', 'none', 'true', 'false',
    'allow', 'lint', 'test', 'test_only',  # 属性关键字
}

# 线性资源类型
LINEAR_TYPES = {
    "Coin", "Balance", "TreasuryCap", "CoinMetadata",
    "Receipt", "FlashLoanReceipt", "HotPotato",
    "Position", "Pool", "Vault",
}

# 访问控制类型
ACCESS_CONTROL_TYPES = {
    "AdminCap", "OwnerCap", "TreasuryCap", "MinterCap",
    "Capability", "Witness", "Cap",
}


# ============================================================================
# 解析器
# ============================================================================

class MoveFileParser:
    """单个 Move 文件解析器"""

    def __init__(self, file_path: str, summary_length: int = 100):
        self.file_path = file_path
        self.summary_length = summary_length
        self.content = ""
        self.lines: List[str] = []
        self.module_address = ""
        self.module_name = ""

    def parse(self) -> Tuple[List[FunctionNode], List[TypeNode]]:
        """解析文件，返回函数节点和类型节点"""
        with open(self.file_path, "r", encoding="utf-8") as f:
            self.content = f.read()
        self.lines = self.content.split("\n")

        # 解析模块信息
        self._parse_module()

        # 解析 use 语句
        uses = self._parse_uses()

        # 解析函数
        functions = self._parse_functions(uses)

        # 解析结构体
        types = self._parse_structs()

        return functions, types

    def _parse_module(self):
        """解析模块声明"""
        match = MODULE_PATTERN.search(self.content)
        if match:
            self.module_address = match.group("address") or ""
            self.module_name = match.group("name") or ""

    def _parse_uses(self) -> List[str]:
        """解析 use 语句"""
        uses = []
        for match in USE_PATTERN.finditer(self.content):
            path = match.group("path")
            item = match.group("item")
            if item:
                uses.append(f"{path}::{item}")
            else:
                uses.append(path)
        return uses

    def _parse_functions(self, uses: List[str]) -> List[FunctionNode]:
        """解析所有函数"""
        functions = []

        for match in FUNCTION_PATTERN.finditer(self.content):
            func_name = match.group("name")

            # 🔥 v2.5.5: 跳过测试函数 (属性 + 函数名模式)
            attributes = match.group("attributes") or ""
            if "#[test_only]" in attributes or "#[test]" in attributes:
                continue
            # 函数名模式过滤
            if func_name.startswith("test_") or func_name.endswith("_test") or func_name.endswith("_for_test"):
                continue

            start_pos = match.start()
            start_line = self.content[:start_pos].count("\n") + 1

            # 找到函数结束位置 (匹配大括号)
            end_line = self._find_block_end(start_pos)

            # 提取函数体
            func_body = self._get_lines(start_line, end_line)

            # 解析可见性
            visibility = "private"
            vis_match = match.group("visibility")
            is_entry = bool(match.group("entry"))

            if vis_match:
                if "friend" in vis_match:
                    visibility = "public(friend)"
                elif "package" in vis_match:
                    visibility = "public(package)"
                else:
                    visibility = "public"

            # 正确处理 public entry 的顺序
            if is_entry:
                if visibility == "private":
                    visibility = "entry"
                else:
                    visibility = f"{visibility} entry"  # "public entry" 而不是 "entry public"

            # 解析类型参数
            type_params = []
            phantom_params = []
            if match.group("type_params"):
                for tp in match.group("type_params").split(","):
                    tp = tp.strip()
                    if tp.startswith("phantom"):
                        phantom_params.append(tp.replace("phantom", "").strip())
                    elif tp:
                        type_params.append(tp.split(":")[0].strip())

            # 解析参数中的线性资源
            linear_resources = []
            receipts = []
            params = match.group("params") or ""
            for lt in LINEAR_TYPES:
                if lt in params:
                    if "Receipt" in lt:
                        receipts.append(lt)
                    else:
                        linear_resources.append(lt)

            # 解析函数调用 (传入当前函数名以排除自引用，传入 uses 以解析导入函数)
            calls = self._parse_calls(func_body, match.group("name"), uses)

            # 计算风险指标
            risk_indicators = self._calculate_risk(func_body, params)

            # 生成摘要
            summary = self._generate_summary(match.group("name"), params, match.group("return_type"))

            # 构建签名
            sig_parts = []
            if visibility != "private":
                sig_parts.append(visibility)
            sig_parts.append(f"fun {match.group('name')}")
            if match.group("type_params"):
                sig_parts[-1] += f"<{match.group('type_params')}>"
            sig_parts[-1] += f"({params})"
            if match.group("return_type"):
                sig_parts[-1] += f": {match.group('return_type').strip()}"
            signature = " ".join(sig_parts)

            # 构建完整的函数 ID (与 project_indexer 保持一致)
            # 格式: address::module::function (如果有 address) 或 module::function
            if self.module_address:
                func_id = f"{self.module_address}::{self.module_name}::{match.group('name')}"
            else:
                func_id = f"{self.module_name}::{match.group('name')}"

            node = FunctionNode(
                id=func_id,
                module_path=self.file_path,
                module_address=self.module_address,
                module_name=self.module_name,
                name=match.group("name"),
                visibility=visibility,
                span=Span(start=start_line, end=end_line),
                signature=signature,
                summary=summary[:self.summary_length],
                type_params=type_params,
                phantom_params=phantom_params,
                linear_resources=linear_resources,
                receipts=receipts,
                uses=uses,
                calls=calls,
                risk_indicators=risk_indicators,
                risk_score=risk_indicators.total_score(),
            )
            functions.append(node)

        return functions

    def _parse_structs(self) -> List[TypeNode]:
        """解析所有结构体"""
        types = []

        for match in STRUCT_PATTERN.finditer(self.content):
            start_pos = match.start()
            start_line = self.content[:start_pos].count("\n") + 1
            end_line = start_line + match.group(0).count("\n")

            # 解析 abilities
            abilities = [a.strip() for a in match.group("abilities").split(",")]

            # 解析字段
            fields = []
            has_uid = False
            for field_line in match.group("fields").split(","):
                field_line = field_line.strip()
                if field_line:
                    fields.append(field_line)
                    if "UID" in field_line or "id: UID" in field_line:
                        has_uid = True

            # 解析类型参数
            type_params = []
            if match.group("type_params"):
                for tp in match.group("type_params").split(","):
                    tp = tp.strip()
                    type_params.append(tp.split(":")[0].strip())

            # 构建完整的类型 ID (与函数 ID 格式一致)
            if self.module_address:
                type_id = f"{self.module_address}::{self.module_name}::{match.group('name')}"
            else:
                type_id = f"{self.module_name}::{match.group('name')}"

            node = TypeNode(
                id=type_id,
                module_path=self.file_path,
                module_name=self.module_name,
                name=match.group("name"),
                span=Span(start=start_line, end=end_line),
                abilities=abilities,
                has_uid=has_uid,
                fields=fields,
                type_params=type_params,
            )
            types.append(node)

        return types

    def _find_block_end(self, start_pos: int) -> int:
        """找到代码块结束位置"""
        depth = 0
        in_string = False
        i = start_pos

        while i < len(self.content):
            char = self.content[i]

            # 简单的字符串检测
            if char == '"' and (i == 0 or self.content[i-1] != '\\'):
                in_string = not in_string

            if not in_string:
                if char == '{':
                    depth += 1
                elif char == '}':
                    depth -= 1
                    if depth == 0:
                        return self.content[:i].count("\n") + 1

            i += 1

        return len(self.lines)

    def _get_lines(self, start: int, end: int) -> str:
        """获取指定行范围的内容"""
        return "\n".join(self.lines[start-1:end])

    def _parse_calls(self, func_body: str, current_func_name: str = "", uses: List[str] = None) -> List[str]:
        """解析函数体中的调用（包括跨模块和模块内调用）

        Args:
            func_body: 函数体代码
            current_func_name: 当前函数名 (用于排除函数定义匹配导致的自引用)
            uses: use 语句列表 (用于解析导入的函数)
        """
        calls = []
        uses = uses or []

        # 🔥 构建导入函数名到完整调用ID的映射
        # 例如: use sui::transfer::{share_object} -> imported_funcs["share_object"] = "sui::transfer::share_object"
        # 例如: use myapp::auth::{check_admin as verify_admin} -> imported_funcs["verify_admin"] = "myapp::auth::check_admin"
        # 例如: use sui::coin::{Self, Coin, into_balance} -> imported_funcs["into_balance"] = "sui::coin::into_balance"
        imported_funcs: Dict[str, str] = {}
        for use_stmt in uses:
            # 解析 use 语句: "sui::transfer::{share_object,public_freeze_object}" 或 "sui::transfer::share_object"
            if "::{" in use_stmt:
                # 格式: module::{func1, func2, func3 as alias}
                base_module = use_stmt.split("::{")[0]
                items_part = use_stmt.split("::{")[1].rstrip("}")
                for item in items_part.split(","):
                    item = item.strip()
                    if not item:
                        continue
                    # 🔥 跳过 Self 和类型名 (大写开头)
                    if item == "Self" or (item[0].isupper() and " as " not in item):
                        continue
                    # 🔥 处理 as 别名: "check_permission as verify_access"
                    if " as " in item:
                        original, alias = item.split(" as ", 1)
                        original = original.strip()
                        alias = alias.strip()
                        # 别名可能是任意大小写，但原始名应该是小写函数名
                        if alias and original and original[0].islower():
                            imported_funcs[alias] = f"{base_module}::{original}"
                    else:
                        # 普通导入 - 只添加函数名 (小写开头)
                        if item[0].islower():
                            imported_funcs[item] = f"{base_module}::{item}"
            elif "::" in use_stmt:
                # 格式: module::func 或 module::submodule
                parts = use_stmt.rsplit("::", 1)
                if len(parts) == 2:
                    base_module, item = parts
                    # 🔥 处理 as 别名
                    if " as " in item:
                        original, alias = item.split(" as ", 1)
                        original = original.strip()
                        alias = alias.strip()
                        if alias and original and alias[0].islower():
                            imported_funcs[alias] = f"{base_module}::{original}"
                    # 只有当 item 看起来像函数名时才添加 (小写开头)
                    elif item and item[0].islower():
                        imported_funcs[item] = f"{base_module}::{item}"

        # 1. 解析跨模块调用: module::function()
        # 注意：这里 module 可能是短名称 (如 pool) 或完整路径 (如 cetus_clmm::pool)
        for match in CALL_PATTERN.finditer(func_body):
            module = match.group("module")
            function = match.group("function")
            call_id = f"{module}::{function}"
            if call_id not in calls:
                calls.append(call_id)

        # 2. 解析模块内直接调用: function()
        # 🔥 改进: 先检查是否是导入的函数
        for match in INTERNAL_CALL_PATTERN.finditer(func_body):
            function = match.group("function")
            # 排除关键字
            if function in KEYWORDS:
                continue
            # 排除当前函数名 (避免函数定义 `fun xxx()` 被误识别为调用)
            if function == current_func_name:
                continue

            # 🔥 检查是否是导入的函数 (映射值已经是完整路径)
            if function in imported_funcs:
                call_id = imported_funcs[function]  # 直接使用映射的完整路径
            else:
                # 构造调用 ID（使用完整的 address::module 格式）
                if self.module_address:
                    call_id = f"{self.module_address}::{self.module_name}::{function}"
                else:
                    call_id = f"{self.module_name}::{function}"

            if call_id not in calls:
                calls.append(call_id)

        return calls

    def _calculate_risk(self, func_body: str, params: str) -> RiskIndicators:
        """计算风险指标"""
        indicators = RiskIndicators()

        # 溢出风险 (乘法、加法、位移)
        indicators.overflow = len(re.findall(r'\*|\+|<<|>>', func_body))

        # 除法风险
        indicators.division = len(re.findall(r'/', func_body))

        # 访问控制
        for ac_type in ACCESS_CONTROL_TYPES:
            if ac_type in params or ac_type in func_body:
                indicators.access_control += 1

        # 状态修改
        indicators.state_modification = len(re.findall(
            r'balance::join|balance::split|coin::mint|coin::burn|transfer::|dynamic_field::|table::|bag::',
            func_body
        ))

        # 外部调用
        indicators.external_call = len(re.findall(r'::', func_body))

        return indicators

    def _generate_summary(self, name: str, params: str, return_type: Optional[str]) -> str:
        """生成函数摘要"""
        summary_parts = []

        # 基于函数名推断功能
        name_lower = name.lower()
        if "add" in name_lower and "liquidity" in name_lower:
            summary_parts.append("添加流动性")
        elif "remove" in name_lower and "liquidity" in name_lower:
            summary_parts.append("移除流动性")
        elif "swap" in name_lower:
            summary_parts.append("代币交换")
        elif "deposit" in name_lower:
            summary_parts.append("存款")
        elif "withdraw" in name_lower:
            summary_parts.append("取款")
        elif "borrow" in name_lower:
            summary_parts.append("借贷")
        elif "repay" in name_lower:
            summary_parts.append("还款")
        elif "mint" in name_lower:
            summary_parts.append("铸造")
        elif "burn" in name_lower:
            summary_parts.append("销毁")
        elif "transfer" in name_lower:
            summary_parts.append("转账")
        elif "init" in name_lower:
            summary_parts.append("初始化")
        elif "create" in name_lower:
            summary_parts.append("创建")
        elif "update" in name_lower:
            summary_parts.append("更新")
        elif "set" in name_lower:
            summary_parts.append("设置")
        elif "get" in name_lower:
            summary_parts.append("获取")
        else:
            summary_parts.append(name)

        # 添加返回类型信息
        if return_type:
            rt = return_type.strip()
            if "Position" in rt:
                summary_parts.append("返回 Position NFT")
            elif "Coin" in rt:
                summary_parts.append("返回 Coin")
            elif "Balance" in rt:
                summary_parts.append("返回 Balance")

        return ", ".join(summary_parts)


# ============================================================================
# 调用图构建器
# ============================================================================

class CallGraphBuilder:
    """调用图构建器 (支持 LSP 增强模式)"""

    def __init__(self, root: str, include_types: bool = True, summary_length: int = 100, use_lsp: bool = True):
        self.root = os.path.abspath(root)
        self.include_types = include_types
        self.summary_length = summary_length
        self.use_lsp = use_lsp
        self._lsp_client: Optional[LSPClient] = None

    def build(self) -> dict:
        """构建调用图 (优先使用 LSP，失败则回退到 regex)"""
        # 1. 确定项目名
        project_name = self._detect_project_name()

        # 2. 扫描所有 .move 文件
        move_files = self._scan_move_files()

        if not move_files:
            raise ValueError(f"未找到 .move 文件: {self.root}")

        # 3. 尝试使用 LSP 模式
        all_functions: List[FunctionNode] = []
        all_types: List[TypeNode] = []
        lsp_edges: List[Edge] = []
        use_lsp_mode = False

        if self.use_lsp:
            lsp_result = self._build_with_lsp(move_files)
            if lsp_result:
                all_functions, all_types, lsp_edges = lsp_result
                use_lsp_mode = True
                print(f"[INFO] 使用 LSP 模式构建调用图")

        # 4. LSP 失败时回退到 regex 模式
        if not use_lsp_mode:
            print(f"[INFO] 使用 regex 模式构建调用图")
            for file_path in move_files:
                try:
                    parser = MoveFileParser(file_path, self.summary_length)
                    functions, types = parser.parse()
                    all_functions.extend(functions)
                    all_types.extend(types)
                except Exception as e:
                    print(f"[WARN] 解析失败 {file_path}: {e}")

        # 5. 构建边 (调用关系)
        if use_lsp_mode:
            edges = lsp_edges
        else:
            edges = self._build_edges(all_functions)

        # 6. 填充 called_by
        self._fill_called_by(all_functions, edges)

        # 7. 🔥 计算入口点和叶子节点
        entry_points = [n.id for n in all_functions if not n.called_by]
        leaf_nodes = [n.id for n in all_functions if not n.internal_calls]

        # 8. 构建最终 JSON
        return {
            "meta": {
                "project": project_name,
                "root": self.root,
                "generated_at": datetime.now().isoformat(),
                "total_modules": len(set(n.module_name for n in all_functions)),
                "total_functions": len(all_functions),
                "total_types": len(all_types),
                "total_edges": len(edges),
                "mode": "lsp" if use_lsp_mode else "regex",
            },
            "nodes": [n.to_dict() for n in all_functions],
            "edges": [e.to_dict() for e in edges],
            "type_nodes": [t.to_dict() for t in all_types] if self.include_types else [],
            # 🔥 新增：入口点和叶子节点 (方便 agent 理解)
            "entry_points": entry_points,  # 无调用者的函数 (攻击入口)
            "leaf_nodes": leaf_nodes,       # 不调用其他项目函数的函数
        }

    def _build_with_lsp(self, move_files: List[str]) -> Optional[Tuple[List[FunctionNode], List[TypeNode], List[Edge]]]:
        """使用 LSP 构建调用图"""
        # 启动 LSP 客户端
        self._lsp_client = LSPClient()
        if not self._lsp_client.start():
            return None

        try:
            time.sleep(1)  # 等待启动

            # 找到项目根目录 (包含 Move.toml)
            project_root = self._find_project_root()
            if not self._lsp_client.initialize(project_root):
                print("[LSP] 初始化失败")
                return None

            time.sleep(1)  # 等待初始化

            all_functions: List[FunctionNode] = []
            all_types: List[TypeNode] = []
            file_aliases: Dict[str, Dict[str, str]] = {}  # file -> {alias -> original}
            func_info_map: Dict[str, Dict] = {}  # func_id -> {module, name, file, ...}

            # 第一遍：收集所有函数
            first_file = True
            for file_path in move_files:
                # 打开文档
                self._lsp_client.open_document(file_path)

                # 🔥 首次打开需要等待编译 (Move 2024 项目可能需要 5+ 秒)
                wait_time = 5.0 if first_file else 0.5
                first_file = False
                time.sleep(wait_time)

                # 获取文档符号 (带重试，增加重试次数)
                symbols = None
                for _ in range(5):  # 🔥 增加到 5 次
                    symbols = self._lsp_client.get_document_symbols(file_path)
                    if symbols:
                        break
                    time.sleep(1.5)  # 🔥 增加等待时间

                # 🔥 LSP 失败时使用 regex fallback
                if not symbols:
                    file_content = Path(file_path).read_text()
                    lsp_functions = self._extract_functions_regex_fallback(file_content, file_path)
                    if not lsp_functions:
                        continue
                    # 直接处理 regex 解析的函数
                    for func_info in lsp_functions:
                        # 构建 FunctionNode 并添加
                        all_functions.append(func_info)
                        func_info_map[func_info.id] = {
                            "module": func_info.module_name,
                            "name": func_info.name,
                            "file": file_path,
                        }
                    continue

                # 读取文件内容
                file_content = Path(file_path).read_text()

                # 解析别名
                aliases = parse_use_aliases(file_content)
                file_aliases[file_path] = aliases

                # 解析 use 语句
                uses = self._parse_uses_from_content(file_content)

                # 解析模块信息
                module_match = MODULE_PATTERN.search(file_content)
                module_address = module_match.group("address") if module_match else ""
                module_name = module_match.group("name") if module_match else ""

                # 提取函数
                lsp_functions = extract_functions_from_symbols(symbols, file_content=file_content)

                for func in lsp_functions:
                    func_name = func["name"]
                    func_module = func["module"] or module_name
                    start_line = func["start_line"]
                    end_line = func["end_line"]

                    # 提取函数体
                    func_body = self._get_lines_from_content(file_content, start_line, end_line)

                    # 解析可见性和其他属性 (从函数体第一行)
                    visibility, is_entry, params, return_type, type_params_str = self._parse_function_header(func_body)

                    # 解析函数调用 (使用 LSP 辅助函数)
                    raw_calls = find_function_calls_in_code(file_content, start_line, end_line, func_name)

                    # 🔥 解析别名并构建调用列表 (保留行号，分类内/外部调用)
                    calls = []
                    calls_with_lines = []  # [(call_id, line), ...]
                    for line_no, _, call_name in raw_calls:
                        # 解析别名
                        resolved = call_name
                        original_name = call_name  # 保存原始名用于显示
                        if call_name in aliases:
                            resolved = aliases[call_name]

                        # 构建调用 ID
                        if "::" in resolved:
                            call_id = resolved
                        else:
                            # 同模块调用
                            call_id = f"{func_module}::{resolved}"

                        if call_id not in calls:
                            calls.append(call_id)
                        # 🔥 保存行号 (1-indexed)
                        calls_with_lines.append((call_id, line_no + 1))

                    # 计算风险指标
                    risk_indicators = self._calculate_risk_from_body(func_body, params)

                    # 生成摘要
                    summary = self._generate_summary_for_func(func_name, params, return_type)

                    # 构建签名
                    signature = self._build_signature(visibility, is_entry, func_name, type_params_str, params, return_type)

                    # 构建函数 ID
                    if module_address:
                        func_id = f"{module_address}::{func_module}::{func_name}"
                    else:
                        func_id = f"{func_module}::{func_name}"

                    # 解析类型参数
                    type_params = []
                    phantom_params = []
                    if type_params_str:
                        for tp in type_params_str.split(","):
                            tp = tp.strip()
                            if tp.startswith("phantom"):
                                phantom_params.append(tp.replace("phantom", "").strip())
                            elif tp:
                                type_params.append(tp.split(":")[0].strip())

                    # 解析线性资源
                    linear_resources = []
                    receipts = []
                    for lt in LINEAR_TYPES:
                        if lt in params:
                            if "Receipt" in lt:
                                receipts.append(lt)
                            else:
                                linear_resources.append(lt)

                    node = FunctionNode(
                        id=func_id,
                        module_path=file_path,
                        module_address=module_address,
                        module_name=func_module,
                        name=func_name,
                        visibility=visibility,
                        span=Span(start=start_line + 1, end=end_line + 1),  # 转为 1-indexed
                        signature=signature,
                        summary=summary[:self.summary_length],
                        type_params=type_params,
                        phantom_params=phantom_params,
                        linear_resources=linear_resources,
                        receipts=receipts,
                        uses=uses,
                        calls=calls,
                        calls_with_lines=calls_with_lines,  # 🔥 保存行号
                        risk_indicators=risk_indicators,
                        risk_score=risk_indicators.total_score(),
                    )
                    all_functions.append(node)
                    func_info_map[func_id] = {
                        "module": func_module,
                        "name": func_name,
                        "file": file_path,
                    }

                # 解析结构体 (仍用 regex)
                types = self._parse_structs_from_content(file_content, file_path, module_address, module_name)
                all_types.extend(types)

            # 第二遍：构建调用边 (基于名字匹配)
            edges = self._build_edges_with_aliases(all_functions, file_aliases)

            return all_functions, all_types, edges

        except Exception as e:
            print(f"[LSP] 构建失败: {e}")
            import traceback
            traceback.print_exc()
            return None

        finally:
            if self._lsp_client:
                self._lsp_client.stop()

    def _find_project_root(self) -> str:
        """找到项目根目录 (包含 Move.toml)"""
        # 从 self.root 向上查找 Move.toml
        current = self.root
        for _ in range(5):  # 最多向上 5 层
            toml_path = os.path.join(current, "Move.toml")
            if os.path.exists(toml_path):
                return current
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        return self.root

    def _parse_uses_from_content(self, content: str) -> List[str]:
        """从文件内容解析 use 语句"""
        uses = []
        for match in USE_PATTERN.finditer(content):
            path = match.group("path")
            item = match.group("item")
            if item:
                uses.append(f"{path}::{item}")
            else:
                uses.append(path)
        return uses

    def _build_imported_funcs_from_uses(self, uses: List[str]) -> Dict[str, str]:
        """
        🔥 v2.5.5: 从 use 语句构建导入函数映射

        Args:
            uses: use 语句列表，如 ["cetus_clmm::config::{Self, checked_package_version}"]

        Returns:
            导入函数名到完整路径的映射，如 {"checked_package_version": "cetus_clmm::config::checked_package_version"}
        """
        imported_funcs: Dict[str, str] = {}

        for use_stmt in uses:
            if "::{" in use_stmt:
                # 格式: module::{func1, func2, func3 as alias}
                base_module = use_stmt.split("::{")[0]
                items_part = use_stmt.split("::{")[1].rstrip("}")
                for item in items_part.split(","):
                    item = item.strip()
                    if not item:
                        continue
                    # 处理别名: func as alias
                    if " as " in item:
                        original, alias = item.split(" as ", 1)
                        original = original.strip()
                        alias = alias.strip()
                        if alias and original and original[0].islower():
                            imported_funcs[alias] = f"{base_module}::{original}"
                    else:
                        # 普通导入 - 只添加函数名 (小写开头)
                        if item[0].islower():
                            imported_funcs[item] = f"{base_module}::{item}"
            elif "::" in use_stmt:
                # 格式: module::func 或 module::submodule
                parts = use_stmt.rsplit("::", 1)
                if len(parts) == 2:
                    base_module, item = parts
                    if " as " in item:
                        original, alias = item.split(" as ", 1)
                        original = original.strip()
                        alias = alias.strip()
                        if alias and original and alias[0].islower():
                            imported_funcs[alias] = f"{base_module}::{original}"
                    elif item and item[0].islower():
                        imported_funcs[item] = f"{base_module}::{item}"

        return imported_funcs

    def _get_lines_from_content(self, content: str, start: int, end: int) -> str:
        """从内容获取指定行范围 (0-indexed)"""
        lines = content.split("\n")
        return "\n".join(lines[start:end + 1])

    def _parse_function_header(self, func_body: str) -> Tuple[str, bool, str, str, str]:
        """解析函数头部，返回 (visibility, is_entry, params, return_type, type_params)"""
        first_line = func_body.split('\n')[0] if func_body else ""

        visibility = "private"
        is_entry = False

        if "public(friend)" in first_line:
            visibility = "public(friend)"
        elif "public(package)" in first_line:
            visibility = "public(package)"
        elif "public" in first_line:
            visibility = "public"

        if "entry" in first_line:
            is_entry = True
            if visibility == "private":
                visibility = "entry"
            else:
                visibility = f"{visibility} entry"

        # 提取参数
        params_match = re.search(r'\(([^)]*)\)', func_body)
        params = params_match.group(1) if params_match else ""

        # 提取返回类型
        return_type = ""
        ret_match = re.search(r'\)\s*:\s*([^{]+)', func_body)
        if ret_match:
            return_type = ret_match.group(1).strip()

        # 提取类型参数
        type_params = ""
        tp_match = re.search(r'fun\s+\w+\s*<([^>]+)>', func_body)
        if tp_match:
            type_params = tp_match.group(1)

        return visibility, is_entry, params, return_type, type_params

    def _calculate_risk_from_body(self, func_body: str, params: str) -> RiskIndicators:
        """计算风险指标"""
        indicators = RiskIndicators()

        indicators.overflow = len(re.findall(r'\*|\+|<<|>>', func_body))
        indicators.division = len(re.findall(r'/', func_body))

        for ac_type in ACCESS_CONTROL_TYPES:
            if ac_type in params or ac_type in func_body:
                indicators.access_control += 1

        indicators.state_modification = len(re.findall(
            r'balance::join|balance::split|coin::mint|coin::burn|transfer::|dynamic_field::|table::|bag::',
            func_body
        ))

        indicators.external_call = len(re.findall(r'::', func_body))

        return indicators

    def _generate_summary_for_func(self, name: str, params: str, return_type: str) -> str:
        """生成函数摘要"""
        summary_parts = []
        name_lower = name.lower()

        if "add" in name_lower and "liquidity" in name_lower:
            summary_parts.append("添加流动性")
        elif "remove" in name_lower and "liquidity" in name_lower:
            summary_parts.append("移除流动性")
        elif "swap" in name_lower:
            summary_parts.append("代币交换")
        elif "deposit" in name_lower:
            summary_parts.append("存款")
        elif "withdraw" in name_lower:
            summary_parts.append("取款")
        elif "borrow" in name_lower:
            summary_parts.append("借贷")
        elif "repay" in name_lower:
            summary_parts.append("还款")
        elif "mint" in name_lower:
            summary_parts.append("铸造")
        elif "burn" in name_lower:
            summary_parts.append("销毁")
        elif "transfer" in name_lower:
            summary_parts.append("转账")
        elif "init" in name_lower:
            summary_parts.append("初始化")
        elif "create" in name_lower:
            summary_parts.append("创建")
        elif "update" in name_lower:
            summary_parts.append("更新")
        elif "set" in name_lower:
            summary_parts.append("设置")
        elif "get" in name_lower:
            summary_parts.append("获取")
        else:
            summary_parts.append(name)

        if return_type:
            if "Position" in return_type:
                summary_parts.append("返回 Position NFT")
            elif "Coin" in return_type:
                summary_parts.append("返回 Coin")
            elif "Balance" in return_type:
                summary_parts.append("返回 Balance")

        return ", ".join(summary_parts)

    def _extract_functions_regex_fallback(self, file_content: str, file_path: str) -> List[FunctionNode]:
        """
        🔥 Regex fallback: 当 LSP 无法解析时使用 (支持 Move 2024 新语法)

        Move 2024 新语法: module address::name; (无大括号包裹)
        """
        functions = []

        # 解析模块名
        module_match = MODULE_PATTERN.search(file_content)
        module_address = module_match.group("address") if module_match else ""
        module_name = module_match.group("name") if module_match else "unknown"

        # 解析 use 语句
        uses = self._parse_uses_from_content(file_content)

        # 使用 FUNCTION_PATTERN 解析函数
        for match in FUNCTION_PATTERN.finditer(file_content):
            func_name = match.group("name")

            # 🔥 v2.5.5: 跳过测试函数 (属性 + 函数名模式)
            attributes = match.group("attributes") or ""
            if "#[test_only]" in attributes or "#[test]" in attributes:
                continue
            # 函数名模式过滤
            if func_name.startswith("test_") or func_name.endswith("_test") or func_name.endswith("_for_test"):
                continue
            start_pos = match.start()
            start_line = file_content[:start_pos].count("\n") + 1

            # 找到函数结束行
            end_line = find_function_end(file_content, start_line - 1) + 1

            # 提取函数体
            func_body = self._get_lines_from_content(file_content, start_line - 1, end_line - 1)

            # 解析可见性
            visibility, is_entry, params, return_type, type_params_str = self._parse_function_header(func_body)

            # 解析函数调用
            # 🔥 v2.5.5: 构建导入函数映射，正确解析跨模块导入的函数调用
            imported_funcs = self._build_imported_funcs_from_uses(uses)

            raw_calls = find_function_calls_in_code(file_content, start_line - 1, end_line - 1, func_name)
            calls = []
            calls_with_lines = []
            for line_no, _, call_name in raw_calls:
                if "::" in call_name:
                    # 已有模块前缀的调用
                    call_id = call_name
                elif call_name in imported_funcs:
                    # 🔥 导入函数，使用完整路径
                    call_id = imported_funcs[call_name]
                else:
                    # 模块内部函数
                    if module_address:
                        call_id = f"{module_address}::{module_name}::{call_name}"
                    else:
                        call_id = f"{module_name}::{call_name}"
                if call_id not in calls:
                    calls.append(call_id)
                calls_with_lines.append((call_id, line_no + 1))

            # 计算风险指标
            risk_indicators = self._calculate_risk_from_body(func_body, params)

            # 生成摘要
            summary = self._generate_summary_for_func(func_name, params, return_type)

            # 构建签名
            signature = self._build_signature(visibility, is_entry, func_name, type_params_str, params, return_type)

            # 构建函数 ID
            if module_address:
                func_id = f"{module_address}::{module_name}::{func_name}"
            else:
                func_id = f"{module_name}::{func_name}"

            node = FunctionNode(
                id=func_id,
                module_path=file_path,
                module_address=module_address,
                module_name=module_name,
                name=func_name,
                visibility=visibility,
                span=Span(start=start_line, end=end_line),
                signature=signature,
                summary=summary[:self.summary_length],
                uses=uses,
                calls=calls,
                calls_with_lines=calls_with_lines,
                risk_indicators=risk_indicators,
                risk_score=risk_indicators.total_score(),
            )
            functions.append(node)

        return functions

    def _build_signature(self, visibility: str, is_entry: bool, name: str, type_params: str, params: str, return_type: str) -> str:
        """构建函数签名"""
        sig_parts = []
        if visibility != "private":
            sig_parts.append(visibility)
        sig_parts.append(f"fun {name}")
        if type_params:
            sig_parts[-1] += f"<{type_params}>"
        sig_parts[-1] += f"({params})"
        if return_type:
            sig_parts[-1] += f": {return_type}"
        return " ".join(sig_parts)

    def _parse_structs_from_content(self, content: str, file_path: str, module_address: str, module_name: str) -> List[TypeNode]:
        """从内容解析结构体"""
        types = []

        for match in STRUCT_PATTERN.finditer(content):
            start_pos = match.start()
            start_line = content[:start_pos].count("\n") + 1
            end_line = start_line + match.group(0).count("\n")

            abilities = [a.strip() for a in match.group("abilities").split(",")]

            fields = []
            has_uid = False
            for field_line in match.group("fields").split(","):
                field_line = field_line.strip()
                if field_line:
                    fields.append(field_line)
                    if "UID" in field_line or "id: UID" in field_line:
                        has_uid = True

            type_params = []
            if match.group("type_params"):
                for tp in match.group("type_params").split(","):
                    tp = tp.strip()
                    type_params.append(tp.split(":")[0].strip())

            if module_address:
                type_id = f"{module_address}::{module_name}::{match.group('name')}"
            else:
                type_id = f"{module_name}::{match.group('name')}"

            node = TypeNode(
                id=type_id,
                module_path=file_path,
                module_name=module_name,
                name=match.group("name"),
                span=Span(start=start_line, end=end_line),
                abilities=abilities,
                has_uid=has_uid,
                fields=fields,
                type_params=type_params,
            )
            types.append(node)

        return types

    def _build_edges_with_aliases(self, functions: List[FunctionNode], file_aliases: Dict[str, Dict[str, str]]) -> List[Edge]:
        """构建调用边 (支持别名解析) + 分类内/外部调用"""
        edges = []

        # 构建函数名索引
        func_name_index: Dict[str, List[Tuple[str, str]]] = {}  # name -> [(module, full_id), ...]
        for f in functions:
            if f.name not in func_name_index:
                func_name_index[f.name] = []
            func_name_index[f.name].append((f.module_name, f.id))

        # 构建短名称到完整 ID 的映射
        short_to_full_id: Dict[str, str] = {}
        all_func_ids = set()
        for f in functions:
            short_id = f"{f.module_name}::{f.name}"
            short_to_full_id[short_id] = f.id
            all_func_ids.add(f.id)

        # 🔥 构建 call -> line 映射 (用于获取行号)
        def get_call_line(func: FunctionNode, call_id: str) -> Optional[int]:
            """从 calls_with_lines 获取调用行号"""
            for cid, line in func.calls_with_lines:
                if cid == call_id:
                    return line
            return None

        for func in functions:
            internal_calls = []  # 项目内调用 (有定义)
            external_calls = []  # 外部库调用 (无定义)

            for call in func.calls:
                target_id = None
                call_line = get_call_line(func, call)

                # 1. 直接匹配完整 ID
                if call in all_func_ids:
                    target_id = call

                # 2. 短名称匹配
                if not target_id and call in short_to_full_id:
                    target_id = short_to_full_id[call]

                # 3. 按模块::函数名匹配
                if not target_id and "::" in call:
                    parts = call.split("::")
                    call_module = parts[-2] if len(parts) >= 2 else ""
                    call_func = parts[-1]

                    if call_func in func_name_index:
                        for (m, full_id) in func_name_index[call_func]:
                            if m == call_module:
                                target_id = full_id
                                break

                # 4. 仅函数名匹配 (同模块优先)
                if not target_id and "::" not in call:
                    if call in func_name_index:
                        candidates = func_name_index[call]
                        # 同模块优先
                        for (m, full_id) in candidates:
                            if m == func.module_name:
                                target_id = full_id
                                break
                        # 唯一候选
                        if not target_id and len(candidates) == 1:
                            target_id = candidates[0][1]

                # 🔥 分类内部/外部调用
                if target_id and target_id != func.id:  # 排除自引用
                    internal_calls.append(target_id)
                    # 构建 edge (带行号)
                    edge = Edge(
                        from_id=func.id,
                        to_id=target_id,
                        edge_type="calls",
                        call_site_line=call_line,  # 🔥 保存行号
                    )
                    if not any(e.from_id == edge.from_id and e.to_id == edge.to_id for e in edges):
                        edges.append(edge)
                elif call and call != func.id:
                    # 找不到定义 = 外部库调用
                    external_calls.append(call)

            # 🔥 更新函数节点的内/外部调用分类
            func.internal_calls = list(set(internal_calls))
            func.external_calls = list(set(external_calls))

        return edges

    def _detect_project_name(self) -> str:
        """检测项目名"""
        # 优先从 Move.toml 读取
        toml_paths = [
            os.path.join(self.root, "Move.toml"),
            os.path.join(os.path.dirname(self.root), "Move.toml"),
        ]

        for toml_path in toml_paths:
            if os.path.exists(toml_path):
                try:
                    with open(toml_path, "r") as f:
                        content = f.read()
                    match = re.search(r'name\s*=\s*"([^"]+)"', content)
                    if match:
                        return match.group(1)
                except Exception:
                    pass

        # 否则使用目录名
        return os.path.basename(self.root.rstrip("/"))

    def _scan_move_files(self) -> List[str]:
        """扫描所有 .move 文件"""
        move_files = []

        if os.path.isfile(self.root) and self.root.endswith(".move"):
            return [self.root]

        for root, dirs, files in os.walk(self.root):
            # 🔥 v2.5.5: 跳过 build, tests 和版本控制目录
            dirs[:] = [d for d in dirs if d not in ["build", "tests", ".git", "node_modules"]]

            for file in files:
                if file.endswith(".move"):
                    # 🔥 v2.5.5: 跳过测试文件 (文件名包含 _test 或 _tests)
                    if "_test.move" in file or "_tests.move" in file:
                        continue
                    move_files.append(os.path.join(root, file))

        return sorted(move_files)

    def _build_edges(self, functions: List[FunctionNode]) -> List[Edge]:
        """构建调用边"""
        edges = []

        # 构建 id 到节点的映射
        id_to_node = {f.id: f for f in functions}

        # 构建短名称到完整 ID 的映射
        # 例如: "pool::swap" -> "cetus_clmm::pool::swap"
        short_to_full_id: Dict[str, str] = {}
        for f in functions:
            # 短名称: module::function
            short_id = f"{f.module_name}::{f.name}"
            short_to_full_id[short_id] = f.id

        for func in functions:
            for call in func.calls:
                # 首先尝试直接匹配 (完整 ID)
                if call in id_to_node:
                    edges.append(Edge(
                        from_id=func.id,
                        to_id=call,
                        edge_type="calls",
                    ))
                    continue

                # 尝试通过短名称匹配
                # call 格式可能是 "module::function"
                if call in short_to_full_id:
                    edges.append(Edge(
                        from_id=func.id,
                        to_id=short_to_full_id[call],
                        edge_type="calls",
                    ))

        return edges

    def _fill_called_by(self, functions: List[FunctionNode], edges: List[Edge]):
        """填充 called_by 字段"""
        called_by_map: Dict[str, List[str]] = {}

        for edge in edges:
            if edge.to_id not in called_by_map:
                called_by_map[edge.to_id] = []
            if edge.from_id not in called_by_map[edge.to_id]:
                called_by_map[edge.to_id].append(edge.from_id)

        for func in functions:
            func.called_by = called_by_map.get(func.id, [])


# ============================================================================
# 调用图查询接口
# ============================================================================

class CallGraphQuery:
    """调用图查询接口"""

    def __init__(self, graph: dict):
        self.graph = graph
        self._build_index()

    def _build_index(self):
        """构建索引"""
        self.nodes_by_id = {n["id"]: n for n in self.graph["nodes"]}
        self.types_by_id = {t["id"]: t for t in self.graph.get("type_nodes", [])}

        # 构建短名称索引 (module::function -> full_id)
        # 用于兼容旧格式的查询
        self.short_name_index: Dict[str, str] = {}
        for node in self.graph["nodes"]:
            module_name = node.get("module_name", "")
            func_name = node.get("name", "")
            if module_name and func_name:
                short_id = f"{module_name}::{func_name}"
                self.short_name_index[short_id] = node["id"]

    def get_function(self, func_id: str) -> Optional[dict]:
        """获取函数节点 (支持完整ID和短名称)"""
        # 首先尝试完整 ID
        if func_id in self.nodes_by_id:
            return self.nodes_by_id[func_id]

        # 尝试短名称匹配
        if func_id in self.short_name_index:
            full_id = self.short_name_index[func_id]
            return self.nodes_by_id.get(full_id)

        return None

    def get_neighbors(self, func_id: str, depth: int = 1) -> List[dict]:
        """获取邻居节点"""
        if depth <= 0:
            return []

        node = self.get_function(func_id)
        if not node:
            return []

        neighbors = []
        visited = {func_id}

        # 获取调用的函数
        for call_id in node.get("calls", []):
            if call_id not in visited:
                visited.add(call_id)
                if call_id in self.nodes_by_id:
                    neighbors.append(self.nodes_by_id[call_id])

        # 获取被调用的函数
        for caller_id in node.get("called_by", []):
            if caller_id not in visited:
                visited.add(caller_id)
                if caller_id in self.nodes_by_id:
                    neighbors.append(self.nodes_by_id[caller_id])

        # 递归获取更深层次的邻居
        if depth > 1:
            for neighbor in list(neighbors):
                deep_neighbors = self.get_neighbors(neighbor["id"], depth - 1)
                for dn in deep_neighbors:
                    if dn["id"] not in visited:
                        visited.add(dn["id"])
                        neighbors.append(dn)

        return neighbors

    def get_functions_by_module(self, module_name: str) -> List[dict]:
        """获取模块内的所有函数"""
        return [n for n in self.graph["nodes"] if n["module_name"] == module_name]

    def get_high_risk_functions(self, threshold: int = 50) -> List[dict]:
        """获取高风险函数"""
        return [n for n in self.graph["nodes"] if n.get("risk_score", 0) >= threshold]

    def get_type_definitions(self, type_names: List[str]) -> List[dict]:
        """获取类型定义"""
        return [t for t in self.graph.get("type_nodes", []) if t["name"] in type_names]


# ============================================================================
# 函数上下文构建器
# ============================================================================

class FunctionContextBuilder:
    """基于调用图构建函数验证上下文"""

    def __init__(self, graph: dict, config: Optional[dict] = None, project_root: Optional[str] = None):
        """
        Args:
            graph: 调用图 JSON
            config: 上下文配置 (来自 CONTEXT_CONFIG)
            project_root: 项目根目录 (用于解析外部依赖)
        """
        self.graph = graph
        self.query = CallGraphQuery(graph)
        self.project_root = project_root

        # 初始化依赖解析器
        self.dependency_resolver = None
        if DependencyResolver and project_root:
            try:
                self.dependency_resolver = DependencyResolver(project_root)
                print(f"[FunctionContextBuilder] 依赖解析器已初始化: {project_root}")
            except Exception as e:
                print(f"[FunctionContextBuilder] 依赖解析器初始化失败: {e}")

        # 默认配置
        self.config = config or {
            "neighbor_depth": 3,  # 增加到3层以捕获更完整的调用链
            "max_neighbors_per_level": 8,
            "max_context_tokens": 12000,
            "include_type_definitions": True,
            "resolve_external_deps": True,  # 是否解析外部依赖
            "collect_neighbor_external_deps": True,  # 是否收集邻居的外部依赖
        }

    def build_context(
        self,
        target_functions: List[str],
        module_name: str,
        source_code: str,
    ) -> dict:
        """
        构建目标函数的验证上下文

        Args:
            target_functions: 目标函数名列表 (如 ["swap", "add_liquidity"])
            module_name: 模块名
            source_code: 原模块完整源码

        Returns:
            dict: 包含 target_code, neighbors, types, imports, external_deps 的上下文
        """
        context = {
            "target_functions": [],
            "neighbors": [],
            "types": [],
            "imports": [],
            "module_summary": "",
            "external_deps": [],  # 🔥 新增：外部依赖的函数实现
        }

        # 收集所有外部调用 (用于后续解析)
        all_external_calls = set()

        # 1. 收集目标函数信息
        for func_name in target_functions:
            func_id = f"{module_name}::{func_name}"
            func_node = self.query.get_function(func_id)
            if func_node:
                context["target_functions"].append({
                    "name": func_name,
                    "id": func_id,
                    "signature": func_node.get("signature", ""),
                    "risk_score": func_node.get("risk_score", 0),
                    "span": func_node.get("span"),
                    "code": self._extract_function_code(source_code, func_node.get("span")),
                })

                # 收集 imports
                for use in func_node.get("uses", []):
                    if use not in context["imports"]:
                        context["imports"].append(use)

                # 🔥 收集外部调用 (不在当前模块的调用)
                for call in func_node.get("calls", []):
                    if "::" in call:
                        call_module = call.split("::")[0]
                        # 如果调用的模块不是当前模块，且不在调用图中，则是外部调用
                        if call_module != module_name and not self.query.get_function(call):
                            all_external_calls.add(call)

        # 2. 收集邻居函数 (调用/被调)
        depth = self.config.get("neighbor_depth", 3)
        max_per_level = self.config.get("max_neighbors_per_level", 8)
        visited_ids = {f["id"] for f in context["target_functions"]}
        collect_neighbor_deps = self.config.get("collect_neighbor_external_deps", True)

        for target in context["target_functions"]:
            neighbors = self.query.get_neighbors(target["id"], depth=depth)
            for neighbor in neighbors[:max_per_level]:
                if neighbor["id"] not in visited_ids:
                    visited_ids.add(neighbor["id"])

                    # 🔥 关键改进：内联被调用函数的代码
                    neighbor_code = ""
                    if self.config.get("inline_neighbor_code", True):
                        neighbor_code = self._extract_neighbor_code(neighbor)

                    context["neighbors"].append({
                        "name": neighbor.get("name"),
                        "id": neighbor["id"],
                        "signature": neighbor.get("signature", ""),
                        "summary": neighbor.get("summary", ""),
                        "risk_score": neighbor.get("risk_score", 0),
                        "relation": self._get_relation(target["id"], neighbor),
                        "code": neighbor_code,  # 🔥 新增：邻居函数完整代码
                        "module_path": neighbor.get("module_path", ""),
                    })

                    # 🔥 收集邻居函数的外部调用
                    if collect_neighbor_deps:
                        for call in neighbor.get("calls", []):
                            if "::" in call and not self.query.get_function(call):
                                all_external_calls.add(call)

        # 3. 收集相关类型定义
        if self.config.get("include_type_definitions", True):
            # 从函数签名中提取类型名
            type_names = self._extract_type_names(context["target_functions"])
            type_defs = self.query.get_type_definitions(type_names)
            for t in type_defs:
                context["types"].append({
                    "name": t.get("name"),
                    "abilities": t.get("abilities", []),
                    "fields": t.get("fields", []),
                    "has_uid": t.get("has_uid", False),
                })

        # 4. 🔥 解析外部依赖 (来自 ~/.move)
        if self.config.get("resolve_external_deps", True) and self.dependency_resolver:
            print(f"[FunctionContextBuilder] 正在解析 {len(all_external_calls)} 个外部调用...")
            for call in sorted(all_external_calls):
                impl = self.dependency_resolver.find_function(call, "")
                if impl:
                    context["external_deps"].append({
                        "call": call,
                        "implementation": impl,
                    })
                    print(f"  ✅ 已解析: {call}")
                else:
                    print(f"  ❌ 未找到: {call}")

        # 5. 生成模块摘要
        context["module_summary"] = self._generate_module_summary(module_name)

        return context

    def _extract_function_code(self, source_code: str, span: Optional[dict]) -> str:
        """从源码中提取函数代码"""
        if not span:
            return ""
        lines = source_code.split("\n")
        start = span.get("start", 1) - 1
        end = span.get("end", len(lines))
        return "\n".join(lines[start:end])

    def _extract_neighbor_code(self, neighbor: dict) -> str:
        """
        从邻居函数的源文件中提取代码

        Args:
            neighbor: 邻居函数节点 (包含 module_path 和 span)

        Returns:
            str: 函数完整代码，失败时返回空字符串
        """
        module_path = neighbor.get("module_path", "")
        span = neighbor.get("span")

        if not module_path or not span:
            return ""

        try:
            # 缓存源文件内容
            if not hasattr(self, "_source_cache"):
                self._source_cache = {}

            if module_path not in self._source_cache:
                if os.path.exists(module_path):
                    with open(module_path, "r", encoding="utf-8") as f:
                        self._source_cache[module_path] = f.read()
                else:
                    return ""

            source_code = self._source_cache[module_path]
            return self._extract_function_code(source_code, span)

        except Exception as e:
            # 静默失败，返回空字符串
            return ""

    def _get_relation(self, target_id: str, neighbor: dict) -> str:
        """判断邻居与目标的关系"""
        if target_id in neighbor.get("called_by", []):
            return "calls_target"
        if target_id in neighbor.get("calls", []):
            return "called_by_target"
        return "indirect"

    def _extract_type_names(self, functions: List[dict]) -> List[str]:
        """从函数签名中提取类型名"""
        type_names = set()
        type_pattern = re.compile(r'(?:&mut\s+|&\s*)?([\w]+)(?:<|>|,|\)|$)')

        for func in functions:
            sig = func.get("signature", "")
            for match in type_pattern.finditer(sig):
                name = match.group(1)
                # 过滤掉基本类型
                if name not in {"u8", "u16", "u32", "u64", "u128", "u256",
                               "bool", "address", "vector", "mut"}:
                    type_names.add(name)

        return list(type_names)

    def _generate_module_summary(self, module_name: str) -> str:
        """生成模块摘要"""
        functions = self.query.get_functions_by_module(module_name)
        if not functions:
            return ""

        public_funcs = [f for f in functions if "public" in f.get("visibility", "")]
        entry_funcs = [f for f in functions if "entry" in f.get("visibility", "")]

        summary_parts = [
            f"模块 {module_name}:",
            f"  - 函数总数: {len(functions)}",
            f"  - 公开函数: {len(public_funcs)}",
            f"  - 入口函数: {len(entry_funcs)}",
        ]

        # 添加高风险函数提示
        high_risk = [f for f in functions if f.get("risk_score", 0) >= 50]
        if high_risk:
            summary_parts.append(f"  - 高风险函数: {', '.join(f['name'] for f in high_risk[:5])}")

        return "\n".join(summary_parts)

    def format_context_prompt(self, context: dict) -> str:
        """将上下文格式化为 prompt 片段"""
        lines = []

        # 模块摘要
        if context.get("module_summary"):
            lines.append("## 模块概览")
            lines.append(context["module_summary"])
            lines.append("")

        # 导入语句
        if context.get("imports"):
            lines.append("## 依赖导入")
            for imp in context["imports"][:10]:  # 最多 10 个
                lines.append(f"use {imp};")
            lines.append("")

        # 类型定义
        if context.get("types"):
            lines.append("## 相关类型定义")
            for t in context["types"]:
                abilities = ", ".join(t.get("abilities", []))
                lines.append(f"struct {t['name']} has {abilities} {{ ... }}")
            lines.append("")

        # 邻居函数 - 🔥 改进：输出完整代码而非仅签名
        if context.get("neighbors"):
            lines.append("## 被调用函数的完整实现 (用于理解逻辑)")
            lines.append("以下是目标函数调用的其他函数的完整代码，请仔细阅读以理解业务逻辑：")
            lines.append("")

            for n in context["neighbors"][:8]:  # 最多 8 个，避免上下文过长
                relation = n.get("relation", "related")
                code = n.get("code", "")

                if code:
                    # 有完整代码时输出
                    lines.append(f"### {n['name']} ({relation})")
                    if n.get("summary"):
                        lines.append(f"// 功能: {n['summary']}")
                    lines.append("```move")
                    lines.append(code)
                    lines.append("```")
                    lines.append("")
                else:
                    # 无代码时仅输出签名
                    lines.append(f"// {n['name']}: {n['signature']}")

            lines.append("")

        # 🔥 外部依赖 - 来自 ~/.move 的库函数实现 (仅供参考理解)
        if context.get("external_deps"):
            lines.append("## 外部库函数实现 (仅供理解，不要在 spec 中调用)")
            lines.append("")
            lines.append("以下是目标函数调用的外部库函数的完整实现。")
            lines.append("")
            lines.append("**⚠️ 重要提示**:")
            lines.append("1. 这些代码仅供你理解计算逻辑，帮助你写出正确的 requires/ensures 约束")
            lines.append("2. **不要在 spec 中调用这些外部函数**，spec 应该只用简单的数学表达式")
            lines.append("3. 例如：看到 `checked_shlw` 检查 `n >= 1 << 192` 会溢出，")
            lines.append("   你应该写 `requires(product < (1 << 192));` 而不是调用任何外部函数")
            lines.append("")

            for dep in context["external_deps"][:10]:  # 最多 10 个
                call = dep.get("call", "")
                impl = dep.get("implementation", "")
                if impl:
                    lines.append(f"### {call}")
                    lines.append("```move")
                    lines.append(impl)
                    lines.append("```")
                    lines.append("")

            lines.append("")

        return "\n".join(lines)


def load_callgraph(path: str) -> Optional[dict]:
    """加载调用图 JSON"""
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_callgraph_for_project(project_root: str, out_path: Optional[str] = None, use_lsp: bool = True) -> dict:
    """为项目构建调用图

    Args:
        project_root: 项目根目录
        out_path: 输出路径，可选
        use_lsp: 是否使用 LSP (move-analyzer)，默认 True
    """
    sources_dir = os.path.join(project_root, "sources")
    if not os.path.exists(sources_dir):
        sources_dir = project_root

    builder = CallGraphBuilder(sources_dir, use_lsp=use_lsp)
    graph = builder.build()

    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(graph, f, indent=2, ensure_ascii=False)

    return graph


# ============================================================================
# CLI 入口
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Sui Move 调用图生成器")
    parser.add_argument("root", nargs="?", default=".", help="项目根目录或源码目录 (默认: 当前目录)")
    parser.add_argument("--out", "-o", help="输出路径，默认 data/callgraph/<project>.json")
    parser.add_argument("--include-types", action="store_true", default=True,
                        help="包含类型定义")
    parser.add_argument("--no-types", action="store_true", help="不包含类型定义")
    parser.add_argument("--no-lsp", action="store_true",
                        help="禁用 LSP (move-analyzer)，使用纯正则解析")
    parser.add_argument("--summary-length", type=int, default=100,
                        help="函数摘要最大长度")
    args = parser.parse_args()

    include_types = args.include_types and not args.no_types
    use_lsp = not args.no_lsp

    print(f"[INFO] 解析目录: {args.root}")
    print(f"[INFO] 模式: {'LSP (move-analyzer)' if use_lsp else '正则解析'}")
    builder = CallGraphBuilder(args.root, include_types, args.summary_length, use_lsp=use_lsp)

    try:
        graph = builder.build()
    except Exception as e:
        print(f"[ERROR] 构建失败: {e}")
        return 1

    # 确定输出路径
    out_path = args.out
    if not out_path:
        os.makedirs(CALLGRAPH_DIR, exist_ok=True)
        out_path = os.path.join(CALLGRAPH_DIR, f"{graph['meta']['project']}.json")

    # 写入文件
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2, ensure_ascii=False)

    print(f"[INFO] 调用图已生成: {out_path}")
    mode = graph['meta'].get('mode', 'unknown')
    print(f"[INFO] 解析模式: {mode}")
    print(f"[INFO] 统计: {graph['meta']['total_functions']} 个函数, "
          f"{graph['meta']['total_modules']} 个模块, "
          f"{graph['meta'].get('total_types', 0)} 个类型, "
          f"{graph['meta'].get('total_edges', 0)} 条边")

    return 0


if __name__ == "__main__":
    exit(main())
