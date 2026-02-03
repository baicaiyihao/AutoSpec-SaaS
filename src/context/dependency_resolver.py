"""
Dependency Resolver for Move Projects

This module resolves external dependencies for Move projects by:
1. Parsing Move.toml to find dependencies
2. Mapping package names to ~/.move cached directories
3. Extracting external function implementations for AI context
"""

import re
import os
import tomllib
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class Dependency:
    """Represents a Move package dependency."""
    name: str
    git_url: Optional[str] = None
    rev: Optional[str] = None
    local_path: Optional[str] = None  # Resolved path in ~/.move


class DependencyResolver:
    """Resolves Move project dependencies from ~/.move cache."""

    # Sui 内置依赖路径 (MoveStdlib, Sui, SuiSystem, Bridge 等)
    SUI_BUILTIN_CACHE_PATTERNS = [
        "https___github_com_MystenLabs_sui_git_mainnet",
        "https___github_com_MystenLabs_sui_git_mainnet-*",
        "https___github_com_MystenLabs_sui_git_testnet*",
        "https___github_com_MystenLabs_sui_git_devnet*",
    ]

    def __init__(self, project_root: str):
        """
        Initialize resolver for a Move project.

        Args:
            project_root: Path to the Move project root (containing Move.toml)
        """
        self.project_root = Path(project_root)
        self.move_cache = Path.home() / ".move"
        self.dependencies: dict[str, Dependency] = {}
        self.package_to_module: dict[str, str] = {}  # Package name -> module prefix

        self._add_sui_builtin_dependencies()  # 先添加内置依赖
        self._parse_move_toml()
        self._resolve_dependencies()

    def _add_sui_builtin_dependencies(self):
        """
        添加 Sui 内置依赖 (MoveStdlib, Sui, SuiSystem, Bridge 等)

        这些依赖包含标准库函数如:
        - sui::balance (value, join, split, destroy_zero)
        - sui::object (id, new, delete)
        - sui::coin (Coin, value, split, join)
        - sui::clock (timestamp_ms)
        - sui::event (emit)
        - std::vector (empty, push_back, pop_back, length, borrow)
        - std::string (from_ascii, utf8)
        """
        if not self.move_cache.exists():
            print(f"[DependencyResolver] Warning: ~/.move not found")
            return

        # 查找 Sui 内置缓存目录
        sui_cache_path = None
        for pattern in self.SUI_BUILTIN_CACHE_PATTERNS:
            matches = list(self.move_cache.glob(pattern))
            if matches:
                # 优先选择 mainnet，然后选最新的
                for match in sorted(matches, reverse=True):
                    if match.is_dir():
                        sui_cache_path = match
                        break
            if sui_cache_path:
                break

        if not sui_cache_path:
            print(f"[DependencyResolver] Warning: Sui builtin cache not found in ~/.move")
            return

        print(f"[DependencyResolver] Found Sui cache: {sui_cache_path}")

        # 添加内置依赖 (实际目录名, 显示名, 模块前缀)
        builtin_packages = [
            ("sui-framework", "Sui", "sui"),           # sui:: 模块 (balance, coin, object, clock, etc.)
            ("move-stdlib", "MoveStdlib", "std"),      # std:: 模块 (vector, string, option, etc.)
            ("sui-system", "SuiSystem", "sui_system"), # sui_system:: 模块
            ("bridge", "Bridge", "bridge"),            # bridge:: 模块
        ]

        # 多种可能的路径模式
        search_patterns = [
            "crates/sui-framework/packages/{dir_name}",
            "crates/sui-framework/packages/sui-framework",  # 有时 sui-framework 包含所有模块
            "packages/{dir_name}",
            "{dir_name}",
        ]

        for dir_name, display_name, module_prefix in builtin_packages:
            pkg_path = None

            # 尝试多种路径模式
            for pattern in search_patterns:
                test_path = sui_cache_path / pattern.format(dir_name=dir_name)
                if test_path.exists() and test_path.is_dir():
                    # 检查是否有 sources 目录或直接有 .move 文件
                    if (test_path / "sources").exists() or list(test_path.glob("*.move")):
                        pkg_path = test_path
                        break

            # 如果没找到，用 rglob 搜索
            if not pkg_path:
                pkg_paths = list(sui_cache_path.rglob(f"**/{dir_name}/sources"))
                if pkg_paths:
                    pkg_path = pkg_paths[0].parent  # 取 sources 的父目录

            if pkg_path and pkg_path.is_dir():
                self.dependencies[display_name] = Dependency(
                    name=display_name,
                    local_path=str(pkg_path),
                )
                self.package_to_module[module_prefix] = display_name
                print(f"[DependencyResolver] Added builtin {display_name} -> {pkg_path}")

    def _parse_move_toml(self):
        """Parse Move.toml to extract dependencies."""
        move_toml = self.project_root / "Move.toml"
        if not move_toml.exists():
            print(f"[DependencyResolver] Warning: Move.toml not found at {move_toml}")
            return

        with open(move_toml, "rb") as f:
            config = tomllib.load(f)

        deps = config.get("dependencies", {})
        for name, info in deps.items():
            if isinstance(info, dict):
                self.dependencies[name] = Dependency(
                    name=name,
                    git_url=info.get("git"),
                    rev=info.get("rev"),
                )
            elif isinstance(info, str):
                # Local path dependency
                self.dependencies[name] = Dependency(
                    name=name,
                    local_path=info,
                )

        # Build package to module mapping from addresses
        addresses = config.get("addresses", {})
        # This helps map from address to module name
        for addr_name, addr_value in addresses.items():
            self.package_to_module[addr_name] = addr_name

    def _git_url_to_cache_path(self, git_url: str, rev: str) -> str:
        """
        Convert git URL + rev to ~/.move cache directory name.

        Example:
            git_url: https://github.com/CetusProtocol/integer-mate.git
            rev: mainnet-v1.3.0
            Result: https___github_com_CetusProtocol_integer-mate_git_mainnet-v1.3.0
        """
        # Remove .git suffix and protocol
        url = git_url.rstrip(".git")

        # Replace special characters
        cache_name = url.replace("://", "___").replace("/", "_").replace(".", "_")

        # Append revision
        cache_name = f"{cache_name}_git_{rev}"

        return cache_name

    def _resolve_dependencies(self):
        """Resolve all dependencies to their ~/.move paths."""
        if not self.move_cache.exists():
            print(f"[DependencyResolver] Warning: ~/.move not found")
            return

        for name, dep in self.dependencies.items():
            if dep.git_url and dep.rev:
                cache_name = self._git_url_to_cache_path(dep.git_url, dep.rev)
                cache_path = self.move_cache / cache_name

                if cache_path.exists():
                    dep.local_path = str(cache_path)
                    print(f"[DependencyResolver] Resolved {name} -> {cache_path}")
                else:
                    # Try fuzzy matching
                    possible_matches = list(self.move_cache.glob(f"*{dep.rev}*"))
                    for match in possible_matches:
                        # Check if package name is in the path
                        package_hint = dep.git_url.split("/")[-1].replace(".git", "")
                        if package_hint.lower() in str(match).lower():
                            dep.local_path = str(match)
                            print(f"[DependencyResolver] Fuzzy resolved {name} -> {match}")
                            break

                    if not dep.local_path:
                        print(f"[DependencyResolver] Warning: Cache not found for {name}: {cache_name}")

    def find_function(self, module_path: str, function_name: str) -> Optional[str]:
        """
        Find an external function implementation.

        Args:
            module_path: Module path like 'coin::value', 'sui::coin::split', or 'balance::join'
            function_name: Function name (optional, extracted from module_path if includes ::)

        Returns:
            Function implementation code or None
        """
        if "::" in module_path:
            parts = module_path.split("::")
            # 🔥 修复: 支持多种路径格式
            # - "coin::value" → module_name="coin", function_name="value"
            # - "sui::coin::split" → module_name="coin", function_name="split"
            if len(parts) >= 3:
                # 三段式: package::module::function (如 sui::coin::split)
                module_name = parts[-2]  # coin
                function_name = parts[-1]  # split
            else:
                # 两段式: module::function (如 coin::value)
                module_name = parts[0]  # coin
                function_name = parts[-1]  # value
        else:
            module_name = module_path

        # Search in all dependency paths
        for dep_name, dep in self.dependencies.items():
            if not dep.local_path:
                continue

            dep_path = Path(dep.local_path)

            # Search for module file
            for move_file in dep_path.rglob("*.move"):
                # 优化：先检查文件名是否匹配模块名
                file_stem = move_file.stem  # e.g., "coin", "balance", "tx_context"
                if file_stem != module_name and module_name not in file_stem:
                    continue

                try:
                    with open(move_file, "r", encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    continue

                # Check if this module contains the function
                # 支持多种模块声明格式:
                # - module sui::coin { ... }
                # - module 0x2::coin { ... }
                # - module coin { ... }
                module_patterns = [
                    f"module sui::{module_name}",
                    f"module std::{module_name}",
                    f"module 0x1::{module_name}",
                    f"module 0x2::{module_name}",
                    f"::{module_name} {{",
                    f"module {module_name} {{",
                ]

                if any(pattern in content for pattern in module_patterns):
                    # Extract function
                    func_code = self._extract_function(content, function_name)
                    if func_code:
                        return func_code

        return None

    def _extract_function(self, content: str, function_name: str) -> Optional[str]:
        """Extract a function implementation from Move source code."""
        # Pattern to match function definition
        # Handles: public fun, fun, public(friend) fun, etc.
        pattern = rf'(?:public(?:\([^)]+\))?\s+)?fun\s+{re.escape(function_name)}\s*[(<]'

        match = re.search(pattern, content)
        if not match:
            return None

        start = match.start()

        # Find the end of the function by matching braces
        brace_count = 0
        in_function = False
        end = start

        for i, char in enumerate(content[start:], start=start):
            if char == '{':
                brace_count += 1
                in_function = True
            elif char == '}':
                brace_count -= 1
                if in_function and brace_count == 0:
                    end = i + 1
                    break

        if end > start:
            return content[start:end].strip()

        return None

    def get_external_functions_context(self, function_calls: list[str]) -> str:
        """
        Get context for multiple external function calls.

        Args:
            function_calls: List of function calls like ['math_u256::checked_shlw', 'full_math_u128::full_mul']

        Returns:
            Formatted context string with all found implementations
        """
        context_parts = []

        for call in function_calls:
            impl = self.find_function(call, "")
            if impl:
                context_parts.append(f"// {call}\n{impl}")

        if context_parts:
            header = "// === External Dependencies (from ~/.move) ===\n"
            return header + "\n\n".join(context_parts)

        return ""

    def resolve_all_external_calls(self, source_code: str) -> dict[str, str]:
        """
        Find and resolve all external function calls in source code.

        Args:
            source_code: Move source code to analyze

        Returns:
            Dict mapping function call to implementation
        """
        results = {}

        # Find use statements
        use_pattern = r'use\s+([\w_]+)::([\w_]+)(?:::\{([^}]+)\})?;'
        for match in re.finditer(use_pattern, source_code):
            package = match.group(1)
            module = match.group(2)
            imports = match.group(3)

            if imports:
                # Specific imports: use pkg::module::{func1, func2};
                for func in imports.split(","):
                    func = func.strip()
                    if func and not func.startswith("Self"):
                        impl = self.find_function(f"{module}::{func}", func)
                        if impl:
                            results[f"{package}::{module}::{func}"] = impl
            else:
                # Module-level import: use pkg::module;
                # Look for usages in code
                usage_pattern = rf'{module}::(\w+)'
                for usage in re.finditer(usage_pattern, source_code):
                    func_name = usage.group(1)
                    impl = self.find_function(f"{module}::{func_name}", func_name)
                    if impl:
                        results[f"{package}::{module}::{func_name}"] = impl

        return results


def test_resolver():
    """Test the dependency resolver."""
    project_root = "/Users/stom698/git/AutoMove/AutoSpec/cetus-contracts/packages/cetus_clmm"
    resolver = DependencyResolver(project_root)

    # Test finding specific functions
    test_calls = [
        "math_u256::checked_shlw",
        "full_math_u128::full_mul",
        "math_u256::div_round",
    ]

    for call in test_calls:
        impl = resolver.find_function(call, "")
        if impl:
            print(f"\n=== {call} ===")
            print(impl)
        else:
            print(f"\n=== {call} === NOT FOUND")


if __name__ == "__main__":
    test_resolver()
