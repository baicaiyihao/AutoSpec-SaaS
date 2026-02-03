"""
代码上下文理解模块

包含:
- callgraph: 调用图构建与分析
- dependency_resolver: 外部依赖解析
- project_indexer: 项目索引 (整合 callgraph + dependency)

用于安全审计 - 提供漏洞传播路径分析
"""

from .callgraph import (
    CallGraphBuilder,
    CallGraphQuery,
    FunctionContextBuilder,
    FunctionNode,
    RiskIndicators,
)
from .dependency_resolver import DependencyResolver, Dependency
from .project_indexer import MoveProjectIndexer, ModuleInfo, CodeChunk

__all__ = [
    # Callgraph
    "CallGraphBuilder",
    "CallGraphQuery",
    "FunctionContextBuilder",
    "FunctionNode",
    "RiskIndicators",
    # Dependency
    "DependencyResolver",
    "Dependency",
    # Project Indexer
    "MoveProjectIndexer",
    "ModuleInfo",
    "CodeChunk",
]
