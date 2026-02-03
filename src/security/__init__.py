"""
安全审计模块

包含:
- pattern_scan: 漏洞模式扫描 (规则匹配 + 向量搜索)
- exploit_analyzer: 漏洞利用链分析
- exclusion_rules: 排除规则 (v2.5.0)
"""

from .pattern_scan import SecurityScanner
from .exploit_analyzer import ExploitChainAnalyzer
from .exclusion_rules import (
    apply_exclusion_rules,
    ExclusionRule,
    EXCLUSION_RULES,
    get_rule_by_id,
    get_all_rule_ids,
    print_rules_summary,
)

__all__ = [
    "SecurityScanner",
    "ExploitChainAnalyzer",
    # 排除规则 (v2.5.0)
    "apply_exclusion_rules",
    "ExclusionRule",
    "EXCLUSION_RULES",
    "get_rule_by_id",
    "get_all_rule_ids",
    "print_rules_summary",
]
