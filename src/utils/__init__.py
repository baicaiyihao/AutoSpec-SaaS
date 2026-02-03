# AutoSpec 共享工具模块
# 提取自各模块的重复代码，实现复用

from src.utils.diff_utils import generate_diff
from src.utils.json_parser import (
    safe_parse_json,
    extract_json_from_text,
    robust_parse_json,
    extract_fields_regex,
    WHITEHAT_FIELD_PATTERNS,
)
from src.utils.code_extractor import extract_code_block, clean_move_code
from src.utils.cache import AnalysisCache, analysis_cache, cache_key_for_code

__all__ = [
    "generate_diff",
    "safe_parse_json",
    "extract_json_from_text",
    "robust_parse_json",
    "extract_fields_regex",
    "WHITEHAT_FIELD_PATTERNS",
    "extract_code_block",
    "clean_move_code",
    "AnalysisCache",
    "analysis_cache",
    "cache_key_for_code",
]
