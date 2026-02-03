"""
Diff 工具函数 - 统一的代码差异生成
提取自 council.py 和 learner.py 的重复逻辑
"""
import difflib
from typing import Optional


def generate_diff(
    old_code: str,
    new_code: str,
    old_label: str = "before",
    new_label: str = "after",
    context_lines: int = 3,
    max_length: Optional[int] = 5000,
    no_change_message: str = "No significant changes detected."
) -> str:
    """
    生成两段代码的 unified diff

    Args:
        old_code: 旧版本代码
        new_code: 新版本代码
        old_label: 旧版本标签 (显示在 diff 头部)
        new_label: 新版本标签 (显示在 diff 头部)
        context_lines: 上下文行数 (默认 3)
        max_length: 最大输出长度 (None 表示不限制)
        no_change_message: 无变化时的返回消息

    Returns:
        str: unified diff 格式的差异文本
    """
    if not old_code or not new_code:
        return no_change_message

    old_lines = old_code.splitlines(keepends=True)
    new_lines = new_code.splitlines(keepends=True)

    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=old_label,
        tofile=new_label,
        n=context_lines,
    )

    diff_text = "".join(diff)

    if not diff_text.strip():
        return no_change_message

    # 截断过长的 diff
    if max_length and len(diff_text) > max_length:
        diff_text = diff_text[:max_length] + "\n... (Diff truncated)"

    return diff_text
