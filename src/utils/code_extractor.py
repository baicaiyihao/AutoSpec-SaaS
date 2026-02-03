"""
代码提取工具 - 从 LLM 输出中提取代码块
提取自 generator.py, council.py 的重复逻辑
"""
import re
from typing import Optional, List


def extract_code_block(
    text: str,
    language: str = "move",
    fallback_languages: Optional[List[str]] = None
) -> Optional[str]:
    """
    从文本中提取指定语言的代码块

    Args:
        text: 包含代码块的文本
        language: 目标语言 (默认 move)
        fallback_languages: 备选语言列表 (如 ["rust", ""])

    Returns:
        str: 提取的代码，未找到时返回 None
    """
    if not text:
        return None

    if fallback_languages is None:
        fallback_languages = ["rust", ""]  # 空字符串匹配无语言标记的代码块

    # 尝试目标语言
    all_languages = [language] + fallback_languages

    for lang in all_languages:
        if lang:
            pattern = rf"```{lang}\s*\n(.*?)\n\s*```"
        else:
            pattern = r"```\s*\n(.*?)\n\s*```"

        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return None


def clean_move_code(text: str) -> str:
    """
    清理 Move 代码，移除 markdown 标记并验证基本结构

    Args:
        text: 原始文本 (可能包含 markdown 代码块)

    Returns:
        str: 清理后的 Move 代码
    """
    if not text:
        return ""

    # 尝试提取代码块
    extracted = extract_code_block(text, language="move")
    if extracted:
        return extracted

    # 没有代码块，尝试直接清理
    cleaned = text.replace("```move", "").replace("```rust", "").replace("```", "")
    cleaned = cleaned.strip()

    return cleaned


def extract_snippet_around_line(
    code: str,
    target_line: int,
    context_lines: int = 5
) -> str:
    """
    提取指定行周围的代码片段

    Args:
        code: 完整代码
        target_line: 目标行号 (1-indexed)
        context_lines: 上下文行数

    Returns:
        str: 代码片段
    """
    if not code:
        return ""

    lines = code.splitlines()
    total_lines = len(lines)

    if target_line < 1 or target_line > total_lines:
        # 无效行号，返回前 N 行
        return "\n".join(lines[:context_lines * 2])

    start = max(0, target_line - context_lines - 1)
    end = min(total_lines, target_line + context_lines)

    snippet_lines = []
    for i in range(start, end):
        line_num = i + 1
        prefix = "→ " if line_num == target_line else "  "
        snippet_lines.append(f"{prefix}{line_num:4d} | {lines[i]}")

    return "\n".join(snippet_lines)


def extract_snippet_by_keyword(
    code: str,
    keyword: str,
    context_lines: int = 5,
    max_snippets: int = 3
) -> str:
    """
    根据关键字提取代码片段

    Args:
        code: 完整代码
        keyword: 搜索关键字
        context_lines: 上下文行数
        max_snippets: 最多返回的片段数

    Returns:
        str: 包含关键字的代码片段
    """
    if not code or not keyword:
        return ""

    lines = code.splitlines()
    snippets = []
    used_lines = set()

    for i, line in enumerate(lines):
        if keyword.lower() in line.lower():
            if i in used_lines:
                continue

            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)

            snippet_lines = []
            for j in range(start, end):
                used_lines.add(j)
                line_num = j + 1
                prefix = "→ " if j == i else "  "
                snippet_lines.append(f"{prefix}{line_num:4d} | {lines[j]}")

            snippets.append("\n".join(snippet_lines))

            if len(snippets) >= max_snippets:
                break

    return "\n---\n".join(snippets) if snippets else ""
