"""
JSON 解析工具 - 处理 LLM 输出中的 JSON 提取和修复

提供 10 种修复策略，处理 LLM 返回的各种格式问题：
1. 直接解析
2. 修复常见语法问题（尾逗号、注释、缺逗号、Move代码字符串）
3. 处理多行字符串中的换行符
4. 单引号转双引号
5. 逐行修复
6. 部分提取（findings 数组）
7. 截断 JSON 补全（补全缺失括号）
8. 激进截断修复（处理未闭合字符串）
9. WhiteHat 关键字段正则提取
10. Verifier 关键字段正则提取 (v2.5.8)

预处理：
- 移除控制字符（\x00 等）
- 移除思考标签（<thinking> 等）
"""
import json
import re
from typing import Any, Dict, List, Optional


def extract_json_from_text(text: str) -> Optional[str]:
    """
    从文本中提取 JSON 字符串 (支持 markdown 代码块)

    尝试顺序:
    1. 直接解析整个文本
    2. 提取 ```json ... ``` 代码块
    3. 提取 { ... } 匹配

    Args:
        text: 包含 JSON 的文本

    Returns:
        str: 提取出的 JSON 字符串，无法提取时返回 None
    """
    if not text:
        return None

    text = text.strip()

    # 方法 1: 直接尝试解析 (如果整个文本就是 JSON)
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        pass

    # 方法 2: 提取 markdown 代码块
    json_block_pattern = r'```(?:json)?\s*\n?(.*?)\n?```'
    match = re.search(json_block_pattern, text, re.DOTALL)
    if match:
        candidate = match.group(1).strip()
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            pass

    # 方法 3: 提取 { ... } 或 [ ... ] 匹配
    # 使用贪婪匹配找最外层括号
    brace_pattern = r'(\{[\s\S]*\}|\[[\s\S]*\])'
    match = re.search(brace_pattern, text)
    if match:
        candidate = match.group(1).strip()
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            pass

    return None


def safe_parse_json(
    text: str,
    default: Optional[Dict[str, Any]] = None,
    raise_on_error: bool = False
) -> Dict[str, Any]:
    """
    安全地解析 JSON，支持多种格式

    Args:
        text: 包含 JSON 的文本
        default: 解析失败时返回的默认值 (默认为空字典)
        raise_on_error: 是否在解析失败时抛出异常

    Returns:
        Dict: 解析结果或默认值

    Raises:
        json.JSONDecodeError: 当 raise_on_error=True 且解析失败时
    """
    if default is None:
        default = {}

    json_str = extract_json_from_text(text)

    if json_str is None:
        if raise_on_error:
            raise json.JSONDecodeError("No valid JSON found in text", text, 0)
        return default

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        if raise_on_error:
            raise e
        return default


def clean_json_string(text: str) -> str:
    """
    清理可能包含 markdown 标记的 JSON 字符串

    Args:
        text: 原始文本

    Returns:
        str: 清理后的文本
    """
    if not text:
        return ""

    # 移除 markdown 代码块标记
    cleaned = text.replace("```json", "").replace("```", "").strip()
    return cleaned


# ============================================================================
# 高级 JSON 修复（10 种策略）
# ============================================================================

def robust_parse_json(
    response: str,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    健壮地解析 LLM 响应中的 JSON（10 种修复策略）

    适用于处理 LLM 返回的包含代码、多行字符串等复杂 JSON。

    Args:
        response: LLM 响应文本
        verbose: 是否打印调试信息

    Returns:
        解析后的字典，失败时返回 {"error": "...", "raw_response": "..."}
    """
    # 0. 预处理：移除控制字符（保留 \n \r \t）
    response = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', response)

    # 1. 预处理：移除思考标签
    cleaned = re.sub(r'<thinking>.*?</thinking>', '', response, flags=re.DOTALL)
    cleaned = re.sub(r'<reasoning>.*?</reasoning>', '', cleaned, flags=re.DOTALL)
    cleaned = re.sub(r'<analysis>.*?</analysis>', '', cleaned, flags=re.DOTALL)

    # 处理未闭合的 <thinking> 标签
    if '<thinking>' in cleaned:
        json_start = cleaned.find('{')
        code_block_start = cleaned.find('```')
        if code_block_start != -1 and (json_start == -1 or code_block_start < json_start):
            json_start = code_block_start
        if json_start != -1:
            cleaned = cleaned[json_start:]
        else:
            cleaned = re.sub(r'<thinking>.*', '', cleaned, flags=re.DOTALL)

    cleaned = cleaned.strip()

    # 2. 提取 JSON 字符串（处理各种 markdown 代码块格式问题）
    json_str = None

    # 尝试1: 完整的 ```json ... ``` 代码块
    json_match = re.search(r'```(?:json)?\s*\n?(\{[\s\S]*?\})\s*\n?```', cleaned, re.DOTALL)
    if json_match:
        json_str = json_match.group(1).strip()

    # 尝试2: 只有开头 ```json 没有结尾 ``` 的情况（LLM 常见问题）
    if not json_str:
        # 匹配 ```json 后面的内容直到最后一个 }
        json_match = re.search(r'```(?:json)?\s*\n?(\{[\s\S]*\})', cleaned, re.DOTALL)
        if json_match:
            json_str = json_match.group(1).strip()

    # 尝试3: 移除所有 ``` 标记后直接找 JSON
    if not json_str:
        # 移除 markdown 代码块标记
        no_markdown = re.sub(r'```(?:json)?', '', cleaned)
        brace_match = re.search(r'\{[\s\S]*\}', no_markdown, re.DOTALL)
        if brace_match:
            json_str = brace_match.group(0).strip()

    # 尝试4: 直接在原文中找 { ... }
    if not json_str:
        brace_match = re.search(r'\{[\s\S]*\}', cleaned, re.DOTALL)
        if brace_match:
            json_str = brace_match.group(0).strip()

    # 如果还是没找到，使用原文
    if not json_str:
        json_str = cleaned

    # 3. 尝试 10 种策略解析
    return _try_parse_json_strategies(json_str, response, verbose)


def _try_parse_json_strategies(
    json_str: str,
    original_response: str,
    verbose: bool = False
) -> Dict[str, Any]:
    """尝试 10 种策略解析 JSON"""

    # 策略1: 直接解析
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        pass

    # 策略2: 修复常见语法问题
    fixed = _fix_json_syntax(json_str)
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass

    # 策略3: 处理字符串值中的实际换行符（LLM返回代码时常见）
    try:
        def escape_newlines_in_strings(m):
            key = m.group(1)
            value = m.group(2)
            escaped_value = value.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
            return f'"{key}": "{escaped_value}"'

        multiline_fixed = re.sub(
            r'"([^"]+)"\s*:\s*"((?:[^"\\]|\\.)*?)"(?=\s*[,}\]])',
            escape_newlines_in_strings,
            fixed,
            flags=re.DOTALL
        )
        return json.loads(multiline_fixed)
    except (json.JSONDecodeError, Exception):
        pass

    # 策略4: 单引号转双引号
    try:
        relaxed = re.sub(r"(?<![\\])'", '"', json_str)
        return json.loads(relaxed)
    except json.JSONDecodeError:
        pass

    # 策略5: 逐行修复
    try:
        lines = json_str.split('\n')
        fixed_lines = []
        for i, line in enumerate(lines):
            line = line.rstrip()
            if i < len(lines) - 1:
                next_line = lines[i + 1].strip()
                if next_line.startswith('}') or next_line.startswith(']'):
                    line = line.rstrip(',')
            if fixed_lines and not line.strip().startswith(('}', ']', '')):
                prev = fixed_lines[-1].rstrip()
                if prev and not prev.endswith(('{', '[', ',', ':')):
                    if re.match(r'\s*"[^"]+"\s*:', line):
                        fixed_lines[-1] = prev + ','
            fixed_lines.append(line)
        fixed_json = '\n'.join(fixed_lines)
        return json.loads(fixed_json)
    except json.JSONDecodeError:
        pass

    # 策略6: 提取部分有效的 JSON（如 findings 数组）
    try:
        findings_match = re.search(r'"findings"\s*:\s*\[(.*?)\]', json_str, re.DOTALL)
        if findings_match:
            findings_str = '[' + findings_match.group(1) + ']'
            findings = _parse_json_array_lenient(findings_str)
            if findings:
                return {
                    "findings": findings,
                    "analysis_summary": {"partial_parse": True},
                    "risk_areas": [],
                    "safe_patterns": []
                }
    except Exception:
        pass

    # 策略7: 修复截断的 JSON（补全缺失的括号）
    try:
        truncated = json_str.rstrip()
        open_braces = truncated.count('{') - truncated.count('}')
        open_brackets = truncated.count('[') - truncated.count(']')

        if open_braces > 0 or open_brackets > 0:
            last_colon = truncated.rfind('":')
            if last_colon != -1:
                after_colon = truncated[last_colon+2:].strip()
                if after_colon.startswith('"') and after_colon.count('"') % 2 == 1:
                    key_start = truncated.rfind('"', 0, last_colon)
                    if key_start > 0:
                        truncated = truncated[:key_start].rstrip().rstrip(',')

            truncated += ']' * open_brackets + '}' * open_braces
            result = json.loads(truncated)
            result["_truncated"] = True
            return result
    except json.JSONDecodeError:
        pass

    # 策略8: 🔥 激进截断修复（处理未闭合的字符串值）
    try:
        truncated = json_str.rstrip()

        # 检查是否有未闭合的字符串（奇数个引号）
        quote_count = truncated.count('"') - truncated.count('\\"')
        if quote_count % 2 == 1:
            # 找到最后一个未闭合字符串的开始位置
            # 从后往前找最后一个 ": " 后面的引号
            last_value_start = truncated.rfind('": "')
            if last_value_start != -1:
                # 截断这个未闭合的字段，闭合字符串
                value_start = last_value_start + 4  # 跳过 ": "
                # 找到这个键值对开始的位置
                key_start = truncated.rfind('"', 0, last_value_start)
                if key_start > 0:
                    # 截断到这个字段之前
                    truncated = truncated[:key_start].rstrip().rstrip(',')

        # 补全括号
        open_braces = truncated.count('{') - truncated.count('}')
        open_brackets = truncated.count('[') - truncated.count(']')
        truncated += ']' * max(0, open_brackets) + '}' * max(0, open_braces)

        if truncated.strip():
            result = json.loads(truncated)
            result["_truncated"] = True
            return result
    except json.JSONDecodeError:
        pass

    # 策略9: 🔥 最后兜底 - 只提取已知的关键字段
    try:
        # 尝试提取 is_exploitable 等关键字段
        result = {}

        # is_exploitable
        is_exp = re.search(r'"is_exploitable"\s*:\s*(true|false)', json_str, re.IGNORECASE)
        if is_exp:
            result["is_exploitable"] = is_exp.group(1).lower() == "true"

        # confidence
        conf = re.search(r'"confidence"\s*:\s*"?([^",}\]]+)"?', json_str)
        if conf:
            result["confidence"] = conf.group(1).strip().strip('"')

        # exploitability_score
        score = re.search(r'"exploitability_score"\s*:\s*(\d+)', json_str)
        if score:
            result["exploitability_score"] = int(score.group(1))

        # vulnerability_summary (截取前500字符)
        summary = re.search(r'"vulnerability_summary"\s*:\s*"([^"]{0,500})', json_str)
        if summary:
            result["vulnerability_summary"] = summary.group(1)

        if result:
            result["_partial_extract"] = True
            return result
    except Exception:
        pass

    # 策略10: 🔥 v2.5.8 Verifier 关键字段提取
    try:
        result = {}

        # conclusion (confirmed/false_positive/needs_review)
        conclusion = re.search(r'"conclusion"\s*:\s*"?(confirmed|false_positive|needs_review)"?', json_str, re.IGNORECASE)
        if conclusion:
            result["conclusion"] = conclusion.group(1).lower()

        # final_severity
        severity = re.search(r'"final_severity"\s*:\s*"?(critical|high|medium|low|none)"?', json_str, re.IGNORECASE)
        if severity:
            result["final_severity"] = severity.group(1).lower()

        # confidence (数字)
        conf = re.search(r'"confidence"\s*:\s*"?(\d+)"?', json_str)
        if conf:
            result["confidence"] = int(conf.group(1))

        if result:
            result["_partial_extract"] = True
            return result
    except Exception:
        pass

    # 所有策略失败
    if verbose:
        print(f"[JsonParser] 10 种策略均失败")
        print(f"原始响应前500字符: {original_response[:500]}...")
    return {"error": "JSON parse failed", "raw_response": original_response}


def _fix_json_syntax(json_str: str) -> str:
    """修复常见的 JSON 语法错误"""
    fixed = json_str

    # 1. 移除 JavaScript 风格的注释
    fixed = re.sub(r'//.*?$', '', fixed, flags=re.MULTILINE)
    fixed = re.sub(r'/\*.*?\*/', '', fixed, flags=re.DOTALL)

    # 2. 修复尾逗号
    fixed = re.sub(r',\s*}', '}', fixed)
    fixed = re.sub(r',\s*]', ']', fixed)

    # 3. 修复缺少逗号：}" 或 ]" 后面跟着 "key":
    fixed = re.sub(r'([\}\]])(\s*)"', r'\1,\2"', fixed)

    # 4. 修复字符串值后缺少逗号
    fixed = re.sub(r'"\s*\n(\s*)"([^"]+)":', r'",\n\1"\2":', fixed)

    # 5. 修复数字/布尔值后缺少逗号
    fixed = re.sub(r'(\d)\s*\n(\s*)"', r'\1,\n\2"', fixed)
    fixed = re.sub(r'(true|false|null)\s*\n(\s*)"', r'\1,\n\2"', fixed)

    # 6. 修复 ][ 和 }{ 之间缺少逗号
    fixed = re.sub(r'\]\s*\[', '],[', fixed)
    fixed = re.sub(r'\}\s*\{', '},{', fixed)

    # 7. 修复 Move 代码中的字符串字面量
    # b\"...\") -> b\"...\")
    fixed = re.sub(r'(b\\"[^"\\]*)"\)', r'\1\\")', fixed)
    fixed = re.sub(r'(\\"[^"\\]*)"\);', r'\1\\");', fixed)
    fixed = re.sub(r'(\\"[^"\\]*)"\}', r'\1\\"}', fixed)

    # 8. 修复代码字段中的未转义引号
    def fix_code_field(match):
        field_name = match.group(1)
        content = match.group(2)
        # 修复 b"..." 和 x"..." 字符串
        content = re.sub(r'b"([^"]*)"', r'b\\"\\1\\"', content)
        content = re.sub(r'x"([^"]*)"', r'x\\"\\1\\"', content)
        content = re.sub(r'(?<!\\)"([^"\\]{1,50})"(?=[,);])', r'\\"\\1\\"', content)
        return f'"{field_name}": "{content}"'

    fixed = re.sub(
        r'"(poc_code|exploit_module_code|exploit_code|attack_code)"\s*:\s*"((?:[^"\\]|\\.)*)(?=")',
        fix_code_field,
        fixed,
        flags=re.DOTALL
    )

    # 9. 修复 Move 特有模式
    fixed = re.sub(r'assert!\(([^)]*)"([^"]*)"', r'assert!(\\1\\"\\2\\"', fixed)
    fixed = re.sub(r'&b"([^"]*)"', r'&b\\"\\1\\"', fixed)

    # 10. 🔥 v2.5.16: 修复多余的闭合括号 (LLM 常见问题)
    # 例如: {...}} -> {...}
    # 计算括号平衡，移除多余的 } 或 ]
    open_braces = fixed.count('{')
    close_braces = fixed.count('}')
    if close_braces > open_braces:
        # 从末尾移除多余的 }
        excess = close_braces - open_braces
        for _ in range(excess):
            last_brace = fixed.rfind('}')
            if last_brace > 0:
                # 检查是否是连续的 }}
                if fixed[last_brace-1:last_brace+1] == '}}':
                    fixed = fixed[:last_brace] + fixed[last_brace+1:]
                else:
                    # 只移除最后一个
                    fixed = fixed[:last_brace] + fixed[last_brace+1:]

    open_brackets = fixed.count('[')
    close_brackets = fixed.count(']')
    if close_brackets > open_brackets:
        excess = close_brackets - open_brackets
        for _ in range(excess):
            last_bracket = fixed.rfind(']')
            if last_bracket > 0:
                fixed = fixed[:last_bracket] + fixed[last_bracket+1:]

    return fixed


def _parse_json_array_lenient(array_str: str) -> List[Dict[str, Any]]:
    """宽松地解析 JSON 数组，尽可能提取有效元素"""
    results = []

    # 尝试匹配每个 {...} 对象
    obj_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    for match in re.finditer(obj_pattern, array_str):
        try:
            obj = json.loads(match.group(0))
            results.append(obj)
        except json.JSONDecodeError:
            # 尝试修复后解析
            try:
                fixed = _fix_json_syntax(match.group(0))
                obj = json.loads(fixed)
                results.append(obj)
            except json.JSONDecodeError:
                pass

    return results


# ============================================================================
# 字段提取（最后兜底）
# ============================================================================

def extract_fields_regex(
    text: str,
    field_patterns: Dict[str, str]
) -> Dict[str, Any]:
    r"""
    使用正则表达式直接提取字段（当 JSON 解析完全失败时的兜底）

    Args:
        text: 原始文本
        field_patterns: 字段名到正则模式的映射
            例如: {"is_exploitable": r'"is_exploitable"\s*:\s*(true|false)'}

    Returns:
        提取的字段字典
    """
    result = {}
    for field_name, pattern in field_patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            value = match.group(1)
            # 尝试转换类型
            if value.lower() == 'true':
                result[field_name] = True
            elif value.lower() == 'false':
                result[field_name] = False
            elif value.isdigit():
                result[field_name] = int(value)
            else:
                result[field_name] = value
    return result


# 预定义的 WhiteHat 字段模式
WHITEHAT_FIELD_PATTERNS = {
    "is_exploitable": r'"is_exploitable"\s*:\s*(true|false)',
    "exploitability_score": r'"exploitability_score"\s*:\s*(\d+)',
    "confidence": r'"confidence"\s*:\s*"([^"]*)"',
    "exploit_reasoning": r'"exploit_reasoning"\s*:\s*"([^"]*)"',
}
