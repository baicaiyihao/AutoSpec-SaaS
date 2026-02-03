import argparse
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

# 可选依赖：dotenv (用于向量库功能)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv 不是必需的

try:
    from langchain_chroma import Chroma
    from langchain_core.documents import Document
    from langchain_community.embeddings import DashScopeEmbeddings
except ImportError:
    Chroma = None  # type: ignore
    Document = None  # type: ignore
    DashScopeEmbeddings = None  # type: ignore

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = BASE_DIR / "data" / "knowledge_base" / "security"
DEFAULT_OUTPUT = BASE_DIR / "reports" / "datasets" / "security_patterns.jsonl"
DEFAULT_VECTOR_DIR = BASE_DIR / "data" / "vector_store" / "security_patterns"
DEFAULT_COLLECTION = "security_patterns"

SEVERITY_KEYWORDS = ["critical", "high", "medium", "low", "advisory"]

KEYWORD_TAGS = {
    "overflow": "overflow",
    "underflow": "overflow",
    "access control": "access_control",
    "permission": "access_control",
    "admin": "access_control",
    "oracle": "oracle",
    "price": "oracle",
    "time": "time_validation",
    "start_time": "time_validation",
    "timestamp": "time_validation",
    "fee": "fee",
    "reward": "reward",
    "gas": "gas",
    "version": "upgrade",
    "upgrade": "upgrade",
}


def iter_issue_chunks(text: str) -> List[str]:
    """
    按 ID (如 A-1/M-3/L-5/H-1) 粗分报告段落。
    支持多种格式:
    - Format A (Cetus/FullSail): `A-1` 直接在行首
    - Format B (Scallop): `## H-1: Title` 带 markdown 标题
    """
    # 尝试两种格式
    # Format B: Scallop 格式 (## H-1: Title)
    pattern_scallop = re.compile(r"(?m)^##\s+([A-Z]-\d+):")
    matches_scallop = list(pattern_scallop.finditer(text))

    # Format A: 普通格式 (A-1 直接在行首)
    pattern_simple = re.compile(r"(?m)^([A-Z]-\d+)\b")
    matches_simple = list(pattern_simple.finditer(text))

    # 选择匹配数更多的格式
    if len(matches_scallop) > len(matches_simple):
        matches = matches_scallop
        is_scallop = True
    else:
        matches = matches_simple
        is_scallop = False

    if not matches:
        return []

    chunks = []
    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
    return chunks


def extract_section(chunk: str, heading: str) -> Optional[str]:
    """
    抽取以 heading 开头的段落文本。
    支持格式:
    - `Description\n...`
    - `### Description\n...`
    - `**Description**\n...`
    """
    # 尝试多种模式
    patterns = [
        rf"(?i)###?\s*{heading}\s*\n",           # ### Description 或 ## Description
        rf"(?i)\*\*{heading}\*\*\s*\n",          # **Description**
        rf"(?i)^{heading}\s*\n",                 # Description (行首)
        rf"(?i){heading}\s*\n",                  # Description (任意位置)
    ]

    match = None
    for pat in patterns:
        match = re.search(pat, chunk, re.MULTILINE)
        if match:
            break

    if not match:
        return None

    start = match.end()
    rest = chunk[start:].strip()
    lines: List[str] = []

    # 停止词：下一个章节开始
    stop_words = {"description", "recommendation", "remediation", "severity", "keywords", "id"}

    for line in rest.splitlines():
        stripped = line.strip().lower()
        # 检测下一个章节 (### xxx 或 **xxx** 或纯标题)
        if stripped in stop_words:
            break
        if re.match(r"^###?\s+\w+", line.strip()):
            break
        if re.match(r"^\*\*\w+.*\*\*$", line.strip()):
            break
        lines.append(line.rstrip())

    joined = "\n".join(lines).strip()
    return joined or None


def guess_severity(chunk: str) -> Optional[str]:
    """
    猜测严重性。支持格式:
    - `**Severity: High**`
    - `Severity\nhigh`
    - 直接包含 critical/high/medium/low/advisory
    """
    # 优先匹配 **Severity: xxx** 格式
    sev_match = re.search(r"\*\*Severity:\s*(\w+)\*\*", chunk, re.IGNORECASE)
    if sev_match:
        sev = sev_match.group(1).lower()
        if sev in SEVERITY_KEYWORDS:
            return sev

    # 备选：直接搜索关键词
    lower = chunk.lower()
    for sev in SEVERITY_KEYWORDS:
        if sev in lower:
            return sev
    return None


def find_issue_tags(chunk: str) -> List[str]:
    lower = chunk.lower()
    tags: Set[str] = set()
    for key, tag in KEYWORD_TAGS.items():
        if key in lower:
            tags.add(tag)
    return sorted(tags)


def find_detection_cues(chunk: str) -> List[str]:
    cues: Set[str] = set()
    # 函数/模块形式：module::function 或 foo.bar
    for match in re.findall(r"[A-Za-z_]+\:\:[A-Za-z0-9_]+", chunk):
        cues.add(match)
    for match in re.findall(r"[A-Za-z_]+\.[A-Za-z0-9_]+", chunk):
        cues.add(match)
    # 变量/标识符线索：含下划线的词
    for match in re.findall(r"\b[a-z_]{3,}\b", chunk):
        if "_" in match and len(cues) < 15:
            cues.add(match)
    return sorted(cues)


def parse_chunk(chunk: str, source_file: str, project_name: str) -> Dict:
    """
    解析单个漏洞 chunk。支持格式:
    - Scallop: `## H-1: Title`
    - Cetus/FullSail: `A-1\nTitle\n...`
    """
    lines = [l.strip() for l in chunk.splitlines() if l.strip()]
    first_line = lines[0] if lines else ""

    # 提取 ID 和 Title
    issue_id = "UNKNOWN"
    title = ""

    # Format B: Scallop 格式 `## H-1: Title`
    scallop_match = re.match(r"^##\s+([A-Z]-\d+):\s*(.+)$", first_line)
    if scallop_match:
        issue_id = scallop_match.group(1)
        title = scallop_match.group(2).strip()
    else:
        # Format A: 普通格式
        id_match = re.match(r"^([A-Z]-\d+)\b", first_line)
        if id_match:
            issue_id = id_match.group(1)
        if len(lines) > 1 and not re.match(r"^[A-Z]-\d+$", lines[1]):
            title = lines[1]

    severity = guess_severity(chunk) or ""
    description = extract_section(chunk, "description") or ""
    recommendation = extract_section(chunk, "recommendation") or ""
    remediation = extract_section(chunk, "remediation") or ""

    # 如果没有提取到 description，使用整个 chunk (去掉标题行)
    if not description:
        desc_lines = lines[1:] if scallop_match else lines[2:]
        description = "\n".join(desc_lines[:20])  # 限制长度

    detection_cues = find_detection_cues(chunk)
    issue_tags = find_issue_tags(chunk)

    # 尝试从 cues 里拆出第一个函数名
    function_hint = None
    module_path = None
    for cue in detection_cues:
        if "::" in cue:
            function_hint = cue
            break

    # 提取修复状态
    remediation_status = ""
    if "remediated" in chunk.lower():
        remediation_status = "remediated"
    elif "acknowledged" in chunk.lower():
        remediation_status = "acknowledged"
    elif "pending" in chunk.lower():
        remediation_status = "pending"

    return {
        "id": issue_id,
        "project": project_name,
        "source_file": source_file,
        "module_path": module_path,
        "function": function_hint,
        "title": title,
        "severity": severity,
        "issue_tags": issue_tags,
        "description": description[:2000],  # 限制长度
        "recommendation": recommendation[:1000],
        "remediation_status": remediation_status,
        "detection_cues": detection_cues,
        "suggested_checks": [],
    }


def extract_from_file(md_path: Path) -> List[Dict]:
    text = md_path.read_text(encoding="utf-8", errors="ignore")
    chunks = iter_issue_chunks(text)
    project_name = md_path.stem
    patterns = [parse_chunk(chunk, md_path.name, project_name) for chunk in chunks]
    return patterns


def write_jsonl(output_path: Path, rows: List[Dict]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def build_vector_store(rows: List[Dict], vector_dir: Path, collection: str) -> None:
    if Chroma is None or Document is None or DashScopeEmbeddings is None:
        print("⚠️ 未安装向量化依赖，跳过向量库生成。")
        return
    api_key = os.getenv("DASHSCOPE_API_KEY")
    if not api_key:
        print("⚠️ 未找到 DASHSCOPE_API_KEY，跳过向量库生成。")
        return

    docs: List[Document] = []
    for row in rows:
        # 构建文档内容
        content = "\n".join(
            filter(
                None,
                [
                    row.get("title", ""),
                    row.get("description", ""),
                    row.get("recommendation", ""),
                    " | ".join(row.get("issue_tags", [])),
                ],
            )
        )

        # ChromaDB 不支持 list 类型的 metadata，需要转换
        clean_metadata = {}
        for key, value in row.items():
            if isinstance(value, list):
                clean_metadata[key] = " | ".join(str(v) for v in value) if value else ""
            elif value is None:
                clean_metadata[key] = ""
            else:
                clean_metadata[key] = value

        docs.append(Document(page_content=content, metadata=clean_metadata))

    vector_dir.mkdir(parents=True, exist_ok=True)
    embeddings = DashScopeEmbeddings(model="text-embedding-v2", dashscope_api_key=api_key)
    Chroma.from_documents(
        documents=docs,
        embedding=embeddings,
        persist_directory=str(vector_dir),
        collection_name=collection,
    )
    print(f"✅ 向量库已生成 -> {vector_dir} (collection={collection})")


def main():
    parser = argparse.ArgumentParser(description="提取安全/漏洞报告为结构化数据集，支持可选向量库。")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_DIR, help="Markdown 安全报告目录")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT, help="输出 JSONL 路径")
    parser.add_argument("--persist-vector", action="store_true", help="同时生成 security_patterns 向量库")
    parser.add_argument("--vector-dir", type=Path, default=DEFAULT_VECTOR_DIR, help="向量库存储目录")
    parser.add_argument("--collection", type=str, default=DEFAULT_COLLECTION, help="向量库集合名")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"❌ 输入目录不存在: {args.input}")
        return

    md_files = sorted([p for p in args.input.glob("*.md") if p.is_file()])
    if not md_files:
        print(f"❌ 未找到 Markdown 文件: {args.input}")
        return

    all_rows: List[Dict] = []
    for md_file in md_files:
        rows = extract_from_file(md_file)
        all_rows.extend(rows)
        print(f"✅ 解析 {md_file.name}: {len(rows)} 条")

    write_jsonl(args.out, all_rows)
    print(f"🎯 已写入数据集: {args.out} (共 {len(all_rows)} 条)")

    if args.persist_vector:
        build_vector_store(all_rows, args.vector_dir, args.collection)


if __name__ == "__main__":
    main()
