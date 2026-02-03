"""
安全模式扫描器 (Security Pattern Scanner)

对 Move 代码进行安全模式匹配，检测潜在漏洞风险。
即使代码通过形式化验证，也能发现规范层面的安全隐患。

支持两种匹配模式:
1. 关键词/正则匹配 (基于 JSONL)
2. 语义向量检索 (基于 ChromaDB)

Usage:
    from src.security.pattern_scan import SecurityScanner

    scanner = SecurityScanner(use_vector_db=True)
    report = scanner.scan(code)
    print(report.to_markdown())
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 导入配置
from src.config import DASHSCOPE_API_KEY

# Jinja2 模板渲染 (可选)
try:
    from jinja2 import Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

# 可选依赖：向量检索
try:
    from langchain_chroma import Chroma
    from langchain_community.embeddings import DashScopeEmbeddings
    VECTOR_DB_AVAILABLE = True
except ImportError:
    Chroma = None
    DashScopeEmbeddings = None
    VECTOR_DB_AVAILABLE = False

# ==============================================================================
# 严重性权重 (用于风险评分)
# ==============================================================================

SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 20,
    "advisory": 10,
}

# ==============================================================================
# 内置安全规则 (不依赖外部 JSONL)
# ==============================================================================

BUILTIN_RULES = [
    {
        "id": "BUILTIN-001",
        "title": "Potential Arithmetic Overflow",
        "severity": "high",
        "issue_tags": ["overflow", "math_safety"],
        "detection_cues": ["* ", "amount *", "value *", "price *", "fee *"],
        "pattern": r"\b\w+\s*\*\s*\w+",
        "recommendation": "Use u128 casting or add overflow checks with requires()",
        "suggested_checks": ["requires((a as u128) * (b as u128) <= MAX_U64)"],
    },
    {
        "id": "BUILTIN-002",
        "title": "Missing Access Control Check",
        "severity": "high",
        "issue_tags": ["access_control", "privilege"],
        "detection_cues": ["admin", "owner", "cap"],
        "pattern": r"public\s+fun\s+\w+.*(?:admin|set_|update_|remove_|add_)",
        "recommendation": "Ensure AdminCap or ownership verification is required",
        "suggested_checks": ["requires(caller == admin)"],
    },
    {
        "id": "BUILTIN-003",
        "title": "Unchecked Division (Potential Div-by-Zero)",
        "severity": "medium",
        "issue_tags": ["div_zero", "math_safety"],
        "detection_cues": ["/", "div"],
        "pattern": r"\b\w+\s*/\s*\w+",
        "recommendation": "Add requires(divisor != 0) or use safe_div",
        "suggested_checks": ["requires(divisor != 0)"],
    },
    {
        "id": "BUILTIN-004",
        "title": "Flash Loan Without Proper Repayment Check",
        "severity": "high",
        "issue_tags": ["flash_loan", "defi"],
        "detection_cues": ["flash", "loan", "borrow", "repay", "receipt"],
        "pattern": r"(flash|loan|borrow).*receipt",
        "recommendation": "Ensure Receipt is properly validated and consumed",
        "suggested_checks": ["ensures(repaid_amount >= borrowed_amount + fee)"],
    },
    {
        "id": "BUILTIN-005",
        "title": "Oracle Price Manipulation Risk",
        "severity": "high",
        "issue_tags": ["oracle", "price_manipulation"],
        "detection_cues": ["oracle", "price", "pyth", "get_price"],
        "pattern": r"(get_price|oracle|price_feed)",
        "recommendation": "Use TWAP, check staleness, and verify confidence intervals",
        "suggested_checks": ["requires(price_timestamp > now - MAX_STALENESS)"],
    },
    {
        "id": "BUILTIN-006",
        "title": "Linear Resource Not Properly Handled",
        "severity": "medium",
        "issue_tags": ["linear_resource", "type_safety"],
        "detection_cues": ["coin", "balance", "receipt"],
        "pattern": r"(Coin<|Balance<|Receipt)",
        "recommendation": "Ensure linear resources are returned, consumed, or destructured",
        "suggested_checks": ["ensures(resource_consumed OR resource_returned)"],
    },
    {
        "id": "BUILTIN-007",
        "title": "Missing Input Validation",
        "severity": "low",
        "issue_tags": ["validation", "input_check"],
        "detection_cues": ["amount", "value", "rate", "bps"],
        "pattern": r"public\s+fun\s+\w+\s*\([^)]*(?:amount|value|rate)",
        "recommendation": "Add requires(amount > 0) and upper bound checks",
        "suggested_checks": ["requires(amount > 0)", "requires(rate <= MAX_RATE)"],
    },
    {
        "id": "BUILTIN-008",
        "title": "Liquidation Logic Risk",
        "severity": "high",
        "issue_tags": ["liquidation", "defi", "lending"],
        "detection_cues": ["liquidat", "collateral", "health", "ratio"],
        "pattern": r"(liquidat|health_factor|collateral_ratio)",
        "recommendation": "Verify liquidation threshold and penalty calculations",
        "suggested_checks": ["requires(health_factor < LIQUIDATION_THRESHOLD)"],
    },
    # =========================================================================
    # Sui Move 通用安全规则 (BUILTIN-009 ~ BUILTIN-016)
    # =========================================================================
    {
        "id": "BUILTIN-009",
        "title": "Shared Object Without Access Control",
        "severity": "high",
        "issue_tags": ["access_control", "shared_object", "sui"],
        "detection_cues": ["&mut ", "public fun", "entry fun"],
        "pattern": r"public\s+(entry\s+)?fun\s+\w+[^{]*&mut\s+\w+",
        "recommendation": "Add AdminCap/OwnerCap parameter or assert sender check for shared object mutations",
        "suggested_checks": ["requires(tx_context::sender(ctx) == admin)", "requires(has_capability)"],
    },
    {
        "id": "BUILTIN-010",
        "title": "Coin Type Confusion",
        "severity": "high",
        "issue_tags": ["type_safety", "coin", "sui"],
        "detection_cues": ["Coin<T>", "Balance<T>", "<T>"],
        "pattern": r"fun\s+\w+<\s*T\s*>[^{]*(?:Coin|Balance)<\s*T\s*>",
        "recommendation": "Verify generic coin type T against expected type or whitelist",
        "suggested_checks": ["requires(type_name::get<T>() == expected_type)"],
    },
    {
        "id": "BUILTIN-011",
        "title": "Object Ownership Transfer Risk",
        "severity": "high",
        "issue_tags": ["ownership", "transfer", "sui"],
        "detection_cues": ["transfer::", "public_transfer", "share_object"],
        "pattern": r"(transfer::public_transfer|transfer::share_object)\s*\(",
        "recommendation": "Verify recipient and ensure ownership transfer is intentional",
        "suggested_checks": ["Validate recipient address", "Check transfer authorization"],
    },
    {
        "id": "BUILTIN-012",
        "title": "Capability Leak via Public Transfer",
        "severity": "high",
        "issue_tags": ["capability", "access_control", "sui"],
        "detection_cues": ["Cap", "Capability", "public_transfer"],
        "pattern": r"public_transfer\s*\([^)]*Cap",
        "recommendation": "Capabilities should not be freely transferable; remove store ability or restrict transfer",
        "suggested_checks": ["Capability should not have 'store' ability", "Use transfer::transfer instead"],
    },
    {
        "id": "BUILTIN-013",
        "title": "Clock/Timestamp Manipulation Risk",
        "severity": "medium",
        "issue_tags": ["timestamp", "clock", "sui"],
        "detection_cues": ["clock", "timestamp", "Clock", "timestamp_ms"],
        "pattern": r"clock::timestamp_ms|&Clock",
        "recommendation": "Be aware validators can slightly manipulate timestamps; use time windows instead of exact comparisons",
        "suggested_checks": ["Use tolerance window for time checks", "requires(current_time >= start_time - TOLERANCE)"],
    },
    {
        "id": "BUILTIN-014",
        "title": "Flash Loan Callback Order",
        "severity": "high",
        "issue_tags": ["flash_loan", "hot_potato", "sui"],
        "detection_cues": ["flash", "borrow", "repay", "Receipt"],
        "pattern": r"public\s+fun\s+(flash_|borrow)[^}]+Receipt",
        "recommendation": "Use Hot Potato pattern - return Receipt that must be consumed in same transaction",
        "suggested_checks": ["Receipt has no drop/store ability", "repay() consumes Receipt"],
    },
    {
        "id": "BUILTIN-015",
        "title": "BCS Deserialization Without Validation",
        "severity": "medium",
        "issue_tags": ["deserialization", "external_data", "sui"],
        "detection_cues": ["bcs::", "from_bytes", "deserialize"],
        "pattern": r"bcs::(from_bytes|to_bytes)|deserialize",
        "recommendation": "Validate deserialized data before use; external data may be malformed",
        "suggested_checks": ["Validate struct fields after deserialization", "Check data bounds"],
    },
    {
        "id": "BUILTIN-016",
        "title": "Reentrancy via Shared Object",
        "severity": "high",
        "issue_tags": ["reentrancy", "shared_object", "sui"],
        "detection_cues": ["&mut ", "external call", "callback"],
        "pattern": r"public\s+fun\s+\w+[^{]*&mut[^{]+\w+::\w+\s*\(",
        "recommendation": "Update state before external calls; use reentrancy guard for shared objects",
        "suggested_checks": ["Follow checks-effects-interactions pattern", "requires(!is_locked)"],
    },
    # =========================================================================
    # 闪电贷类型混淆漏洞 (BUILTIN-017 ~ BUILTIN-018) - v2.5.4 新增
    # =========================================================================
    {
        "id": "BUILTIN-017",
        "title": "Flash Loan Repayment Type Confusion",
        "severity": "critical",
        "issue_tags": ["flash_loan", "type_safety", "defi", "sui"],
        "detection_cues": ["flashloan", "flash_loan", "repay", "Receipt", "type_name", "Coin<"],
        "pattern": r"(repay|flash).*<\s*\w+\s*>.*Coin<\s*\w+\s*>",
        "recommendation": "Verify repayment coin type matches borrowed coin type: assert!(type_name::get<A>() == receipt.type_name)",
        "suggested_checks": [
            "repay 函数必须验证: type_name::get<A>().into_string() == receipt.type_name",
            "检查: contains_type 只验证池子里有该币，不验证是否是借出的币",
            "漏洞模式: 借 CoinA 还 CoinB → 掏空 CoinA 池"
        ],
    },
    {
        "id": "BUILTIN-018",
        "title": "Hot Potato Receipt Without Type Verification",
        "severity": "critical",
        "issue_tags": ["flash_loan", "hot_potato", "type_safety", "sui"],
        "detection_cues": ["Receipt", "FlashReceipt", "repay", "pool_id", "amount"],
        "pattern": r"struct\s+\w*Receipt\s*\{[^}]*pool_id[^}]*\}",
        "recommendation": "Receipt must store borrowed coin type_name and repay must verify it matches",
        "suggested_checks": [
            "Receipt 应包含: type_name: TypeName (借出币种类型)",
            "repay 应验证: type_name::get<RepaidCoin>() == receipt.type_name",
            "仅检查 pool_id 和 amount 不够，必须验证币种"
        ],
    },
]


# ==============================================================================
# 数据类型定义
# ==============================================================================

@dataclass
class PatternMatch:
    """单个模式匹配结果"""
    pattern_id: str
    title: str
    severity: str
    issue_tags: List[str]
    description: str  # 风险分析/漏洞详情
    recommendation: str  # 修复建议
    suggested_checks: List[str]
    matched_cues: List[str]
    confidence: float  # 0.0 - 1.0
    line_hints: List[int]  # 可能相关的行号


@dataclass
class ScanReport:
    """扫描报告"""
    total_patterns_checked: int
    matches: List[PatternMatch] = field(default_factory=list)
    risk_score: int = 0
    summary: str = ""

    def to_markdown(self) -> str:
        """生成 Markdown 格式报告"""
        if not self.matches:
            return "## Security Scan Report\n\n✅ No potential issues detected.\n"

        lines = [
            "## Security Scan Report",
            "",
            f"**Risk Score:** {self.risk_score}/100",
            f"**Issues Found:** {len(self.matches)}",
            "",
            "### Findings",
            "",
        ]

        # 按严重性排序
        sorted_matches = sorted(
            self.matches,
            key=lambda m: SEVERITY_WEIGHTS.get(m.severity, 0),
            reverse=True
        )

        for i, m in enumerate(sorted_matches, 1):
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "advisory": "🔵",
            }.get(m.severity, "⚪")

            lines.append(f"#### {i}. {severity_emoji} [{m.severity.upper()}] {m.title}")
            lines.append(f"- **ID:** `{m.pattern_id}`")
            lines.append(f"- **Tags:** {', '.join(m.issue_tags)}")
            lines.append(f"- **Confidence:** {m.confidence:.0%}")
            if m.matched_cues:
                lines.append(f"- **Matched Cues:** `{', '.join(m.matched_cues[:5])}`")
            lines.append(f"- **Recommendation:** {m.recommendation}")
            if m.suggested_checks:
                lines.append("- **Suggested Spec Checks:**")
                for check in m.suggested_checks[:3]:
                    lines.append(f"  - `{check}`")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> Dict:
        """转换为字典 (用于 JSON 输出)"""
        return {
            "risk_score": self.risk_score,
            "total_patterns_checked": self.total_patterns_checked,
            "issues_count": len(self.matches),
            "matches": [
                {
                    "pattern_id": m.pattern_id,
                    "title": m.title,
                    "severity": m.severity,
                    "issue_tags": m.issue_tags,
                    "confidence": m.confidence,
                    "recommendation": m.recommendation,
                }
                for m in self.matches
            ],
        }

    def get_high_priority_warnings(self) -> List[str]:
        """获取高优先级警告 (用于注入到 Prompt)"""
        warnings = []
        for m in self.matches:
            if m.severity in ["critical", "high"]:
                warning = f"[⚠️ {m.severity.upper()}] {m.title}: {m.recommendation}"
                if m.suggested_checks:
                    warning += f" Suggested: {m.suggested_checks[0]}"
                warnings.append(warning)
        return warnings[:5]  # 限制数量


# ==============================================================================
# 安全扫描器
# ==============================================================================

class SecurityScanner:
    """
    安全模式扫描器

    结合内置规则、外部 JSONL 知识库和向量语义检索，对 Move 代码进行安全分析。
    """

    def __init__(
        self,
        patterns_path: Optional[str] = None,
        use_vector_db: bool = True,
        vector_db_path: Optional[str] = None
    ):
        """
        初始化扫描器

        Args:
            patterns_path: 外部 JSONL 文件路径 (可选)
            use_vector_db: 是否启用向量语义检索 (默认 True)
            vector_db_path: 向量库路径 (可选)
        """
        self.external_patterns = self._load_external_patterns(patterns_path)
        self.all_patterns = BUILTIN_RULES + self.external_patterns

        # 初始化向量检索
        self.vector_db = None
        self.use_vector_db = use_vector_db and VECTOR_DB_AVAILABLE
        if self.use_vector_db:
            self.vector_db = self._init_vector_db(vector_db_path)

        vector_status = f"+ 向量检索 ({'启用' if self.vector_db else '禁用'})"
        print(f"🔒 [SecurityScanner] 已加载 {len(BUILTIN_RULES)} 条内置规则 + {len(self.external_patterns)} 条外部模式 {vector_status}")

    def _init_vector_db(self, vector_db_path: Optional[str] = None) -> Optional[object]:
        """
        初始化向量数据库连接

        自动检测 embedding 类型：
        1. 优先使用本地 HuggingFace 模型（如果 security_patterns_local 存在）
        2. 否则使用 DashScope API（如果有 API Key）
        """
        if not VECTOR_DB_AVAILABLE:
            return None

        base_path = Path(__file__).resolve().parents[2] / "data" / "vector_store"

        # 1. 优先检查本地模型向量库
        local_db_path = base_path / "security_patterns_local"
        if local_db_path.exists():
            try:
                from langchain_huggingface import HuggingFaceEmbeddings
                # 模型缓存到项目目录下
                model_cache_dir = base_path.parent / "models"
                embeddings = HuggingFaceEmbeddings(
                    model_name="sentence-transformers/all-MiniLM-L6-v2",
                    cache_folder=str(model_cache_dir),
                    model_kwargs={'device': 'cpu', 'local_files_only': True},
                    encode_kwargs={'normalize_embeddings': True}
                )
                db = Chroma(
                    persist_directory=str(local_db_path),
                    embedding_function=embeddings,
                    collection_name="security_patterns"
                )
                print("📦 [SecurityScanner] 使用本地 HuggingFace embedding 向量库")
                return db
            except ImportError:
                pass  # 本地模型不可用，继续尝试 DashScope
            except Exception as e:
                print(f"⚠️  [SecurityScanner] 本地向量库初始化失败: {e}")

        # 2. 回退到 DashScope API
        if not DASHSCOPE_API_KEY:
            print("⚠️  [SecurityScanner] 未找到 DASHSCOPE_API_KEY 且无本地向量库，禁用向量检索")
            return None

        api_db_path = Path(vector_db_path) if vector_db_path else (base_path / "security_patterns")

        if not api_db_path.exists():
            print(f"⚠️  [SecurityScanner] 向量库不存在: {api_db_path}，禁用向量检索")
            return None

        try:
            embeddings = DashScopeEmbeddings(model="text-embedding-v2", dashscope_api_key=DASHSCOPE_API_KEY)
            db = Chroma(
                persist_directory=str(api_db_path),
                embedding_function=embeddings,
                collection_name="security_patterns"
            )
            print("☁️  [SecurityScanner] 使用 DashScope API 向量库")
            return db
        except Exception as e:
            print(f"⚠️  [SecurityScanner] 向量库初始化失败: {e}")
            return None

    def _load_external_patterns(self, path: Optional[str]) -> List[Dict]:
        """加载外部 JSONL 模式"""
        default_path = Path(__file__).resolve().parents[2] / "reports" / "datasets" / "security_patterns.jsonl"
        target_path = Path(path) if path else default_path

        if not target_path.exists():
            return []

        patterns = []
        with target_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    patterns.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return patterns

    def scan(
        self,
        code: str,
        domain_hint: Optional[str] = None,
        function_hints: Optional[List[str]] = None,
    ) -> ScanReport:
        """
        扫描代码，返回安全报告

        Args:
            code: Move 源代码
            domain_hint: 领域提示 (如 "lending", "amm")
            function_hints: 函数名提示列表
        """
        matches: List[PatternMatch] = []
        code_lower = code.lower()

        # 1. 关键词/正则匹配
        for pattern in self.all_patterns:
            match_result = self._match_pattern(code, code_lower, pattern, domain_hint, function_hints)
            if match_result:
                matches.append(match_result)

        # 2. 向量语义检索 (如果启用)
        if self.vector_db:
            vector_matches = self._semantic_search(code, domain_hint)
            matches.extend(vector_matches)

        # 去重 (按 title)
        seen_titles = set()
        unique_matches = []
        for m in matches:
            if m.title not in seen_titles:
                seen_titles.add(m.title)
                unique_matches.append(m)

        # 计算风险分数
        risk_score = self._calculate_risk_score(unique_matches)

        report = ScanReport(
            total_patterns_checked=len(self.all_patterns),
            matches=unique_matches,
            risk_score=risk_score,
            summary=self._generate_summary(unique_matches, risk_score),
        )

        return report

    def _semantic_search(self, code: str, domain_hint: Optional[str] = None, top_k: int = 5) -> List[PatternMatch]:
        """使用向量数据库进行语义搜索"""
        if not self.vector_db:
            return []

        try:
            # 构建查询：代码片段 + 领域提示
            query = code[:2000]  # 限制长度
            if domain_hint:
                query = f"[{domain_hint}] {query}"

            # 检索相似文档
            results = self.vector_db.similarity_search_with_score(query, k=top_k * 2)  # 多检索一些，后面会过滤

            matches = []
            code_lower = code.lower()

            for doc, score in results:
                # score 是距离，越小越相似
                # 转换为置信度 (0-1)，距离 < 1.0 认为是高相似度
                confidence = max(0, min(1, 1 - score / 2))

                # 只保留相似度足够高的结果 (距离 < 1.5)
                if score > 1.5:
                    continue

                metadata = doc.metadata
                title = metadata.get("title", "Unknown Issue")
                description = metadata.get("description", "")
                function_hint = metadata.get("function", "")
                detection_cues = metadata.get("detection_cues", "")

                # 🔥 关键改进：验证代码相关性
                # 检查漏洞描述中的关键元素是否在当前代码中存在
                relevance_score = self._check_code_relevance(
                    code_lower=code_lower,
                    title=title,
                    description=description,
                    function_hint=function_hint,
                    detection_cues=detection_cues
                )

                # 如果相关性太低，跳过这个漏洞
                if relevance_score < 0.3:
                    continue

                # 调整置信度 (结合向量相似度和代码相关性)
                adjusted_confidence = confidence * relevance_score

                severity = metadata.get("severity", "low")

                # 找到实际匹配的 cues
                matched_cues = self._find_matched_cues(code_lower, detection_cues, title)

                matches.append(PatternMatch(
                    pattern_id=f"VEC-{metadata.get('id', 'UNKNOWN')}",
                    title=title,
                    severity=severity if severity else "low",
                    issue_tags=metadata.get("issue_tags", "").split(" | ") if metadata.get("issue_tags") else [],
                    description=description,  # 风险分析
                    recommendation=metadata.get("recommendation", ""),
                    suggested_checks=[],
                    matched_cues=matched_cues if matched_cues else ["semantic_match"],
                    confidence=adjusted_confidence,
                    line_hints=[],
                ))

            return matches[:top_k]  # 限制返回数量
        except Exception as e:
            print(f"⚠️  [SecurityScanner] 向量检索失败: {e}")
            return []

    def _check_code_relevance(
        self,
        code_lower: str,
        title: str,
        description: str,
        function_hint: str,
        detection_cues: str
    ) -> float:
        """
        检查漏洞与当前代码的相关性

        Returns:
            相关性分数 0.0 - 1.0
        """
        relevance = 0.0
        checks = 0
        negative_hits = 0  # 负面匹配（描述中提到但代码中不存在的模式）
        critical_missing = 0  # 核心概念缺失

        # 0. 提取标题中的核心概念（这些必须在代码中存在）
        # 例如 "Fee Recipient" -> recipient 必须存在
        core_concepts = self._extract_core_concepts(title)
        for concept in core_concepts:
            if concept not in code_lower:
                critical_missing += 1

        # 如果核心概念不存在，直接返回很低的分数
        if critical_missing > 0:
            return 0.1  # 核心概念缺失，基本判定为不相关

        # 1. 检查标题中的关键词
        title_keywords = self._extract_keywords(title)
        for kw in title_keywords:
            checks += 1
            if kw in code_lower:
                relevance += 1.0

        # 2. 检查函数名
        if function_hint:
            func_name = function_hint.split("::")[-1].lower() if "::" in function_hint else function_hint.lower()
            checks += 1
            if func_name in code_lower:
                relevance += 1.5  # 函数名匹配权重更高

        # 3. 检查 detection_cues
        if detection_cues:
            cues = detection_cues.split(" | ") if " | " in detection_cues else [detection_cues]
            for cue in cues[:5]:
                cue_lower = cue.lower().strip()
                if len(cue_lower) >= 3:  # 忽略太短的 cue
                    checks += 1
                    if cue_lower in code_lower:
                        relevance += 0.8

        # 4. 简单索引检查：描述中提到的函数/功能是否存在于代码中
        # 提取描述中的函数名（下划线命名的标识符）
        mentioned_identifiers = re.findall(r'\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b', description.lower())
        # 去重，只保留长度>=8的（更具体的标识符）
        mentioned_identifiers = list(set([x for x in mentioned_identifiers if len(x) >= 8]))

        # 检查这些标识符是否在代码中存在
        missing_count = 0
        for identifier in mentioned_identifiers[:5]:  # 只检查前5个
            if identifier not in code_lower:
                missing_count += 1

        # 如果大部分提到的标识符都不存在，很可能是误报
        if len(mentioned_identifiers) >= 2 and missing_count >= len(mentioned_identifiers) * 0.7:
            return 0.15  # 大概率误报

        # 5. 检查描述中的代码模式（正面和负面）
        code_patterns = re.findall(r'`([^`]+)`', description)
        # 同时检查推荐中提到的特定变量名/函数名
        specific_names = re.findall(r'\b([a-z_]+(?:_[a-z]+)+)\b', description.lower())
        all_patterns = list(set(code_patterns + specific_names))

        for pattern in all_patterns[:10]:
            pattern_lower = pattern.lower()
            if len(pattern_lower) >= 5:  # 只检查有意义的长模式
                checks += 1
                if pattern_lower in code_lower:
                    relevance += 0.6
                else:
                    # 如果是很具体的变量名（含下划线），但代码中不存在，扣分
                    if '_' in pattern_lower and not any(p in code_lower for p in pattern_lower.split('_')):
                        negative_hits += 1

        # 计算最终相关性分数
        if checks == 0:
            return 0.5  # 无法判断，给中等分数

        base_score = min(relevance / max(checks * 0.5, 1), 1.0)

        # 如果有很多负面匹配，降低分数
        if negative_hits >= 2:
            base_score *= 0.5  # 严重降低分数
        elif negative_hits >= 1:
            base_score *= 0.7

        return base_score

    def _extract_core_concepts(self, title: str) -> List[str]:
        """
        从标题中提取核心概念

        这些概念必须在代码中存在，否则漏洞不适用。
        例如: "Fee Recipient Ignored" -> ["recipient"]
              "Oracle Price Manipulation" -> ["oracle", "price"]
              "Whitelist Bypass" -> ["whitelist"]
        """
        # 核心概念词典：标题关键词 -> 代码中必须存在的概念
        concept_mapping = {
            'recipient': ['recipient'],
            'oracle': ['oracle'],
            'whitelist': ['whitelist', 'white_list'],
            'blacklist': ['blacklist', 'black_list'],
            'admin': ['admin'],
            'owner': ['owner'],
            'governance': ['governance', 'gov'],
            'timelock': ['timelock', 'time_lock'],
            'pause': ['pause', 'paused'],
            'upgrade': ['upgrade'],
            'proxy': ['proxy'],
            'delegate': ['delegate'],
            'callback': ['callback'],
            'reentrancy': ['reentrant', 'reentrancy'],
            'slippage': ['slippage'],
            'deadline': ['deadline'],
            'nonce': ['nonce'],
            'signature': ['signature', 'sig'],
        }

        title_lower = title.lower()
        required_concepts = []

        for keyword, concepts in concept_mapping.items():
            if keyword in title_lower:
                required_concepts.extend(concepts)

        return required_concepts

    def _extract_keywords(self, text: str) -> List[str]:
        """从文本中提取关键词"""
        # 移除常见的无意义词
        stop_words = {'the', 'is', 'a', 'an', 'in', 'on', 'of', 'for', 'to', 'with', 'without', 'not', 'and', 'or', 'but'}

        words = re.findall(r'\b[a-z_][a-z0-9_]*\b', text.lower())
        keywords = [w for w in words if len(w) >= 3 and w not in stop_words]

        return keywords[:10]

    def _find_matched_cues(self, code_lower: str, detection_cues: str, title: str) -> List[str]:
        """找到实际匹配的 cues"""
        matched = []

        # 从 detection_cues 中找
        if detection_cues:
            cues = detection_cues.split(" | ") if " | " in detection_cues else [detection_cues]
            for cue in cues:
                cue_lower = cue.lower().strip()
                if len(cue_lower) >= 3 and cue_lower in code_lower:
                    matched.append(cue)

        # 从标题中找
        title_keywords = self._extract_keywords(title)
        for kw in title_keywords:
            if kw in code_lower and kw not in [m.lower() for m in matched]:
                matched.append(kw)

        return matched[:5]

    def _match_pattern(
        self,
        code: str,
        code_lower: str,
        pattern: Dict,
        domain_hint: Optional[str],
        function_hints: Optional[List[str]],
    ) -> Optional[PatternMatch]:
        """匹配单个模式"""
        matched_cues = []
        confidence = 0.0
        line_hints = []

        # 1. 关键词/Cue 匹配
        cues = pattern.get("detection_cues") or []
        for cue in cues:
            cue_lower = str(cue).lower()
            if cue_lower and cue_lower in code_lower:
                matched_cues.append(cue)
                confidence += 0.15

        # 2. 正则模式匹配
        regex_pattern = pattern.get("pattern")
        if regex_pattern:
            try:
                regex_matches = list(re.finditer(regex_pattern, code, re.IGNORECASE))
                if regex_matches:
                    confidence += 0.3
                    # 提取行号
                    for m in regex_matches[:3]:
                        line_num = code[:m.start()].count('\n') + 1
                        line_hints.append(line_num)
            except re.error:
                pass

        # 3. 标签/领域匹配
        issue_tags = pattern.get("issue_tags") or []
        if domain_hint:
            for tag in issue_tags:
                if domain_hint.lower() in tag.lower() or tag.lower() in domain_hint.lower():
                    confidence += 0.2
                    break

        # 4. 函数名匹配
        if function_hints:
            pattern_func = pattern.get("function")
            if pattern_func:
                for func in function_hints:
                    if func.lower() in pattern_func.lower() or pattern_func.lower() in func.lower():
                        confidence += 0.25
                        break

        # 置信度阈值
        if confidence < 0.2 or not matched_cues:
            return None

        confidence = min(confidence, 1.0)

        return PatternMatch(
            pattern_id=pattern.get("id", "UNKNOWN"),
            title=pattern.get("title", "Unknown Issue"),
            severity=pattern.get("severity", "low"),
            issue_tags=issue_tags,
            description=pattern.get("description", ""),  # 风险分析
            recommendation=pattern.get("recommendation", ""),
            suggested_checks=pattern.get("suggested_checks") or [],
            matched_cues=matched_cues[:5],
            confidence=confidence,
            line_hints=line_hints[:5],
        )

    def _calculate_risk_score(self, matches: List[PatternMatch]) -> int:
        """计算风险分数 (0-100)"""
        if not matches:
            return 0

        total = 0
        for m in matches:
            weight = SEVERITY_WEIGHTS.get(m.severity, 10)
            total += weight * m.confidence

        # 归一化到 0-100
        return min(int(total), 100)

    def _generate_summary(self, matches: List[PatternMatch], risk_score: int) -> str:
        """生成摘要"""
        if not matches:
            return "No security concerns detected."

        severity_counts = {}
        for m in matches:
            severity_counts[m.severity] = severity_counts.get(m.severity, 0) + 1

        parts = []
        for sev in ["critical", "high", "medium", "low", "advisory"]:
            if sev in severity_counts:
                parts.append(f"{severity_counts[sev]} {sev}")

        return f"Found {len(matches)} potential issues ({', '.join(parts)}). Risk score: {risk_score}/100"

    def generate_detailed_report(
        self,
        code: str,
        report: ScanReport,
        source_tag: Optional[str] = None
    ) -> str:
        """
        生成详细的安全审计报告

        格式参考专业安全审计报告，包含:
        - 模块/合约名称
        - 函数位置
        - 具体代码行
        - 漏洞描述和建议
        """
        lines = []
        lines.append("")
        lines.append("=" * 70)
        lines.append("                    🔒 SECURITY AUDIT REPORT")
        lines.append("=" * 70)
        lines.append("")

        # 解析代码获取模块和函数信息
        module_name = self._extract_module_name(code)
        functions = self._extract_functions(code)

        lines.append(f"📦 Module: {module_name or 'Unknown'}")
        lines.append(f"🏷️  Domain: {source_tag or 'general'}")
        lines.append(f"📊 Risk Score: {report.risk_score}/100")
        lines.append(f"🔍 Issues Found: {len(report.matches)}")
        lines.append("")
        lines.append("-" * 70)

        # 统计严重性分布
        severity_counts = {}
        for m in report.matches:
            severity_counts[m.severity] = severity_counts.get(m.severity, 0) + 1

        lines.append("📈 Severity Distribution:")
        for sev in ["critical", "high", "medium", "low", "advisory"]:
            if sev in severity_counts:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "advisory": "🔵"}.get(sev, "⚪")
                lines.append(f"   {emoji} {sev.upper()}: {severity_counts[sev]}")
        lines.append("")
        lines.append("=" * 70)
        lines.append("                         FINDINGS")
        lines.append("=" * 70)

        # 按严重性排序
        sorted_matches = sorted(
            report.matches,
            key=lambda m: SEVERITY_WEIGHTS.get(m.severity, 0),
            reverse=True
        )

        for i, m in enumerate(sorted_matches, 1):
            severity_emoji = {
                "critical": "🔴", "high": "🟠", "medium": "🟡",
                "low": "🟢", "advisory": "🔵"
            }.get(m.severity, "⚪")

            lines.append("")
            lines.append(f"┌─ {m.pattern_id}: {m.title}")
            lines.append(f"│")
            lines.append(f"│  Severity:   {severity_emoji} {m.severity.upper()}")
            lines.append(f"│  Confidence: {m.confidence:.0%}")
            lines.append(f"│  Tags:       {', '.join(m.issue_tags) if m.issue_tags else 'N/A'}")

            # 定位到具体位置
            location = self._find_location(code, m, functions)
            if location:
                lines.append(f"│")
                lines.append(f"│  📍 Location:")
                lines.append(f"│     Module:   {module_name or 'Unknown'}")
                if location.get('function'):
                    lines.append(f"│     Function: {location['function']}")
                if location.get('line'):
                    lines.append(f"│     Line:     {location['line']}")
                if location.get('code_snippet'):
                    lines.append(f"│     Code:     {location['code_snippet'][:60]}...")

            # 建议
            if m.recommendation:
                lines.append(f"│")
                lines.append(f"│  💡 Recommendation:")
                # 换行处理长文本
                rec_lines = m.recommendation.split('\n')
                for rec_line in rec_lines[:3]:
                    if rec_line.strip():
                        lines.append(f"│     {rec_line.strip()[:65]}")

            # 建议的 Spec 检查
            if m.suggested_checks:
                lines.append(f"│")
                lines.append(f"│  ✅ Suggested Spec Checks:")
                for check in m.suggested_checks[:2]:
                    lines.append(f"│     • {check}")

            lines.append(f"│")
            lines.append(f"└{'─' * 68}")

        lines.append("")
        lines.append("=" * 70)
        lines.append("💡 NOTE: Formal verification passing does NOT guarantee security.")
        lines.append("   Please manually review all findings above.")
        lines.append("=" * 70)
        lines.append("")

        return "\n".join(lines)

    def _extract_module_name(self, code: str) -> Optional[str]:
        """从代码中提取模块名"""
        match = re.search(r'module\s+(\w+::[\w:]+)\s*\{', code)
        if match:
            return match.group(1)
        return None

    def _extract_functions(self, code: str) -> List[Dict]:
        """从代码中提取函数列表"""
        functions = []
        pattern = r'(public\s+)?fun\s+(\w+)\s*[<\(]'

        for i, line in enumerate(code.split('\n'), 1):
            match = re.search(pattern, line)
            if match:
                functions.append({
                    'name': match.group(2),
                    'line': i,
                    'is_public': match.group(1) is not None,
                    'code': line.strip()
                })
        return functions

    def _find_location(self, code: str, match: PatternMatch, functions: List[Dict]) -> Optional[Dict]:
        """根据匹配结果找到代码中的具体位置"""
        result = {}
        code_lines = code.split('\n')

        # 0. 首先尝试从标题/描述中提取函数名，优先定位到函数
        description = getattr(match, 'description', '') or ''
        title_lower = match.title.lower()
        desc_lower = description.lower()

        # 检查是否有函数名在标题或描述中被提及
        for func in functions:
            func_name = func['name'].lower()
            if func_name in title_lower or func_name in desc_lower:
                result['function'] = func['name']
                result['line'] = func['line']
                result['code_snippet'] = func['code']
                result['code_context'] = self._extract_code_context(code, func['line'])
                return result  # 直接返回函数位置

        # 如果有行号提示，直接使用
        if match.line_hints:
            line_num = match.line_hints[0]
            if 0 < line_num <= len(code_lines):
                result['line'] = line_num
                result['code_snippet'] = code_lines[line_num - 1].strip()
                result['code_context'] = self._extract_code_context(code, line_num)

        # 尝试通过 matched_cues 找到位置
        if not result:
            # 优先选择在函数内部的匹配，而不是 struct 定义
            candidates = []
            for cue in match.matched_cues:
                if cue == "semantic_match":
                    continue
                for i, line in enumerate(code_lines, 1):
                    if cue.lower() in line.lower():
                        # 检查是否在 struct 定义中（跳过 struct 字段）
                        is_in_struct = self._is_in_struct_definition(code_lines, i)
                        # 找到包含这行的函数
                        containing_func = None
                        for func in reversed(functions):
                            if func['line'] <= i:
                                containing_func = func['name']
                                break

                        candidates.append({
                            'line': i,
                            'code_snippet': line.strip(),
                            'function': containing_func,
                            'is_in_struct': is_in_struct,
                            'priority': 0 if is_in_struct else (2 if containing_func else 1)
                        })

            # 按优先级排序：函数内部 > 模块级 > struct 内部
            if candidates:
                candidates.sort(key=lambda x: x['priority'], reverse=True)
                best = candidates[0]
                result['line'] = best['line']
                result['code_snippet'] = best['code_snippet']
                result['code_context'] = self._extract_code_context(code, best['line'])
                if best['function']:
                    result['function'] = best['function']

        # 如果还没找到函数，尝试匹配标题中的函数名
        if not result.get('function'):
            for func in functions:
                if func['name'].lower() in match.title.lower():
                    result['function'] = func['name']
                    if not result.get('line'):
                        result['line'] = func['line']
                        result['code_snippet'] = func['code']
                        result['code_context'] = self._extract_code_context(code, func['line'])
                    break

        return result if result else None

    def _is_in_struct_definition(self, code_lines: List[str], line_num: int) -> bool:
        """检查某行是否在 struct 定义内部"""
        # 向上查找，看是否在 struct {...} 块内
        brace_count = 0
        for i in range(line_num - 1, -1, -1):
            line = code_lines[i]
            brace_count += line.count('}') - line.count('{')
            if 'struct ' in line and '{' in line:
                # 找到了 struct 定义的开始
                if brace_count <= 0:
                    return True
                break
            if 'fun ' in line or 'public fun ' in line:
                # 在函数内，不是 struct
                return False
        return False

    def _extract_code_context(self, code: str, line: int, context_lines: int = 3) -> str:
        """
        提取指定行的前后上下文

        Args:
            code: 完整代码
            line: 目标行号 (1-based)
            context_lines: 前后各取几行 (默认3)

        Returns:
            带行号的代码片段，目标行用 → 标记
        """
        lines = code.split('\n')
        start = max(0, line - 1 - context_lines)
        end = min(len(lines), line + context_lines)

        result = []
        for i in range(start, end):
            line_num = i + 1
            prefix = "→ " if line_num == line else "  "  # 标记目标行
            result.append(f"{line_num:4d} {prefix}{lines[i]}")

        return '\n'.join(result)

    def generate_report_file(
        self,
        code: str,
        report: ScanReport,
        output_dir: str = "reports/security_audits",
        source_tag: Optional[str] = None,
        module_name: Optional[str] = None,
    ) -> str:
        """
        生成 Markdown 格式的安全审计报告文件

        Args:
            code: 源代码
            report: 扫描报告
            output_dir: 输出目录
            source_tag: 领域标签
            module_name: 模块名 (可选，自动提取)

        Returns:
            生成的报告文件路径
        """
        # 确保输出目录存在
        base_dir = Path(__file__).resolve().parents[2]
        output_path = base_dir / output_dir
        output_path.mkdir(parents=True, exist_ok=True)

        # 提取模块名
        if not module_name:
            module_name = self._extract_module_name(code) or "unknown"

        # 提取函数列表
        functions = self._extract_functions(code)

        # 生成时间戳和文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_module_name = module_name.replace("::", "_").replace("/", "_")
        filename = f"{safe_module_name}_{timestamp}.md"
        filepath = output_path / filename

        # 准备模板数据
        severity_emoji = {
            "critical": "🔴", "high": "🟠", "medium": "🟡",
            "low": "🟢", "advisory": "🔵"
        }

        # 统计严重性分布
        severity_dist = {}
        for m in report.matches:
            severity_dist[m.severity] = severity_dist.get(m.severity, 0) + 1

        # 处理每个发现项
        findings = []
        sorted_matches = sorted(
            report.matches,
            key=lambda m: SEVERITY_WEIGHTS.get(m.severity, 0),
            reverse=True
        )

        for m in sorted_matches:
            location = self._find_location(code, m, functions)
            findings.append({
                "pattern_id": m.pattern_id,
                "title": m.title,
                "severity": m.severity,
                "severity_emoji": severity_emoji.get(m.severity, "⚪"),
                "confidence": int(m.confidence * 100),
                "tags": m.issue_tags,
                "module": module_name,
                "function": location.get('function') if location else None,
                "line": location.get('line') if location else None,
                "code_context": location.get('code_context', '') if location else '',
                "recommendation": m.recommendation,
                "suggested_checks": m.suggested_checks,
            })

        # 尝试使用 Jinja2 模板
        template_path = base_dir / "templates" / "security_report.md.j2"
        if JINJA2_AVAILABLE and template_path.exists():
            env = Environment(loader=FileSystemLoader(str(base_dir / "templates")))
            template = env.get_template("security_report.md.j2")
            content = template.render(
                module_name=module_name,
                domain_tag=source_tag or "general",
                risk_score=report.risk_score,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_issues=len(report.matches),
                severity_dist=severity_dist,
                severity_emoji=severity_emoji,
                findings=findings,
            )
        else:
            # 降级：手动生成 Markdown
            content = self._generate_markdown_report(
                module_name=module_name,
                source_tag=source_tag,
                report=report,
                findings=findings,
                severity_dist=severity_dist,
                severity_emoji=severity_emoji,
            )

        # 写入文件
        filepath.write_text(content, encoding="utf-8")
        return str(filepath)

    def _generate_markdown_report(
        self,
        module_name: str,
        source_tag: Optional[str],
        report: ScanReport,
        findings: List[Dict],
        severity_dist: Dict[str, int],
        severity_emoji: Dict[str, str],
    ) -> str:
        """手动生成 Markdown 报告 (降级方案)"""
        lines = [
            "# Security Audit Report",
            "",
            "## Overview",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Module** | `{module_name}` |",
            f"| **Domain** | {source_tag or 'general'} |",
            f"| **Risk Score** | {report.risk_score}/100 |",
            f"| **Scan Time** | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |",
            f"| **Issues Found** | {len(report.matches)} |",
            "",
            "## Severity Distribution",
            "",
        ]

        for sev in ["critical", "high", "medium", "low", "advisory"]:
            if sev in severity_dist:
                lines.append(f"- {severity_emoji.get(sev, '⚪')} **{sev.upper()}**: {severity_dist[sev]}")

        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Findings")
        lines.append("")

        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. {f['severity_emoji']} [{f['severity'].upper()}] {f['title']}")
            lines.append("")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append(f"| **ID** | `{f['pattern_id']}` |")
            lines.append(f"| **Confidence** | {f['confidence']}% |")
            tags_str = ', '.join(f['tags']) if f['tags'] else 'N/A'
            lines.append(f"| **Tags** | {tags_str} |")
            lines.append("")
            lines.append("#### Location")
            lines.append("")
            lines.append(f"- **Module**: `{f['module']}`")
            lines.append(f"- **Function**: `{f['function'] or 'N/A'}`")
            lines.append(f"- **Line**: {f['line'] or 'N/A'}")
            lines.append("")
            lines.append("#### Code Context")
            lines.append("")
            lines.append("```move")
            lines.append(f['code_context'] if f['code_context'] else '(Unable to extract context)')
            lines.append("```")
            lines.append("")
            lines.append("#### Recommendation")
            lines.append("")
            lines.append(f"{f['recommendation']}")
            lines.append("")
            if f['suggested_checks']:
                lines.append("#### Suggested Spec Checks")
                lines.append("")
                for check in f['suggested_checks']:
                    lines.append(f"- `{check}`")
                lines.append("")
            lines.append("---")
            lines.append("")

        lines.append("## Disclaimer")
        lines.append("")
        lines.append("> Formal verification passing does NOT guarantee security.")
        lines.append("> Please manually review all findings above.")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("*Generated by AutoSpec Security Scanner*")

        return "\n".join(lines)

    def generate_audit_package(
        self,
        code: str,
        report: "ScanReport",
        verified_spec: str,
        reviewed_report: Optional[object] = None,
        output_dir: str = "reports/security_audits",
        source_tag: Optional[str] = None,
        module_name: Optional[str] = None,
        verification_rounds: int = 0,
    ) -> str:
        """
        生成完整的审计包（目录），包含：
        1. security_report.md - 安全审计报告
        2. verified_spec.move - 形式化验证通过的代码

        Args:
            code: 原始代码
            report: 扫描报告
            verified_spec: 形式化验证通过的代码
            reviewed_report: 审核后的报告 (可选，包含覆盖分析)
            output_dir: 输出根目录
            source_tag: 领域标签
            module_name: 模块名
            verification_rounds: 验证轮次

        Returns:
            生成的审计包目录路径
        """
        # 确保输出目录存在
        base_dir = Path(__file__).resolve().parents[2]
        audits_base = base_dir / output_dir

        # 提取模块名
        if not module_name:
            module_name = self._extract_module_name(code) or "unknown"

        # 生成时间戳和目录名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_module_name = module_name.replace("::", "_").replace("/", "_")
        package_name = f"{safe_module_name}_{timestamp}"
        package_path = audits_base / package_name
        package_path.mkdir(parents=True, exist_ok=True)

        # 1. 保存形式化验证代码
        spec_file = package_path / "verified_spec.move"
        spec_file.write_text(verified_spec, encoding="utf-8")

        # 2. 生成增强版审计报告
        report_content = self._generate_enhanced_report(
            code=code,
            report=report,
            verified_spec=verified_spec,
            reviewed_report=reviewed_report,
            module_name=module_name,
            source_tag=source_tag,
            verification_rounds=verification_rounds,
        )
        report_file = package_path / "security_report.md"
        report_file.write_text(report_content, encoding="utf-8")

        return str(package_path)

    def _generate_enhanced_report(
        self,
        code: str,
        report: "ScanReport",
        verified_spec: str,
        reviewed_report: Optional[object],
        module_name: str,
        source_tag: Optional[str],
        verification_rounds: int,
    ) -> str:
        """生成增强版审计报告（包含覆盖分析）"""

        severity_emoji = {
            "critical": "🔴", "high": "🟠", "medium": "🟡",
            "low": "🟢", "advisory": "🔵"
        }

        # 统计严重性分布
        severity_dist = {}
        for m in report.matches:
            severity_dist[m.severity] = severity_dist.get(m.severity, 0) + 1

        # 提取函数列表
        functions = self._extract_functions(code)

        # 提取spec函数
        spec_functions = []
        if verified_spec:
            patterns = [
                r'fun\s+(\w+_spec)\s*[<(]',
                r'spec\s+fun\s+(\w+)',
            ]
            for pattern in patterns:
                matches = re.findall(pattern, verified_spec)
                spec_functions.extend(matches)
            spec_functions = list(set(spec_functions))

        # 获取覆盖信息
        coverage_summary = None
        fully_covered = []
        partially_covered = []
        not_covered = []
        adjusted_risk_score = report.risk_score

        if reviewed_report and hasattr(reviewed_report, 'get_coverage_summary'):
            coverage_summary = reviewed_report.get_coverage_summary()
            adjusted_risk_score = reviewed_report.get_filtered_risk_score()
            fully_covered = getattr(reviewed_report, 'fully_covered', [])
            partially_covered = getattr(reviewed_report, 'partially_covered', [])
            not_covered = getattr(reviewed_report, 'not_covered', [])

        # 预先过滤无法定位的漏洞（partially_covered 和 not_covered）
        valid_not_covered_count = 0
        valid_partial_count = 0

        def _has_valid_location(match) -> bool:
            """检查漏洞是否有有效的代码位置"""
            loc = self._find_location(code, match, functions)
            return (
                loc and
                loc.get('line', 0) > 1 and
                loc.get('code_context') and
                'module ' not in loc.get('code_context', '').split('\n')[0]
            )

        if partially_covered:
            for r in partially_covered:
                if _has_valid_location(r.original_match):
                    valid_partial_count += 1

        if not_covered:
            for r in not_covered:
                if _has_valid_location(r.original_match):
                    valid_not_covered_count += 1

        # 计算实际有效的漏洞数量
        actual_issues = len(fully_covered) + valid_partial_count + valid_not_covered_count

        # 使用过滤后的实际漏洞数量
        issues_display = actual_issues if coverage_summary else len(report.matches)

        # 计算风险等级
        def get_risk_level(score: int) -> str:
            if score >= 80:
                return "🔴 Critical"
            elif score >= 60:
                return "🟠 High"
            elif score >= 40:
                return "🟡 Medium"
            elif score >= 20:
                return "🟢 Low"
            else:
                return "✅ Minimal"

        risk_level = get_risk_level(adjusted_risk_score)

        lines = [
            "# Security Audit Report",
            "",
            "## 📋 Overview",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Module** | `{module_name}` |",
            f"| **Domain** | {source_tag or 'general'} |",
            f"| **Risk Level** | {risk_level} ({adjusted_risk_score}/100) |",
            f"| **Verification Rounds** | {verification_rounds} |",
            f"| **Scan Time** | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |",
            f"| **Valid Issues** | {issues_display} |",
            "",
        ]

        # 严重性分布 (只统计有效漏洞)
        if coverage_summary:
            # 重新计算只包含有效漏洞的严重性分布
            valid_severity_dist = {}
            for r in fully_covered:
                sev = r.original_match.severity
                valid_severity_dist[sev] = valid_severity_dist.get(sev, 0) + 1
            # 对于 partially_covered，只计入有效位置的
            for r in partially_covered:
                if _has_valid_location(r.original_match):
                    sev = r.original_match.severity
                    valid_severity_dist[sev] = valid_severity_dist.get(sev, 0) + 1
            # 对于 not_covered，只计入有效位置的
            for r in not_covered:
                if _has_valid_location(r.original_match):
                    sev = r.original_match.severity
                    valid_severity_dist[sev] = valid_severity_dist.get(sev, 0) + 1
            severity_dist = valid_severity_dist

        lines.append("## 📊 Severity Distribution")
        lines.append("")
        for sev in ["critical", "high", "medium", "low", "advisory"]:
            if sev in severity_dist:
                lines.append(f"- {severity_emoji.get(sev, '⚪')} **{sev.upper()}**: {severity_dist[sev]}")
        lines.append("")

        # 形式化验证摘要
        lines.append("---")
        lines.append("")
        lines.append("## ✅ Formal Verification Summary")
        lines.append("")
        lines.append(f"**Status**: {'✅ PASSED' if verified_spec else '❌ FAILED'}")
        lines.append(f"**Rounds to Pass**: {verification_rounds}")
        lines.append("")
        if spec_functions:
            lines.append("**Verified Spec Functions**:")
            for func in spec_functions:
                lines.append(f"- `{func}`")
            lines.append("")
        lines.append("> 📁 See `verified_spec.move` for the complete verified specification code.")
        lines.append("")

        # Spec覆盖分析
        if coverage_summary:
            lines.append("---")
            lines.append("")
            lines.append("## 🛡️ Spec Coverage Analysis")
            lines.append("")
            lines.append("| Coverage Status | Count | Risk Impact |")
            lines.append("|-----------------|-------|-------------|")
            lines.append(f"| ✅ Fully Covered | {len(fully_covered)} | -90% risk |")
            lines.append(f"| 🔶 Partially Covered | {valid_partial_count} | -50% risk |")
            lines.append(f"| ❌ Not Covered | {valid_not_covered_count} | Full risk |")
            lines.append("")

            # 风险评分明细
            lines.append("### 📊 Risk Score Breakdown")
            lines.append("")
            lines.append("| Vulnerability | Severity | Base Score | Coverage | Final Score |")
            lines.append("|--------------|----------|------------|----------|-------------|")

            # 计算每个漏洞的分数
            severity_base = {"critical": 40, "high": 25, "medium": 15, "low": 8, "advisory": 4}

            for r in fully_covered:
                m = r.original_match
                base = severity_base.get(m.severity, 10)
                final = int(base * 0.1)  # -90%
                lines.append(f"| {m.title[:35]}{'...' if len(m.title) > 35 else ''} | {m.severity.upper()} | {base} | ✅ -90% | {final} |")

            for r in partially_covered:
                m = r.original_match
                if _has_valid_location(m):
                    base = severity_base.get(m.severity, 10)
                    final = int(base * 0.5)  # -50%
                    lines.append(f"| {m.title[:35]}{'...' if len(m.title) > 35 else ''} | {m.severity.upper()} | {base} | 🔶 -50% | {final} |")

            for r in not_covered:
                m = r.original_match
                if _has_valid_location(m):
                    base = severity_base.get(m.severity, 10)
                    lines.append(f"| {m.title[:35]}{'...' if len(m.title) > 35 else ''} | {m.severity.upper()} | {base} | ❌ 0% | {base} |")

            lines.append("")
            lines.append(f"**Total Risk Score: {adjusted_risk_score}/100** ({risk_level})")
            lines.append("")
            lines.append("> 💡 Scoring: CRITICAL=40, HIGH=25, MEDIUM=15, LOW=8, ADVISORY=4. Covered by spec reduces risk.")
            lines.append("")

            # 详细覆盖分析
            if fully_covered:
                lines.append("### ✅ Fully Covered by Spec")
                lines.append("")
                lines.append("> These vulnerabilities are addressed by the verified specification.")
                lines.append("")
                for r in fully_covered:
                    m = r.original_match
                    coverage = r.spec_coverage
                    lines.append(f"**{m.pattern_id}: {m.title}**")
                    lines.append(f"- Severity: {severity_emoji.get(m.severity, '⚪')} {m.severity.upper()}")
                    if coverage and coverage.coverage_evidence != "None":
                        lines.append(f"- Evidence: `{coverage.coverage_evidence[:100]}`")
                    lines.append("")

            # Partially Covered - 同样过滤无效位置
            if partially_covered:
                valid_partial = []
                partial_skipped = 0
                for r in partially_covered:
                    m = r.original_match
                    location = self._find_location(code, m, functions)
                    has_valid_location = (
                        location and
                        location.get('line', 0) > 1 and
                        location.get('code_context') and
                        'module ' not in location.get('code_context', '').split('\n')[0]
                    )
                    if has_valid_location:
                        valid_partial.append((r, location))
                    else:
                        partial_skipped += 1

                if valid_partial:
                    lines.append("### 🔶 Partially Covered by Spec")
                    lines.append("")
                    lines.append("> These vulnerabilities are partially addressed. Manual review recommended.")
                    lines.append("")

                    for r, location in valid_partial:
                        m = r.original_match
                        coverage = r.spec_coverage

                        lines.append(f"#### {m.pattern_id}: {m.title}")
                        lines.append("")
                        lines.append(f"| Field | Value |")
                        lines.append(f"|-------|-------|")
                        lines.append(f"| Severity | {severity_emoji.get(m.severity, '⚪')} {m.severity.upper()} |")
                        lines.append(f"| Line | {location.get('line')} |")
                        lines.append("")
                        lines.append("**Code Context**:")
                        lines.append("```move")
                        lines.append(location['code_context'])
                        lines.append("```")
                        lines.append("")

                        # 风险分析
                        desc = getattr(m, 'description', None) or ""
                        if desc and desc.strip():
                            lines.append("**Risk Analysis**:")
                            lines.append(f"> {desc[:500]}")
                            lines.append("")

                        # Spec 覆盖说明
                        if coverage:
                            lines.append(f"**Spec Coverage**: {coverage.explanation}")
                            if coverage.coverage_evidence and coverage.coverage_evidence != "None":
                                lines.append(f"- Evidence: `{coverage.coverage_evidence[:100]}`")
                        lines.append("")

                        # 修复建议
                        if m.recommendation:
                            lines.append("**Recommendation**:")
                            lines.append(f"> {m.recommendation}")
                            lines.append("")

                if partial_skipped > 0:
                    lines.append(f"> ℹ️ {partial_skipped} partially covered findings were filtered out (could not locate in code).")
                    lines.append("")

            if not_covered:
                # 过滤掉无法定位到代码的漏洞
                valid_not_covered = []
                skipped_count = 0
                for r in not_covered:
                    m = r.original_match
                    location = self._find_location(code, m, functions)

                    # 检查位置是否有效（line > 1 且不是指向模块声明）
                    has_valid_location = (
                        location and
                        location.get('line', 0) > 1 and
                        location.get('code_context') and
                        'module ' not in location.get('code_context', '').split('\n')[0]
                    )

                    if has_valid_location:
                        valid_not_covered.append((r, location))
                    else:
                        skipped_count += 1

                if valid_not_covered:
                    lines.append("### ❌ Not Covered by Spec (Remaining Risks)")
                    lines.append("")
                    lines.append("> ⚠️ These vulnerabilities are NOT addressed by the specification. Manual review required!")
                    lines.append("")

                    for r, location in valid_not_covered:
                        m = r.original_match
                        coverage = r.spec_coverage

                        lines.append(f"#### {m.pattern_id}: {m.title}")
                        lines.append("")
                        lines.append(f"| Field | Value |")
                        lines.append(f"|-------|-------|")
                        lines.append(f"| Severity | {severity_emoji.get(m.severity, '⚪')} {m.severity.upper()} |")
                        lines.append(f"| Line | {location.get('line')} |")
                        lines.append("")
                        lines.append("**Code Context**:")
                        lines.append("```move")
                        lines.append(location['code_context'])
                        lines.append("```")
                        lines.append("")

                        # 风险分析 - 解释为什么这是一个风险
                        desc = getattr(m, 'description', None) or ""
                        if desc and desc.strip():
                            lines.append("**Risk Analysis**:")
                            lines.append(f"> {desc[:500]}")
                            lines.append("")

                        # 修复建议
                        if m.recommendation:
                            lines.append("**Recommendation**:")
                            lines.append(f"> {m.recommendation}")
                            lines.append("")

                        if m.suggested_checks:
                            lines.append("**Suggested Spec Checks**:")
                            for check in m.suggested_checks:
                                lines.append(f"- `{check}`")
                            lines.append("")

                if skipped_count > 0:
                    lines.append(f"> ℹ️ {skipped_count} findings were filtered out (could not locate in code).")
                    lines.append("")
        else:
            # 没有覆盖分析，使用原始findings
            lines.append("---")
            lines.append("")
            lines.append("## ⚠️ Findings")
            lines.append("")

            sorted_matches = sorted(
                report.matches,
                key=lambda m: SEVERITY_WEIGHTS.get(m.severity, 0),
                reverse=True
            )

            for i, m in enumerate(sorted_matches, 1):
                location = self._find_location(code, m, functions)
                lines.append(f"### {i}. {severity_emoji.get(m.severity, '⚪')} [{m.severity.upper()}] {m.title}")
                lines.append("")
                lines.append(f"| Field | Value |")
                lines.append(f"|-------|-------|")
                lines.append(f"| ID | `{m.pattern_id}` |")
                lines.append(f"| Confidence | {int(m.confidence * 100)}% |")
                if location:
                    lines.append(f"| Line | {location.get('line', 'N/A')} |")
                lines.append("")
                if location and location.get('code_context'):
                    lines.append("**Code Context**:")
                    lines.append("```move")
                    lines.append(location['code_context'])
                    lines.append("```")
                    lines.append("")
                lines.append(f"**Recommendation**: {m.recommendation}")
                lines.append("")
                lines.append("---")
                lines.append("")

        # Disclaimer
        lines.append("---")
        lines.append("")
        lines.append("## ⚠️ Disclaimer")
        lines.append("")
        lines.append("> Formal verification passing does NOT guarantee complete security.")
        lines.append("> - **Fully Covered** issues have specification guards but may have implementation gaps.")
        lines.append("> - **Not Covered** issues require additional specification or manual code review.")
        lines.append("> - Always perform comprehensive security audits before production deployment.")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("*Generated by AutoSpec Security Scanner*")

        return "\n".join(lines)


# ==============================================================================
# 便捷函数 (向后兼容)
# ==============================================================================

def load_patterns(dataset_path: Optional[str] = None) -> List[Dict]:
    """加载外部模式 (向后兼容)"""
    default_path = Path(__file__).resolve().parents[2] / "reports" / "datasets" / "security_patterns.jsonl"
    path = Path(dataset_path) if dataset_path else default_path
    if not path.exists():
        return []
    patterns: List[Dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                patterns.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return patterns


def scan_code_for_patterns(
    code: str,
    patterns: List[Dict],
    module_hint: Optional[str] = None,
    function_hint: Optional[str] = None,
) -> List[Dict]:
    """基于简单关键词/函数名 cue 的匹配 (向后兼容)"""
    results: List[Dict] = []
    code_lower = code.lower()
    for p in patterns:
        cues = p.get("detection_cues") or []
        matched = False

        if module_hint and p.get("module_path") and module_hint in str(p.get("module_path")):
            matched = True
        if function_hint and p.get("function") and function_hint in str(p.get("function")):
            matched = True

        for cue in cues:
            cue_l = str(cue).lower()
            if cue_l and cue_l in code_lower:
                matched = True
                break

        if matched:
            results.append({
                "id": p.get("id"),
                "title": p.get("title"),
                "severity": p.get("severity"),
                "issue_tags": p.get("issue_tags"),
                "recommendation": p.get("recommendation"),
            })
    return results
