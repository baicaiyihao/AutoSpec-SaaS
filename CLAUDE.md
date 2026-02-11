# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AutoSpec is an automated formal verification framework for Sui Move smart contracts. It uses LLMs (primarily Qwen/DeepSeek via Alibaba DashScope API) to automatically generate, run, and fix Move Spec verification code until it passes `sui-prover`.

## Commands

### Running Verification Tests
```bash
# Run a specific test example
python src/examples/test_flash_loan.py
python src/examples/test_amm.py
python src/examples/test_cetus_clmm.py

# One-click audit (auto-scan, generate plan, run verification)
python -m src.cli.audit --project /path/to/move-project

# Run the main entry point
python src/main.py
```

### Building the RAG Vector Database
```bash
python -m src.rag.build_vector_db
```

### Building Call Graph
```bash
python -m src.context.callgraph \
    --root cetus-contracts/sources \
    --out data/callgraph/cetus.json
```

### Extracting Security Patterns from Audit Reports
```bash
python -m src.rag.extract_security_patterns \
    --input data/knowledge_base/security \
    --out reports/datasets/security_patterns.jsonl
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Prerequisites
- `sui-prover` must be installed and available in PATH
- `DASHSCOPE_API_KEY` environment variable must be set (Alibaba Cloud Tongyi API key)

## Architecture

### Directory Structure

```
src/
├── prover/                      # Formal verification modules
│   ├── auto_loop.py             # Main verification loop
│   ├── council.py               # Spec generation session
│   ├── executor.py              # sui-prover executor
│   ├── generator.py             # Spec code generation
│   ├── learner.py               # Rule learning
│   ├── memorizer.py             # Success case storage
│   ├── spec_merger.py           # Spec merging
│   ├── verification_tracker.py  # Verification status tracking
│   ├── error_classifier.py      # Error classification
│   └── failure_handler.py       # Failure handling strategies
│
├── context/                     # Code context understanding (shared)
│   ├── callgraph.py             # Call graph construction
│   ├── dependency_resolver.py   # External dependency resolution
│   └── semantic_analyzer.py     # Semantic analysis & constraint extraction
│
├── security/                    # Security audit modules
│   ├── pattern_scan.py          # Vulnerability pattern scanning
│   ├── security_reviewer.py     # Security review (false positive filtering)
│   └── exploit_analyzer.py      # Exploit chain analysis
│
├── agents/                      # Multi-agent system
│   ├── base_agent.py            # Base agent class
│   ├── engine.py                # Agent orchestration engine
│   ├── manager_agent.py         # Audit manager
│   ├── analyst_agent.py         # Code analyst
│   ├── auditor_agent.py         # Security auditor (Phase 2 scanning)
│   ├── expert_agent.py          # Domain expert (legacy 5-agent)
│   ├── verifier_agent.py        # 🔥 v2.5.3: Unified verifier (replaces auditor+expert+analyst in Phase 3)
│   ├── white_hat_agent.py       # Exploit verification (Phase 4)
│   ├── role_swap.py             # Original 5-agent role swap mechanism
│   ├── role_swap_v2.py          # 🔥 v2.5.3: Simplified 3-agent role swap
│   └── tools.py                 # Agent toolkit for code retrieval
│
├── modules/                     # Infrastructure
│   ├── model_factory.py         # LLM model factory
│   ├── llm_providers.py         # LLM provider implementations
│   └── project_builder.py       # Temp project builder
│
├── prompts/                     # Prompt templates
├── rag/                         # RAG vector database
├── cli/                         # CLI tools
├── examples/                    # Test examples
└── config.py                    # Configuration (paths, model presets)
```

### Core Loop (`src/prover/auto_loop.py`)
The `auto_prove_task()` function orchestrates the verification cycle:
1. **Source Code Extraction**: `_extract_source_code()` extracts original business code from prompt (separate from generated spec)
2. **Dataset Availability Check**: `_check_pattern_scan_available()` auto-disables scanning if no dataset/vector store found
3. **Security Scan**: `SecurityScanner` checks **original source code** against known vulnerability patterns
4. **Tag Detection**: Automatically identifies code domain (amm, lending, nft, etc.) via `Memorizer.predict_dominant_tag()`
5. **Initial Draft**: `CodeCouncil` generates spec code with security warnings injected
6. **Verification Loop** (max 15 retries):
   - `LocalExecutor` saves code and runs `sui-prover`
   - On failure: error logs feed back to `CodeCouncil` for repair
   - Round 4+: DeepSeek model takes over in "Rescue Mode"
7. **Success**: Code is stored in vector DB; `LearnerAgent` extracts reusable rules; final security scan runs on **original source code** with spec coverage analysis

### Formal Verification (`src/prover/`)

| Module | Role |
|--------|------|
| `auto_loop.py` | Main verification loop orchestrating all components |
| `council.py` | Orchestrates LLM sessions; switches between Advisor Mode (round 1-3) and Rescue Mode (round 4+) |
| `executor.py` | Manages temp Move project in `temp_move_project/`, runs `sui-prover` with 120s timeout |
| `memorizer.py` | ChromaDB-backed vector store for successful specs; handles chunking and semantic retrieval |
| `learner.py` | Post-mortem analysis using git-style diffs; saves learned rules to `data/learned_rules.json` |
| `generator.py` | Wraps Qwen model with prompt template and code cleaning |
| `verification_tracker.py` | Tracks function-level verification status |
| `error_classifier.py` | Classifies prover errors for targeted repair |
| `failure_handler.py` | Handles verification failures with degradation strategies |

### Code Context Understanding (`src/context/`)

| Module | Role |
|--------|------|
| `callgraph.py` | Builds function-level call graphs with risk indicators |
| `dependency_resolver.py` | Resolves external Move dependencies from `~/.move` cache |
| `semantic_analyzer.py` | Extracts function constraints, preconditions, and postconditions |

**Shared by both verification and security audit** - provides:
- Function neighbor context for spec generation
- Vulnerability propagation path analysis for security audit

### Security Audit (`src/security/`)

| Module | Role |
|--------|------|
| `pattern_scan.py` | `SecurityScanner` class with builtin rules + vector search + external JSONL patterns |
| `security_reviewer.py` | Multi-agent review: filters false positives + analyzes spec coverage |
| `exploit_analyzer.py` | Analyzes exploit chains: entry point → attack path → impact |

**Two-Layer False Positive Filtering:**
1. **Pre-filter (Simple Index)**: Extracts identifiers from vulnerability description (e.g., `set_flash_loan_fee`), checks if they exist in code. If 70%+ missing → likely false positive.
2. **Agent Review (DeepSeek)**: Smart prompt distinguishes behavior vs function names. If behavior matches (e.g., "no refund" in `repay` function), confirms even with different function names.

**Spec Coverage Analysis:**
After formal verification passes, analyzes each vulnerability against the verified spec:
- `fully_covered`: Spec has explicit requires/ensures addressing the issue (-90% risk)
- `partially_covered`: Spec addresses some aspects (-50% risk)
- `not_covered`: Spec does NOT address this vulnerability (full risk)

### Multi-Agent System (`src/agents/`)

**v2.5.3 introduces a simplified 3-agent architecture** that reduces token consumption by ~68%.

#### Agent Architecture Comparison

| Architecture | Phase 3 Agents | LLM Calls per Vuln | Token Savings |
|--------------|----------------|-------------------|---------------|
| **3-Agent (v2.5.3, default)** | Verifier → Manager (optional) | 1-2 | ~68% |
| **5-Agent (legacy)** | Auditor → Expert → Analyst → Manager | 4 | baseline |

#### 3-Agent Architecture (Default)

```
Phase 2 (Scan)      Phase 3 (Verify)      Phase 4 (Exploit)
┌──────────┐        ┌──────────┐          ┌──────────┐
│ Auditor  │───────▶│ Verifier │─────────▶│ WhiteHat │
│ (scan)   │        │(3-view)  │          │ (PoC)    │
└──────────┘        └────┬─────┘          └──────────┘
                         │
                         ▼ (confidence < 80%)
                    ┌──────────┐
                    │ Manager  │
                    │(optional)│
                    └──────────┘
```

- **Auditor**: Phase 2 vulnerability scanning (unchanged)
- **Verifier**: Combines 3 verification perspectives in ONE LLM call:
  - Security Auditor view: Known vulnerability patterns, best practices
  - Move Expert view: Type system protections, Sui object model
  - Business Analyst view: Attack economics, realistic scenarios
- **Manager**: Only intervenes when Verifier confidence < 80% or conclusion unclear
- **WhiteHat**: Phase 4 exploit chain verification (only for HIGH/CRITICAL)

#### Configuration

```python
from src.agents import SecurityAuditEngine, AuditConfig

# Use simplified 3-agent architecture (default, recommended)
config = AuditConfig(use_simplified_architecture=True)

# Use legacy 5-agent architecture
config = AuditConfig(use_simplified_architecture=False)
```

#### Key Files

| File | Role |
|------|------|
| `verifier_agent.py` | Unified multi-perspective verifier |
| `role_swap_v2.py` | Simplified verification flow (Verifier → Manager) |
| `role_swap.py` | Legacy 4-round verification flow |
| `engine.py` | Orchestration with architecture selection |

### Prompt Engineering (`src/prompts/`)
- `prove_templates.py`: Core prompt templates enforcing "Wrapper Procedure Verification" pattern
- `dynamic_rules.py`: Keyword-triggered hints (e.g., `*` triggers overflow warnings, `coin` triggers linearity rules)
- `security_prompts.py`: Security review prompts with smart false positive detection logic
- `exploit_prompts.py`: Exploit chain analysis prompts
- `sui_move_security_knowledge.py`: Sui Move security knowledge base for false positive filtering

### Verification Pattern
The system enforces **Wrapper Procedure Verification** style:
```move
#[spec(prove)]
fun calc_spec(a: u64, b: u64): u64 {
    requires((a as u128) * (b as u128) <= 18446744073709551615);
    let result = calc(a, b);
    ensures((result as u128) == (a as u128) * (b as u128));
    result
}
```

Key constraints:
- Never modify `public fun` implementations
- Capture state manually (no `old()` syntax)
- Cast to `u128` for overflow-prone arithmetic
- Handle linear resources (Coin, Receipt) by returning them

## Data Flow

```
Test Script (test_*.py)
    │
    ▼
auto_prove_task()
    │
    ├─► SecurityScanner.scan() ─► warnings injected to prompt
    │
    ├─► Memorizer.predict_dominant_tag() ─► source_tag
    │
    ├─► CodeCouncil.run_council_session() ─► initial spec
    │
    └─► Verification Loop:
            │
            ├─► LocalExecutor.save_code() + run_prove()
            │
            ├─► [Fail] CodeCouncil repairs with RAG + dynamic rules
            │
            └─► [Success] Memorizer.ingest_success_case()
                         LearnerAgent.learn_from_session()
                         SecurityScanner.scan() ─► final security report
```

**Return value**: `auto_prove_task()` returns `(success: bool, code: str, security_report: dict)`

## Configuration

Environment variables (via `.env`):
- `DASHSCOPE_API_KEY`: **Required** for core functionality (Alibaba Cloud Tongyi/DashScope API key)
- `ANTHROPIC_API_KEY`: Optional, for Claude models
- `OPENAI_API_KEY`: Optional, for GPT models
- `DEEPSEEK_API_KEY`: Optional, for DeepSeek models
- `ZHIPU_API_KEY`: Optional, for GLM models

**Model Configuration (`src/config.py`):**
```python
from src.config import get_agent_configs, print_available_providers

# Auto-detect available providers
configs = get_agent_configs("auto")

# Or use a preset
configs = get_agent_configs("china")  # DashScope + ZhipuAI
configs = get_agent_configs("claude")  # All Claude
configs = get_agent_configs("hybrid")  # Mixed providers
```

**Fail-Fast Dependency Validation:**

`auto_prove_task()` validates all dependencies at entry via `_validate_dependencies()`:
- ❌ **DASHSCOPE_API_KEY missing**: Throws `MissingDependencyError` immediately
- ❌ **pattern_scan=True but no dataset**: Throws `MissingDependencyError` with instructions
- This ensures clear error messages instead of mid-execution failures

| Component | Without API Key |
|-----------|-----------------|
| `auto_prove_task()` | ❌ Entry validation throws `MissingDependencyError` |
| `ModelFactory` | ❌ Throws `MissingAPIKeyError` |
| `GeneratorAgent` | ❌ Throws `ValueError` |
| `LearnerAgent` | ⚠️ Disabled, skips learning (non-critical) |
| `SecurityReviewer` | ❌ Never instantiated (blocked at entry) |

Paths (`src/config.py`):
- `VECTOR_DB_DIR`: `data/vector_store/`
- `TEMP_PROJECT_DIR`: `temp_move_project/` (cleaned on each run)
- `CALLGRAPH_DIR`: `data/callgraph/`
- `SECURITY_AUDITS_DIR`: `reports/security_audits/`

**Security Dataset Paths (auto-detected using BASE_DIR):**
- `{BASE_DIR}/reports/datasets/security_patterns.jsonl` (structured patterns)
- `{BASE_DIR}/data/vector_store/security_patterns/` (semantic search)

## Security Knowledge Base

Security patterns are stored in `reports/datasets/security_patterns.jsonl`. Each pattern contains:
- `id`: Unique identifier (e.g., "scallop-H-1")
- `severity`: critical/high/medium/low/advisory
- `issue_tags`: Categories like ["overflow", "access_control", "oracle"]
- `detection_cues`: Keywords/patterns to match in code
- `description`: Risk analysis explaining why the vulnerability is dangerous
- `recommendation`: Fix suggestion
- `suggested_checks`: Recommended spec assertions

Source audit reports are in `data/knowledge_base/security/`. Run extraction after adding new reports.

## Security Audit Report Generation

After successful verification, an audit package is generated in `reports/security_audits/{module}_{timestamp}/`:

```
reports/security_audits/temp_flash_lender_20251223_185228/
├── security_report.md    # Human-readable security audit report
└── verified_spec.move    # Formally verified spec code
```

**Report Structure:**
1. **Overview**: Module name, domain, risk level (Minimal/Low/Medium/High/Critical), verification rounds
2. **Severity Distribution**: Count of HIGH/MEDIUM/LOW/ADVISORY issues
3. **Formal Verification Summary**: Pass status, rounds needed, verified spec functions
4. **Spec Coverage Analysis**:
   - Risk Score Breakdown (per vulnerability)
   - Fully Covered / Partially Covered / Not Covered sections
5. **Not Covered Vulnerabilities**: Code context, risk analysis, recommendations

**Risk Score Calculation:**
- Base scores: CRITICAL=40, HIGH=25, MEDIUM=15, LOW=8, ADVISORY=4
- Fully covered by spec: -90% (multiply by 0.1)
- Partially covered: -50% (multiply by 0.5)
- Not covered: Full score

## Import Examples

```python
# Formal verification
from src.prover import auto_prove_task, CodeCouncil, LocalExecutor
from src.prover import Memorizer, LearnerAgent, VerificationTracker

# Code context understanding (shared by verification & audit)
from src.context import CallGraphBuilder, SemanticAnalyzer, DependencyResolver
from src.context import FunctionConstraints, FunctionNode

# Security audit
from src.security import SecurityScanner, SecurityReviewer, ExploitChainAnalyzer

# Multi-agent system (v2.5.3)
from src.agents import SecurityAuditEngine, AuditConfig, AuditResult
from src.agents import ManagerAgent, WhiteHatAgent, VerifierAgent  # 3-agent
from src.agents import AuditorAgent, MoveExpertAgent, AnalystAgent  # 5-agent (legacy)
from src.agents import RoleSwapMechanismV2, VerifiedFindingV2  # 3-agent verification
from src.agents import RoleSwapMechanism, VerifiedFinding  # 5-agent verification (legacy)

# Configuration
from src.config import get_agent_configs, MODEL_INFO, print_available_providers
```

## Important Notes for Development

### Running Tests
Always use conda environment:
```bash
source ~/.zshrc && conda activate crawl4ai && python src/examples/test_flash_loan.py
```

Logs are saved to `reports/security_audits/` directory.

### Key Files by Feature

**Formal Verification:**
- `src/prover/auto_loop.py`: Main verification loop
- `src/prover/council.py`: LLM session orchestration
- `src/prover/executor.py`: sui-prover execution

**Security Audit:**
- `src/security/pattern_scan.py`: SecurityScanner with `generate_audit_package()`, relevance filtering
- `src/security/security_reviewer.py`: Multi-agent review with SpecCoverage analysis
- `src/security/exploit_analyzer.py`: Exploit chain analysis
- `src/security/exclusion_rules.py`: 🔥 v2.5.8: Sui Move false positive exclusion rules (27+ rules, integrated with knowledge base)

**Code Understanding:**
- `src/context/callgraph.py`: Call graph with risk indicators
- `src/context/semantic_analyzer.py`: Constraint extraction for spec generation
- `src/context/dependency_resolver.py`: External dependency resolution

**Prompts:**
- `src/prompts/prove_templates.py`: Spec generation templates
- `src/prompts/security_prompts.py`: Security review prompts
- `src/prompts/exploit_prompts.py`: Exploit analysis prompts
- `src/prompts/sui_move_security_knowledge.py`: Sui Move security knowledge base

**Multi-Agent (v2.5.3):**
- `src/agents/verifier_agent.py`: Unified 3-perspective verifier
- `src/agents/role_swap_v2.py`: Simplified verification flow
- `src/agents/engine.py`: Architecture selection via `use_simplified_architecture`
- `src/agents/move_knowledge.py`: 🔥 v2.5.8: Move security knowledge for prompt injection (operators, bit_shift, reentrancy, etc.)

## Token Optimization (v2.5.3)

v2.5.3 introduces several optimizations to reduce LLM token consumption:

### 1. Simplified Agent Architecture
- **Before**: 4 LLM calls per vulnerability (Auditor → Expert → Analyst → Manager)
- **After**: 1-2 LLM calls per vulnerability (Verifier → Manager if needed)
- **Savings**: ~68% reduction in Phase 3 token usage

### 2. Knowledge Injection Optimization
- Security knowledge guides moved from LLM prompts to rule-based pre-filtering
- Knowledge is NOT injected in Phase 3/4 LLM calls
- Only used in Phase 2 exclusion rules (zero LLM tokens)

### 3. WhiteHat Severity Filter
- WhiteHat only processes HIGH/CRITICAL vulnerabilities
- MEDIUM/LOW/ADVISORY are skipped with `NEEDS_REVIEW` status
- Saves ~70% of Phase 4 token usage

### 4. Exclusion Rules Pre-Filter
27+ rules in `src/security/exclusion_rules.py` filter obvious false positives BEFORE LLM verification:
- Rules 1-6: Sui Move language protections (overflow, type safety, etc.)
- Rule 6b: 🔥 v2.5.8: Reentrancy attack immunity (Move has no dynamic dispatch)
- Rule 6c: 🔥 v2.5.8: Knowledge base integration (`is_likely_false_positive()`)
- Rules 7-12: Sui Move patterns (Capability ACL, public(package), shared objects, etc.)
- Rules 13-17: Non-security issues (constants, mock functions, getters, etc.)
- Rules 18-26: Production contract patterns (Cetus CLMM analysis)

**v2.5.8 Key Fix**: Rule 5 (`check_overflow_bypass`) now correctly excludes bit shift operations - Move bit shifts (<<, >>) do NOT abort on overflow (unlike arithmetic), which was the root cause of the 2025 Cetus $223M hack.

### Token Consumption Comparison

| Scenario (10 vulnerabilities) | v2.5.2 (5-Agent) | v2.5.3 (3-Agent) | Savings |
|------------------------------|------------------|------------------|---------|
| Phase 3 verification | 40 LLM calls | 10-13 calls | 68-75% |
| Phase 4 WhiteHat (3 HIGH/CRITICAL) | 10 calls | 3 calls | 70% |
| Knowledge injection per call | ~2K tokens | 0 tokens | 100% |
| **Total per audit** | ~120K tokens | ~35K tokens | **71%** |

## Documentation

| Document | Description |
|----------|-------------|
| `docs/PROJECT_WEBUI.md` | Web UI 架构文档 (v3.0 当前版本) |
| `docs/PROJECT_V3.1_ROADMAP.md` | v3.1 演进计划 (可配置规则库/团队协作/基准测试) |
| `docs/WEBUI_REVIEW_PLAN.md` | Web UI 实施计划 (已完成) |
| `docs/PROJECT_AUDIT_V2.md` | 审计系统技术文档 |

## Changelog

### v2.5.8 (Current)
- **Operator Confusion Fix**: Added `operators` knowledge topic to help Agent distinguish `<` (comparison) from `<<` (bit shift)
- **Bit Shift Overflow Awareness**: Updated `bit_shift` knowledge with Cetus $223M hack details - Move bit shifts do NOT abort on overflow
- **Rule 5 Fix**: `check_overflow_bypass` now excludes bit shift related findings (they ARE dangerous, unlike arithmetic overflow)
- **Rule 6b**: New `check_reentrancy_immunity` rule - auto-filters reentrancy attack false positives
- **Rule 6c**: New `check_move_language_protection` rule - integrates `sui_move_security_knowledge.py`'s `is_likely_false_positive()` function
- **Knowledge Base Integration**: `exclusion_rules.py` now imports and uses security knowledge base for systematic false positive detection

### v2.5.3
- **3-Agent Architecture**: Merged Auditor/Expert/Analyst into VerifierAgent
- **Token Optimization**: Removed knowledge injection from Phase 3/4 LLM calls
- **WhiteHat Filter**: Only processes HIGH/CRITICAL vulnerabilities
- **Exclusion Rules**: Extracted to separate module with 17 rules

### v2.5.2
- Added Sui Move security knowledge base
- Dynamic knowledge loading for agents

### v2.5.0
- Multi-agent security audit system
- RoleSwap mechanism for false positive reduction
- WhiteHat exploit chain verification
