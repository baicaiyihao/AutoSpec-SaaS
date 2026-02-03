"""
AuditorAgent - 安全审计员Agent

职责:
1. 检测常见漏洞模式(溢出、重入、权限等)
2. 分析DeFi特定风险(闪电贷、预言机、滑点)
3. 识别业务逻辑漏洞
4. 评估每个发现的严重性和可利用性
5. 提供漏洞证据和攻击路径
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent, AgentRole, AgentMessage, AgentConfig

# 🔥 v2.5.2: 动态加载 Sui Move 安全知识
try:
    from src.prompts.sui_move_security_knowledge import (
        get_auditor_context,
        get_false_positive_guide,
        PROTECTED_VULNERABILITY_TYPES,
    )
    SUI_SECURITY_KNOWLEDGE_AVAILABLE = True
except ImportError:
    SUI_SECURITY_KNOWLEDGE_AVAILABLE = False
    get_auditor_context = lambda: ""
    get_false_positive_guide = lambda: ""
    PROTECTED_VULNERABILITY_TYPES = {}


AUDITOR_ROLE_PROMPT = """你是一位专业的智能合约安全审计员。

## 你的职责
1. 检测常见漏洞模式(溢出、重入、权限等)
2. 分析DeFi特定风险(闪电贷、预言机、滑点)
3. 识别业务逻辑漏洞
4. 评估每个发现的严重性和可利用性
5. 提供漏洞证据和攻击路径

## 漏洞分类

### 算术安全
- 整数溢出/下溢
- 除零错误
- 精度损失

### 访问控制
- 缺少权限检查
- 权限提升
- 不当的可见性

### DeFi风险
- 闪电贷攻击
- 价格操纵
- 滑点攻击
- 三明治攻击
- 重入攻击

### Move/Sui特定
- 资源泄漏
- 对象所有权问题
- 动态字段滥用
- Hot Potato误用

## 严重性评估标准
- CRITICAL: 可直接窃取资金或接管合约
- HIGH: 可导致资金损失或严重功能破坏
- MEDIUM: 可导致功能异常或有条件的资金风险
- LOW: 代码质量问题，不直接导致安全风险
"""


@dataclass
class VulnerabilityFinding:
    """漏洞发现"""
    id: str
    title: str
    severity: str
    category: str
    location: Dict[str, Any]
    description: str
    evidence: str
    attack_vector: str
    recommendation: str
    confidence: int


class AuditorAgent(BaseAgent):
    """安全审计员Agent"""

    def __init__(self, config: Optional[AgentConfig] = None):
        super().__init__(
            role=AgentRole.AUDITOR,
            role_prompt=AUDITOR_ROLE_PROMPT,
            config=config
        )
        # 🔥 v2.5.2: 缓存安全知识，避免重复加载
        self._security_context_cache = None

    def _get_security_context(self, compact: bool = False) -> str:
        """
        🔥 v2.5.2: 获取 Sui Move 安全知识上下文

        Args:
            compact: 是否使用紧凑版本 (用于单函数分析，减少 token)

        Returns:
            安全知识上下文字符串
        """
        if not SUI_SECURITY_KNOWLEDGE_AVAILABLE:
            return ""

        if compact:
            # 紧凑版本: 只包含误报判断指南
            return f"""
## 🔥 Sui Move 安全知识 (请在审计时参考)

{get_false_positive_guide()}
"""
        else:
            # 完整版本: 包含语言保护、真实风险、误报指南
            if self._security_context_cache is None:
                self._security_context_cache = get_auditor_context()
            return f"""
## 🔥 Sui Move 安全知识参考

{self._security_context_cache}
"""

    async def process(self, message: AgentMessage) -> AgentMessage:
        """处理消息"""
        msg_type = message.content.get("type")

        if msg_type == "broad_analysis":
            result = await self.broad_analysis(message.content.get("code"), message.content.get("context"))
        elif msg_type == "targeted_analysis":
            result = await self.targeted_analysis(
                message.content.get("code"),
                message.content.get("vuln_type")
            )
        elif msg_type == "verify_finding":
            result = await self.verify_finding(message.content.get("finding"))
        else:
            result = {"error": f"Unknown message type: {msg_type}"}

        return AgentMessage(
            from_agent=self.role,
            to_agent=message.from_agent,
            message_type="response",
            content=result
        )

    async def broad_analysis(self, code: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        广泛分析模式 (BA Mode)

        对代码进行全面的安全审计，不预设漏洞类型。

        Args:
            code: Move源代码
            context: 合约上下文

        Returns:
            发现的漏洞列表
        """
        context_info = ""
        hints_section = ""
        if context:
            context_info = f"""
## 合约上下文
- 模块: {context.get('module_name', 'Unknown')}
- 调用图: {context.get('callgraph', {})}
- 外部依赖: {context.get('dependencies', [])}
"""
            # 🔥 提取预分析提示
            analysis_hints = context.get('analysis_hints')
            if analysis_hints:
                hints_section = self._format_analysis_hints(analysis_hints)

        # 检测是否需要截断 (使用配置文件中的限制)
        from src.config import CODE_TRUNCATE_LIMITS
        ba_limit = CODE_TRUNCATE_LIMITS.get("broad_analysis", 200000)
        code_truncated = len(code) > ba_limit
        truncation_warning = ""
        if code_truncated:
            truncation_warning = f"\n⚠️ **注意: 代码已截断** (原始 {len(code)} 字符，显示前 {ba_limit} 字符)。请基于可见部分进行审计。\n"

        # 🔥 v2.5.2: 注入 Sui Move 安全知识 (完整版)
        security_context = self._get_security_context(compact=False)

        prompt = f"""
## 任务
请对以下Move智能合约进行**全面且系统的**安全审计。
你的发现将传给多轮Agent验证（Phase 3会过滤误报），所以**绝对不能遗漏任何潜在漏洞**。

**核心原则: 宁可误报100个，不可漏报1个真实漏洞！**

{security_context}

{context_info}
{hints_section}
## 合约代码{truncation_warning}
```move
{code[:ba_limit]}
```

## 系统性审计清单 (必须逐项检查，每项都要在 findings 或 safe_patterns 中体现)

### 1. 访问控制 (最重要) ⚠️
- [ ] 每个 `public fun` 是否需要权限检查？
- [ ] 是否有缺少 AdminCap/OwnerCap 的敏感函数？
- [ ] `public fun` 应该是 `public(package)` 或 `entry` 吗？
- [ ] 对象所有权验证是否正确？
- [ ] 是否有 set_xxx / update_xxx 函数缺少权限？

### 2. 资金安全 💰
- [ ] 提款/转账函数是否有权限控制？
- [ ] withdraw / withdraw_all / drain 类函数是否安全？
- [ ] Coin/Balance 操作是否正确？
- [ ] 是否可能有资金被锁死的情况？

### 3. 算术安全 🔢
- [ ] 乘法是否可能溢出？(a * b 特别是金额计算)
- [ ] 加法是否可能溢出？(a + b)
- [ ] 除法是否会除零？
- [ ] 是否使用了 u128 做中间计算？
- [ ] 连续运算的舍入误差是否会累积？

### 4. DeFi 核心 📊
- [ ] swap 是否有滑点保护 (min_amount_out)？
- [ ] 是否有 deadline 参数防止延迟执行？
- [ ] 价格计算是否可被闪电贷操纵？
- [ ] 是否有 TWAP 或价格边界检查？

### 5. 流动性池 🏊
- [ ] 首次存款的 LP 计算是否安全？
- [ ] 是否有 MINIMUM_LIQUIDITY 防止首存攻击？
- [ ] 份额计算是否可被捐赠攻击？
- [ ] 空池状态是否有特殊处理？

### 6. 闪电贷 ⚡
- [ ] Receipt 是否有 drop 能力？(没有 = Hot Potato 模式，强制还款)
- [ ] ⚠️ **还款币种是否与借款币种一致？** (关键！类型混淆漏洞)
  - 检查: repay 函数是否验证 `type_name::get<A>() == receipt.type_name`
  - 漏洞模式: 借 CoinA 还 CoinB → 掏空 CoinA 池
- [ ] Receipt 是否可被伪造或重用？
- [ ] 还款金额验证是否严格？

### 7. Move/Sui 特定 🔷
- [ ] 共享对象 (shared) 是否考虑并发安全？
- [ ] 对象是否可能被意外删除/转移？
- [ ] 动态字段访问是否安全？
- [ ] Capability 对象是否可能泄漏？
- [ ] Witness 模式是否正确使用？

### 8. 业务逻辑 🧠
- [ ] 状态机转换是否正确？
- [ ] 边界条件处理是否完整？
- [ ] 是否有可被利用的时序依赖？

### 9. 🔥 跨函数漏洞依赖链分析 (关键!)
**必须分析多个漏洞是否可以组合利用形成攻击链！**

- [ ] **状态变更依赖**: 哪些函数会修改关键状态变量？触发条件是什么？
  - 权限提升/授权状态的触发条件是什么？
  - 触发条件是否依赖可被外部操纵的计算结果？

- [ ] **数据流追踪**: 函数 A 的输出是否作为函数 B 的输入？
  - 算术运算的输入来自哪里？可以被操纵吗？
  - 运算结果是否会影响权限判断或资金操作？

- [ ] **漏洞放大链**: 一个漏洞是否为另一个漏洞创造利用条件？
  - 重复调用/资产累积漏洞 → 达成其他漏洞的前置条件
  - 访问控制缺陷 → 状态操纵 → 更严重的资金风险

- [ ] **累积效应**: 是否存在"小漏洞组合成大风险"的情况？
  - 多次操作最终达到某个阈值
  - 多个中等漏洞组合后形成完整攻击链

**如果发现漏洞间存在依赖关系，必须在 findings 中添加 `dependency_chain` 字段！**

## 输出要求

**⚠️ 极其重要 - 必须遵守**:
1. **宁可多报不可漏报** - 不确定的也要报告（标注低 confidence），Phase 3 会过滤
2. `code_snippet` 和 `evidence` 必须是**从上面源代码直接复制的真实代码行**
3. ❌ 错误示例: `"evidence": "The u64 type can overflow when..."`
4. ✅ 正确示例: `"evidence": "let result = amount * price;"`
5. 每个发现必须包含足够信息让后续验证
6. **即使 confidence 只有 30-50，也要报告出来**
7. **🔴 所有输出必须使用中文！** title、description、recommendation、attack_vector 等字段都必须用中文
   - ❌ 错误: `"title": "Missing access control in withdraw"`
   - ✅ 正确: `"title": "withdraw 函数缺少访问控制"`

```json
{{
    "analysis_summary": "整体安全评估摘要，包括发现的问题数量和严重性分布",
    "functions_checked": ["列出检查过的所有 public 函数"],
    "findings": [
        {{
            "id": "BA-001",
            "title": "简洁的漏洞标题",
            "severity": "critical|high|medium|low",
            "category": "access_control|arithmetic|defi|move_specific|logic",
            "location": {{
                "file": "模块名",
                "line": 行号,
                "function": "函数名",
                "code_snippet": "从源代码复制的函数签名或关键代码行"
            }},
            "description": "详细描述：1) 问题是什么 2) 为什么有风险 3) 攻击者能做什么",
            "evidence": "从源代码直接复制的漏洞代码行（必须是真实代码，不是描述！）",
            "attack_vector": "攻击者如何利用：1) 入口 2) 步骤 3) 结果",
            "exploitability": "easy|medium|hard",
            "recommendation": "具体的修复建议",
            "confidence": 0-100,
            "dependency_chain": {{
                "depends_on": ["该漏洞利用需要的前置条件或其他漏洞ID"],
                "enables": ["该漏洞可以为哪些攻击创造条件"],
                "data_flow": "关键数据如何从输入流向漏洞点",
                "trigger_condition": "漏洞触发的具体条件（从代码中提取真实的 if 条件）"
            }}
        }}
    ],
    "attack_chains": [
        {{
            "chain_id": "CHAIN-001",
            "title": "组合攻击链标题",
            "severity": "critical|high|medium",
            "involved_findings": ["BA-001", "BA-002", "..."],
            "attack_flow": "Step1 → Step2 → Step3 → 最终影响",
            "description": "完整的攻击链描述，解释多个漏洞如何协同工作",
            "total_impact": "组合利用后的最大影响"
        }}
    ],
    "risk_areas": ["高风险函数/区域列表"],
    "safe_patterns": ["发现的良好实践"],
    "unchecked_areas": ["如果有无法分析的区域，列出原因"]
}}
```
"""
        # 🔥 stateless=True 用于并行调用，避免 conversation_history 污染
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        return self.parse_json_response(response)

    async def targeted_analysis(self, code: str, vuln_type: str) -> Dict[str, Any]:
        """
        针对分析模式 (TA Mode)

        针对特定漏洞类型进行检测。

        Args:
            code: Move源代码
            vuln_type: 漏洞类型 (如 "overflow", "access_control", "flash_loan")

        Returns:
            针对该类型的发现
        """
        vuln_prompts = self._get_vuln_detection_prompt(vuln_type)

        # 检测是否需要截断 (使用配置文件中的限制)
        from src.config import CODE_TRUNCATE_LIMITS
        ta_limit = CODE_TRUNCATE_LIMITS.get("targeted_analysis", 150000)
        code_truncated = len(code) > ta_limit
        truncation_warning = ""
        if code_truncated:
            truncation_warning = f"\n⚠️ **注意: 代码已截断** (原始 {len(code)} 字符，显示前 {ta_limit} 字符)。请基于可见部分进行检测。\n"

        prompt = f"""
## 任务
针对"{vuln_type}"类型漏洞，**逐行检查**以下Move代码。
你的发现将传给白帽验证，**不能遗漏任何{vuln_type}相关的问题**。

## {vuln_type} 检测指南
{vuln_prompts}

## 合约代码{truncation_warning}
```move
{code[:ta_limit]}
```

## 检查要求

1. **逐函数检查** - 列出所有与 {vuln_type} 相关的代码位置
2. **宁可多报** - 如果不确定，也报告出来（标注 confidence 较低）
3. **提供完整信息** - 白帽需要足够信息来验证

## 输出要求

**⚠️ 极其重要 - 必须遵守**:
- `code_snippet` 和 `proof` 必须是**从上面源代码直接复制的真实代码行**
- ❌ 错误示例: `"proof": "The multiplication can overflow because..."`
- ✅ 正确示例: `"proof": "let result = amount * price;"`
- `attack_scenario` 要具体到攻击步骤
- **🔴 所有输出必须使用中文！** title、description、recommendation 等字段都必须用中文

```json
{{
    "vuln_type": "{vuln_type}",
    "detection_result": "found|not_found|uncertain",
    "checked_locations": ["列出检查过的所有相关代码位置"],
    "findings": [
        {{
            "id": "TA-{vuln_type.upper()}-001",
            "title": "具体漏洞标题（如：withdraw_all 函数缺少权限检查）",
            "severity": "critical|high|medium|low",
            "location": {{
                "file": "模块名",
                "line": 行号,
                "function": "函数名",
                "code_snippet": "从源代码复制的函数签名（必须是真实代码）"
            }},
            "description": "漏洞描述：1) 问题是什么 2) 为什么有风险",
            "proof": "从源代码直接复制的漏洞代码行（必须是真实代码，不是描述！）",
            "attack_scenario": "攻击步骤：Step 1: ... Step 2: ... Step 3: ...",
            "why_its_vulnerable": "为什么这段代码有漏洞",
            "recommendation": "具体修复建议",
            "confidence": 0-100
        }}
    ],
    "safe_code": ["检查过但没问题的代码位置（证明你确实检查了）"],
    "analysis_notes": "分析过程中的备注"
}}
```
"""
        # 🔥 stateless=True 用于并行调用，避免 conversation_history 污染
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        return self.parse_json_response(response)

    async def verify_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证漏洞发现

        Args:
            finding: 其他来源的漏洞发现

        Returns:
            验证结果
        """
        # 获取代码上下文
        code_context = finding.get('code_context', '')
        evidence = finding.get('evidence', finding.get('proof', ''))

        prompt = f"""
## 任务
请验证以下漏洞发现是否**真实存在且可被利用**。

## 漏洞信息
- ID: {finding.get('id')}
- 标题: {finding.get('title')}
- 严重性: {finding.get('severity')}
- 位置: {finding.get('location')}
- 描述: {finding.get('description')}
- 漏洞代码: {evidence}

## 相关代码
```move
{code_context if code_context else '无代码上下文'}
```

## 判断标准

### 以下情况应判定为 confirmed (真实漏洞):
1. **访问控制缺失**: public 函数没有权限检查 (如 AdminCap) 且执行敏感操作
2. **整数溢出**: 乘法/加法运算可能超过 u64 范围且没有使用 checked_* 或 u128
3. **资金风险**: 任何人可以调用的函数能够转移/销毁资金
4. **滑点缺失**: swap 函数没有 min_amount_out 参数

### 以下情况应判定为 false_positive (误报):
1. 代码中**已有**权限检查 (AdminCap, OwnerCap, 或 sender 验证)
2. 函数是 public(package) 或 friend，不对外暴露
3. 溢出在数学上不可能发生 (如 amount < 1e18 的约束)
4. 漏洞描述与代码不符

### 🔥 Sui Move 特定误报 (必须标记为 false_positive):
5. **init() 函数漏洞**: Sui 的 init(witness, ctx) 由运行时保护，外部无法调用
6. **witness 伪造**: 外部模块无法创建相同类型的 witness（类型路径不同）
7. **private 函数直接调用**: Move 的 private 函数不能从外部调用

### 以下情况应判定为 needs_more_info:
1. 缺少完整代码上下文
2. 需要了解外部依赖的实现

## ⚠️ 重要提醒
- **宁可误报，不可漏报** - 如果不确定，倾向于 confirmed
- 缺少权限检查的 public 函数是**真实漏洞**，不是误报
- withdraw_all、set_admin 等敏感函数没有权限检查 = confirmed

## 输出要求
```json
{{
    "verification_result": "confirmed|false_positive|needs_more_info",
    "confidence": 0-100,
    "reasoning": "详细说明为什么这是/不是真实漏洞",
    "code_evidence": "支持判断的代码行",
    "severity_adjustment": "same|upgrade|downgrade",
    "adjusted_severity": "critical|high|medium|low"
}}
```
"""
        # 🔥 stateless=True: Phase 3 中并行调用，每次请求独立
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        return self.parse_json_response(response)

    def _get_vuln_detection_prompt(self, vuln_type: str) -> str:
        """获取特定漏洞类型的检测提示"""
        prompts = {
            "overflow": """
## 整数溢出检测指南
1. 检查所有乘法运算 (a * b)
2. 检查所有加法运算 (a + b)
3. 特别关注涉及金额、价格、数量的计算
4. 检查是否使用了 u128 类型进行中间计算
5. 检查是否有 checked_mul/checked_add 等安全函数

## 常见模式
- amount * price (无溢出检查)
- balance + deposit (无溢出检查)
- liquidity * fee_rate / FEE_DENOMINATOR (乘法先于除法)
""",
            "access_control": """
## 访问控制检测指南
1. 检查敏感函数是否需要 AdminCap/OwnerCap
2. 检查 public fun 是否应该是 public(friend) 或 private
3. 检查是否有未授权的状态修改
4. 检查 assert! 中的权限检查是否充分

## 常见模式
- public fun set_xxx() 缺少权限检查
- 任何人都可以调用的铸币/销毁函数
- 缺少所有权验证的转账函数
""",
            "flash_loan": """
## 闪电贷漏洞检测指南
1. 检查借款函数是否返回 Receipt/Hot Potato
2. 检查还款函数是否验证 Receipt
3. 检查还款金额是否包含手续费
4. 检查是否可以绕过还款验证

## 常见模式
- 还款金额验证不严格
- Receipt 可以被伪造或重用
- 手续费计算错误
""",
            "price_manipulation": """
## 价格操纵检测指南
1. 检查价格来源是否可被操纵
2. 检查是否使用 TWAP (时间加权平均价格)
3. 检查是否有价格偏差保护
4. 检查价格更新的权限

## 常见模式
- 使用即时价格而非 TWAP
- 单一价格来源
- 缺少价格边界检查
""",
            "reentrancy": """
## 重入检测指南 (Move 版本)
1. 检查外部调用后是否修改状态
2. 检查是否有 checks-effects-interactions 模式违规
3. 检查回调函数的安全性

## Move 特殊考虑
- Move 的线性类型系统提供了一定保护
- 但通过 public fun 调用仍可能存在逻辑重入
""",
            "slippage": """
## 滑点保护检测指南
1. 检查 swap 函数是否有 min_amount_out 参数
2. 检查是否在大额交易时有保护
3. 检查是否有截止时间 (deadline) 参数

## 常见模式
- swap 缺少 min_amount_out
- 缺少 deadline 导致交易延迟执行
""",
            "first_deposit": """
## 首次存款攻击检测指南
1. 检查流动性池首次存款时的 LP 代币计算
2. 检查是否有最小流动性锁定 (MINIMUM_LIQUIDITY)
3. 检查空池状态下的特殊处理

## 常见模式
- 首次存款者可获得不成比例的 LP 份额
- 攻击者可通过微量存款 + 捐赠操纵价格
- 缺少 sqrt(x*y) 计算或最小锁定
""",
            "donation_attack": """
## 捐赠攻击检测指南
1. 检查是否可以直接向合约转账而不通过正常流程
2. 检查份额计算是否基于实际余额而非记账余额
3. 检查 ERC4626 类似的 vault 模式

## 常见模式
- 直接 transfer 到合约地址绕过记账
- 份额 = deposit * totalShares / totalAssets
- 攻击者捐赠后稀释其他用户份额
""",
            "rounding": """
## 舍入误差检测指南
1. 检查除法运算的舍入方向是否对协议有利
2. 检查小数位精度是否足够
3. 检查连续舍入是否会累积误差

## 常见模式
- 用户取款时向下舍入，存款时向上舍入
- 手续费计算舍入到 0
- 小额操作累积舍入误差
""",
            "object_safety": """
## Sui 对象安全检测指南
1. 检查共享对象 (shared) 是否正确使用
2. 检查对象是否可能被意外删除或转移
3. 检查动态字段 (dynamic field) 是否安全
4. 检查对象 ID 是否可预测

## 常见模式
- 共享对象未考虑并发安全
- 对象可被任意转移给其他用户
- 动态字段可被覆盖或删除
- 对象 ID 可被预测用于抢跑
""",
            "capability_leak": """
## 能力泄漏检测指南
1. 检查 AdminCap/OwnerCap 是否可能被转移给攻击者
2. 检查 Capability 对象是否有 store 能力 (可被任意存储/转移)
3. 检查是否有创建新 Capability 的公开函数

## 常见模式
- Cap 有 store 能力且可被公开转移
- 任何人可调用函数创建新的 Cap
- Cap 的销毁/更新缺少权限检查
""",
            "witness_abuse": """
## Witness 模式滥用检测指南
1. 检查 One-Time Witness (OTW) 是否正确使用
2. 检查 Witness 是否可被多次创建
3. 检查类型级别的权限是否可被绕过

## 常见模式
- OTW 可被多次实例化 (应只在 init 中创建)
- Witness 类型有 drop 能力被错误丢弃
- 泛型 Witness 被伪造
"""
        }
        return prompts.get(vuln_type, f"请检测 {vuln_type} 类型的漏洞。")

    # 所有支持的漏洞类型 (与 engine.py AuditConfig.targeted_vuln_types 保持同步)
    ALL_VULN_TYPES = [
        # 核心漏洞类型
        "overflow", "access_control", "flash_loan",
        "price_manipulation", "slippage", "reentrancy",
        # DeFi 特定
        "first_deposit", "donation_attack", "rounding",
        # Move/Sui 特定
        "object_safety", "capability_leak", "witness_abuse"
    ]

    async def analyze_functions_batch(
        self,
        func_contexts: List[Dict[str, Any]],
        batch_id: int = 0
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        🔥 批量分析多个函数 - 一次 LLM 调用分析多个函数

        相比单函数分析，批量分析可以:
        - 减少 API 调用次数 (5个函数 = 1次调用 vs 5次调用)
        - 利用函数间的上下文关系 (跨函数漏洞链)
        - 大幅提升审计速度

        Args:
            func_contexts: 函数上下文列表，每个元素包含:
                - module_name, function_name, function_code, signature, visibility
                - risk_score, risk_indicators, callers, callees
            batch_id: 批次编号

        Returns:
            {"results": {function_id: [findings]}, "cross_function_issues": [...]}
        """
        if not func_contexts:
            return {"results": {}, "cross_function_issues": []}

        # 构建批量分析的上下文
        functions_text = []
        function_ids = []

        # 🔥 v2.5.9: 收集所有类型定义和被调用函数实现
        all_type_definitions = set()
        all_callee_implementations = set()

        for i, ctx in enumerate(func_contexts, 1):
            module_name = ctx.get("module_name", "unknown")
            function_name = ctx.get("function_name", "unknown")
            function_code = ctx.get("function_code", "")
            signature = ctx.get("signature", "")
            visibility = ctx.get("visibility", "private")
            risk_score = ctx.get("risk_score", 0)
            callers = ctx.get("callers", [])
            callees = ctx.get("callees", [])

            # 🔥 v2.5.9: 收集类型定义
            type_definitions = ctx.get("type_definitions", "")
            if type_definitions:
                all_type_definitions.add(type_definitions)

            # 🔥 v2.5.10: 收集被调用函数的实现 (关键！用于理解跨函数逻辑漏洞)
            callee_implementations = ctx.get("callee_implementations", "")
            if callee_implementations:
                all_callee_implementations.add(callee_implementations)

            func_id = f"{module_name}::{function_name}"
            function_ids.append(func_id)

            # 风险提示
            risk_indicators = ctx.get("risk_indicators", {})
            risk_hints = []
            if risk_indicators.get("overflow", 0) > 0:
                risk_hints.append(f"溢出风险×{risk_indicators['overflow']}")
            if risk_indicators.get("access_control", 0) > 0:
                risk_hints.append("访问控制")
            if risk_indicators.get("state_modification", 0) > 0:
                risk_hints.append(f"状态修改×{risk_indicators['state_modification']}")

            risk_hint_str = f" | 风险指标: {', '.join(risk_hints)}" if risk_hints else ""

            caller_str = f"被调用: {', '.join(callers[:3])}" if callers else "入口函数"
            callee_str = f"调用: {', '.join(callees[:3])}" if callees else ""

            functions_text.append(f"""
### [{i}] {func_id}
- 签名: `{signature}`
- 可见性: `{visibility}` | 风险评分: {risk_score}{risk_hint_str}
- {caller_str}{' | ' + callee_str if callee_str else ''}

```move
{function_code}
```
""")

        # 🔥 v2.5.9: 构建类型定义部分
        type_defs_section = ""
        if all_type_definitions:
            type_defs_section = f"""
## 🔥 相关类型定义 (关键！检查类型混淆漏洞必看)
```move
{chr(10).join(all_type_definitions)}
```
"""

        # 🔥 v2.5.10: 构建被调用函数实现部分 (关键！用于理解跨函数逻辑)
        callee_impl_section = ""
        if all_callee_implementations:
            callee_impl_section = f"""
## 🔥 被调用函数的实现 (关键！理解跨函数逻辑漏洞必看)
```move
{chr(10).join(all_callee_implementations)}
```
"""

        prompt = f"""## 任务
对以下 {len(func_contexts)} 个 Move 函数进行**批量安全审计**。

**重要**: 这些函数可能相互调用，请注意跨函数的漏洞依赖链！
{type_defs_section}{callee_impl_section}
## 函数列表
{''.join(functions_text)}

## 审计清单 (每个函数都要检查)

### 1. 访问控制
- public 函数是否需要权限检查 (AdminCap/OwnerCap)?
- 敏感操作是否验证了调用者身份?

### 2. 算术安全
- 乘法/加法是否可能溢出?
- 除法是否可能除以零?

### 3. 资源安全
- Coin/Balance 操作是否正确?
- 是否有资源泄漏?

### 4. 跨函数分析 (关键!)
- 函数 A 的输出是否影响函数 B 的安全?
- 是否存在组合利用的漏洞链?

## 输出格式

**⚠️ 重要**:
- 每个函数的发现要分开列出，使用 function_id 作为 key
- **🔴 所有输出必须使用中文！** title、description、recommendation、attack_scenario 等字段都必须用中文

```json
{{
    "batch_id": {batch_id},
    "results": {{
        "{function_ids[0] if function_ids else 'module::func'}": [
            {{
                "id": "BATCH-{batch_id}-001",
                "title": "漏洞标题",
                "severity": "critical|high|medium|low",
                "category": "access_control|overflow|resource|logic",
                "location": {{
                    "module": "模块名",
                    "function": "函数名",
                    "code_snippet": "从源代码复制的代码"
                }},
                "description": "漏洞描述",
                "proof": "漏洞代码证据",
                "attack_scenario": "攻击步骤",
                "recommendation": "修复建议",
                "confidence": 0-100
            }}
        ]
    }},
    "cross_function_issues": [
        {{
            "id": "CHAIN-{batch_id}-001",
            "title": "跨函数漏洞链",
            "severity": "high",
            "involved_functions": ["func_a", "func_b"],
            "attack_flow": "Step1 → Step2 → Impact",
            "description": "漏洞链描述"
        }}
    ],
    "safe_functions": ["没有发现问题的函数ID列表"],
    "batch_notes": "批量分析备注"
}}
```

**注意**: 如果某个函数没有发现问题，在 safe_functions 中列出，不要在 results 中包含空数组。
"""
        response = await self.call_llm(prompt, json_mode=True, stateless=True)
        result = self.parse_json_response(response)

        # 确保返回格式正确
        if "results" not in result:
            result["results"] = {}
        if "cross_function_issues" not in result:
            result["cross_function_issues"] = []

        return result

    def _format_analysis_hints(self, hints: Dict[str, Any]) -> str:
        """
        🔥 格式化预分析提示，供审计 prompt 使用

        Args:
            hints: 预分析提取的关键信息

        Returns:
            格式化的提示文本
        """
        sections = []
        sections.append("## 🔥 项目关键信息 (预分析提示 - 请重点关注!)")

        # 关键状态变量
        state_vars = hints.get("key_state_variables", [])
        if state_vars:
            sections.append("\n### 关键状态变量:")
            for v in state_vars[:8]:
                name = v.get('name', '?')
                vtype = v.get('type', '?')
                relevance = v.get('security_relevance', '')[:60]
                sections.append(f"- **{name}** ({vtype}): {relevance}")

        # 条件阈值
        thresholds = hints.get("condition_thresholds", [])
        if thresholds:
            sections.append("\n### 条件阈值 (重点检查这些判断是否可被绕过!):")
            for t in thresholds[:6]:
                cond = t.get('condition', '?')[:60]
                loc = t.get('location', '?')
                impl = t.get('security_implication', '')[:50]
                sections.append(f"- `{cond}` @ {loc}")
                if impl:
                    sections.append(f"  - 安全含义: {impl}")

        # 跨函数数据流
        dataflows = hints.get("cross_function_dataflow", [])
        if dataflows:
            sections.append("\n### 跨函数数据流 (分析漏洞依赖链!):")
            for df in dataflows[:5]:
                flow = df.get('flow', '?')
                concern = df.get('security_concern', '')[:60]
                sections.append(f"- {flow}")
                if concern:
                    sections.append(f"  - 风险: {concern}")

        # 状态变更点
        state_changes = hints.get("state_change_points", [])
        if state_changes:
            sections.append("\n### 状态变更点 (权限提升/余额修改的关键位置!):")
            for sc in state_changes[:5]:
                var = sc.get('variable', '?')
                func = sc.get('function', '?')
                trigger = sc.get('trigger_condition', '')[:50]
                sections.append(f"- **{var}** in `{func}()`: {trigger}")

        # 潜在漏洞链
        vuln_chains = hints.get("potential_vuln_chains", [])
        if vuln_chains:
            sections.append("\n### ⚠️ 潜在漏洞链 (多个漏洞组合利用!):")
            for vc in vuln_chains[:4]:
                chain = vc.get('chain', '?')
                desc = vc.get('description', '')[:80]
                sections.append(f"- **{chain}**")
                if desc:
                    sections.append(f"  - {desc}")

        # 分析总结
        summary = hints.get("analysis_summary", "")
        if summary:
            sections.append(f"\n### 预分析总结:")
            sections.append(f"{summary[:300]}")

        sections.append("\n**请基于以上信息进行针对性审计，特别关注漏洞链和条件阈值！**\n")

        return "\n".join(sections)
