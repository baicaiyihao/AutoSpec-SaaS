"""
Sui Move 安全知识库 - v2.5.25

🔥 v2.5.25 重大更新:
- 扩展 real_vulnerability_keywords，覆盖更多真实漏洞描述
- 强调"必须先检查代码再判断"原则
- 防止因知识注入导致 AI 误判真实漏洞为误报

本模块包含 Sui Move 的完整安全特性知识，用于：
1. 帮助 AI Agent 理解 Sui Move 的安全模型
2. 减少因不了解平台特性导致的误报
3. 正确识别真正的安全问题

参考来源:
- https://blog.sui.io/sui-mitigates-web3-security-risks/
- https://slowmist.medium.com/slowmist-introduction-to-auditing-sui-move-contracts
- https://github.com/slowmist/Sui-MOVE-Smart-Contract-Auditing-Primer
- https://www.movebit.xyz/blog/post/Sui-Objects-Security-Principles-and-Best-Practices.html
- https://www.mirageaudits.com/blog/sui-move-ability-security-mistakes
- https://blog.trailofbits.com/2025/09/10/how-sui-move-rethinks-flash-loan-security/
- https://www.zellic.io/blog/move-fast-break-things-move-security-part-2/
- https://arxiv.org/abs/2205.05181 (The Move Borrow Checker)
- https://formal.land/blog/2024/08/19/verification-move-sui-type-checker-1
- https://blog.sui.io/security-best-practices/
"""

# =============================================================================
# 第一部分: 语言级安全保护 (无法绕过的保护)
# =============================================================================

LANGUAGE_LEVEL_PROTECTIONS = """
## 一、Sui Move 语言级安全保护

以下安全机制由 Move VM 或字节码验证器强制执行，**无法被绕过**：

### 1. 算术溢出/下溢保护 ✅
- **机制**: Move VM 对所有算术运算 (+, -, *, /) 自动进行溢出检查
- **行为**: 溢出时交易 abort，**不会静默回绕 (wrap-around)**
- **例外**: 位运算 (<<, >>, &, |, ^) 不检查溢出 → 仍需审计
- **对比**: Solidity 0.8+ 也有此保护，但旧版本没有

```move
// 如果 a + b > MAX_U64，交易会 abort，不会回绕到 0
let result = a + b;

// ⚠️ 位运算不检查溢出！
let shifted = value << 64;  // 危险：可能产生意外结果
```

### 2. 重入攻击免疫 ✅
- **机制**: Move 没有动态调度 (dynamic dispatch)
- **行为**: 所有函数调用在编译时确定，无法在运行时改变调用目标
- **额外保护**:
  - 资源在任何时刻只能被一个执行上下文访问
  - 没有 Solidity 中的 fallback/receive 函数
  - 没有原生代币转账触发的回调
- **学术依据**: Move 的资源模型确保 "a resource can only be accessed by a single execution context at a time"

### 3. 内存安全 - Borrow Checker ✅
- **机制**: Move 借用检查器 (类似 Rust)
- **学术证明** (arXiv:2205.05181) 三个属性:
  1. **无悬垂引用** (Absence of dangling references)
  2. **不可变引用的引用透明性** (Referential transparency for immutable references)
  3. **无内存泄漏** (Absence of memory leaks)
- **实现**: 字节码验证时运行，拒绝不安全的代码

### 4. 资源安全 - 线性类型系统 ✅
- **机制**: 资源默认不能被复制或丢弃
- **能力控制**:
  - `copy`: 允许复制 (值类型才有)
  - `drop`: 允许丢弃
  - `key`: 可以存储在全局存储
  - `store`: 可以嵌套存储
- **效果**: 双花在编译时就被阻止

```move
// 资源型代币不能被复制
struct Token has key, store { value: u64 }  // 没有 copy

let t1 = Token { value: 100 };
let t2 = t1;   // t1 被移动，不是复制
// t1 不再可用，阻止了双花
```

### 5. 字节码验证器 ✅
- **运行时机**: 模块发布时 (publish-time verification)
- **检查内容**:
  - 类型安全 (Type safety)
  - 资源安全 (Resource safety)
  - 引用安全 (Reference safety)
  - ID 泄漏检查 (UID 不能被重用)
  - key 能力的结构体必须有 `id: UID` 作为第一个字段
- **效果**: 不合法的字节码根本无法上链

### 6. 模块私有性 ✅
- **机制**: 结构体成员只能在定义模块内访问
- **效果**: 外部模块无法直接读写私有字段
- **对比**: Solidity 的 private 只是建议，可通过 storage slot 读取

### 7. init() 函数保护 ✅
- **机制**: `init(witness, ctx)` 只在模块发布时由运行时调用
- **保证**: 只能调用一次，外部无法调用
- **常见误报**: "init 可被重复调用" → 不可能

### 8. TxContext 注入 ✅
- **机制**: TxContext 由 VM 注入，包含交易元数据
- **内容**: sender 地址、epoch、签名者等
- **保证**: 无法被用户伪造

### 9. UID 唯一性和 ID 泄漏防护 ✅
- **机制**: UID 由 tx_hash + counter 派生，全局唯一
- **字节码验证**: ID leak verifier 确保只有 "fresh" UID 可用
- **效果**: 对象删除后 UID 不能被重用

### 10. acquires 注解与全局存储安全 ✅
- **机制**: 访问全局存储的函数必须声明 `acquires T`
- **效果**: 静态分析防止悬垂引用
- **跨模块安全**: 只需在同模块内追踪

```move
// 必须声明 acquires，否则编译错误
public fun remove_resource(addr: address): Resource acquires Resource {
    move_from<Resource>(addr)
}
```
"""

# =============================================================================
# 第二部分: 安全设计模式 (正确使用时提供保护)
# =============================================================================

SECURITY_PATTERNS = """
## 二、Sui Move 安全设计模式

以下模式**正确使用时**提供安全保护：

### 1. Capability 权限模式 ✅
- **原理**: 持有 Capability 对象 = 拥有权限
- **标准用法**: `_: &AdminCap` 作为函数参数
- **安全保证**: 调用者必须持有该 Cap 才能调用函数

```move
// ✅ 安全: 只有持有 AdminCap 的人才能调用
public fun admin_function(_: &AdminCap, config: &mut Config) {
    // 操作配置
}

// ⚠️ 不安全: 没有权限检查
public fun admin_function(config: &mut Config) {
    // 任何人都能调用！
}
```

### 2. One-Time Witness (OTW) 模式 ✅
- **原理**: 特殊类型只能在 init() 中创建一次
- **条件**: 类型名与模块名相同 (大写)，只有 `drop` 能力
- **用途**: 保证单例初始化 (如 TreasuryCap)

```move
module my_token {
    // OTW 类型：名称大写，只有 drop
    struct MY_TOKEN has drop {}

    fun init(witness: MY_TOKEN, ctx: &mut TxContext) {
        // witness 只能在这里使用一次
        let treasury_cap = coin::create_currency(witness, ...);
    }
}
```

### 3. Hot Potato 模式 (Flash Loan) ✅
- **原理**: 没有任何能力的结构体必须被显式消费
- **安全保证**: 借款人必须调用 repay 函数，否则交易失败

```move
// ✅ 安全: Receipt 没有 drop，必须被 repay 消费
struct FlashLoanReceipt {
    pool_id: ID,
    amount: u64,
}

// ⚠️ 致命漏洞: 有 drop 意味着可以忽略还款！
struct FlashLoanReceipt has drop {  // 严重漏洞！
    amount: u64,
}
```

### 4. public(package) 可见性 ✅
- **原理**: 只能被同一 package 内的模块调用
- **用途**: 内部辅助函数，不暴露给外部

```move
// 只有同 package 的模块能调用
public(package) fun internal_transfer(...) { ... }
```

### 5. Phantom 类型参数 ✅
- **原理**: 不实际存储但用于类型区分
- **用途**: 区分不同代币类型

```move
// T 是 phantom，用于区分不同代币
struct Coin<phantom T> has key, store {
    id: UID,
    balance: Balance<T>,
}
```

### 6. Witness 模式 ✅
- **原理**: 通过构造证明来验证权限
- **用途**: 证明调用者是某类型的定义者

```move
// 只有能构造 Witness 的模块才能创建 Guardian
public fun create_guardian<T: drop>(witness: T): Guardian<T> {
    Guardian { id: object::new(ctx) }
}
```
"""

# =============================================================================
# 第三部分: 真正需要审计的安全问题
# =============================================================================

REAL_SECURITY_CONCERNS = """
## 三、真正需要审计的 Sui Move 安全问题

以下问题**即使在 Sui Move 中也存在风险**：

### 1. Ability 滥用 🔴 严重
- **copy + drop 在资产上**: 可以无限复制和销毁 → 严重漏洞
- **drop 在 Hot Potato 上**: 可以跳过强制操作 (如还款) → 严重漏洞
- **审计重点**: 检查所有 struct 的 ability 声明

```move
// 🔴 严重漏洞: 代币可以被复制！
struct MyToken has key, store, copy, drop { value: u64 }

// 🔴 严重漏洞: Flash loan receipt 可以被丢弃！
struct Receipt has drop { amount: u64 }
```

### 2. AdminCap 被共享 🔴 严重
- **问题**: `public_share_object(admin_cap)` 使任何人都成为管理员
- **审计重点**: 检查敏感 Capability 的创建和转移

```move
// 🔴 严重漏洞: 任何人都能操作！
transfer::public_share_object(admin_cap);

// ✅ 正确: 转移给部署者
transfer::transfer(admin_cap, tx_context::sender(ctx));
```

### 3. 泛型类型未验证 🟠 高危
- **问题**: 没有验证泛型参数的实际类型
- **攻击**: 用低价值代币冒充高价值代币

```move
// 🟠 危险: 没有验证 T 的类型
public fun deposit<T>(coin: Coin<T>) { ... }

// ✅ 安全: 验证代币类型
public fun deposit<T>(coin: Coin<T>, expected: TypeName) {
    assert!(type_name::get<T>() == expected, E_WRONG_TYPE);
}
```

### 4. 精度损失 🟠 高危
- **问题**: Move 没有浮点数，整数除法会截断
- **风险**: 资金计算错误导致损失
- **审计重点**: 检查除法顺序

```move
// 🟠 精度损失: 先除后乘
let fee = amount / 1000 * fee_rate;  // 错误

// ✅ 正确: 先乘后除
let fee = amount * fee_rate / 1000;
```

### 5. 位运算溢出 🟠 高危
- **问题**: Move VM 不检查位运算的溢出
- **审计重点**: 检查所有 <<, >>, &, |, ^ 操作

```move
// 🟠 危险: 可能溢出
let result = value << shift_amount;  // 如果 shift_amount >= 64?
```

### 6. 对象所有权问题 🟡 中危
- **UID 交换**: 控制对象创建的合约可以交换 UID
- **对象隐藏**: 对象可以被包装在其他对象中"消失"
- **意外转移**: key+store 对象可以被自由转移
- **意外冻结**: store 对象可以被任何人冻结

### 7. 交易排序 / MEV 🟡 中危
- **问题**: 验证者可以重新排序同一区块内的交易
- **风险**: 抢跑、三明治攻击
- **审计重点**: 价格敏感操作

### 8. 随机数问题 🟡 中危
- **Object ID 不随机**: UID 是确定性派生的
- **Clock 可操控**: 验证者可以在一定范围内操控时间
- **审计重点**: 抽奖、随机选择逻辑

### 9. 闪电贷价格操纵 🟡 中危
- **问题**: 即使有 Hot Potato，仍可借大量资金操纵价格
- **审计重点**: 预言机依赖、奖励机制

### 10. entry 函数与 PTB 安全 🟡 中危
- **问题**: entry 函数可通过 PTB 调用，可能被组合利用
- **审计重点**: 检查 entry 函数的输入验证
"""

# =============================================================================
# 第四部分: 误报判断指南
# =============================================================================

FALSE_POSITIVE_GUIDE = """
## 四、常见误报判断指南

### 当看到以下描述时，很可能是误报：

| 漏洞描述 | 判断 | 原因 |
|---------|------|------|
| "整数溢出绕过验证" | ❌ 误报 | Move VM 溢出会 abort，不会回绕 |
| "重入攻击风险" | ❌ 误报 | Move 没有动态调度 |
| "双花攻击" | ❌ 误报 (除非有 copy) | 线性类型系统保护 |
| "init 可被多次调用" | ❌ 误报 | Sui 运行时保护 |
| "TxContext 可伪造" | ❌ 误报 | VM 注入 |
| "闪电贷无强制还款" | ⚠️ 检查 Receipt 能力 | Hot Potato 没有 drop = 必须消费 |
| "public 函数无权限" | ⚠️ 检查 Cap 参数 | Capability 模式 |
| "共享对象可被任意修改" | ⚠️ 检查 ACL 逻辑 | 共享是设计模式 |

### 判断流程：

1. **看到 "无权限检查"**:
   - 检查函数参数是否有 `&AdminCap`, `&OwnerCap` 等
   - 检查是否是 `public(package)`
   - 如果有 Cap 或 package 可见性 → 误报

2. **看到 "溢出风险"**:
   - 如果是普通算术 (+, -, *, /) → 最多是 DoS，不是绕过
   - 如果是位运算 (<<, >>, &, |) → 真实风险

3. **看到 "可重复调用"**:
   - 如果是 init() → 误报
   - 如果是其他函数 → 检查是否有状态检查

4. **看到 "闪电贷无强制还款"**:
   - 检查 Receipt/FlashReceipt 的能力声明
   - 如果没有 `drop` 能力 → 误报 (Hot Potato 强制消费)
   - ⚠️ 但要检查: 还款时是否验证了币种类型匹配！
   - 真实漏洞: `repay<A>` 只检查 `contains_type<A>` 但不检查 A 是否等于借出的币种

   🔴 **关键代码模式 (真实漏洞 - 不要误判为误报!):**
   ```move
   // Receipt 中的 type_name 被 _ 丢弃了！
   let FlashReceipt { pool_id, type_name: _, amount } = receipt;
   ```
   如果 type_name 被忽略而不是验证，这是**真实漏洞**：
   - 攻击者借 Coin<USDC>，用 Coin<垃圾币> 还款
   - Hot Potato 只保证"必须还款"，不保证"还正确的币"

5. **看到 "类型伪造"**:
   - 检查是否跨模块 → 跨模块无法构造
   - 检查是否有公开构造函数 → 才可能被伪造
"""

# =============================================================================
# 第五部分: 审计检查清单
# =============================================================================

AUDIT_CHECKLIST = """
## 五、Sui Move 安全审计检查清单

### 🔴 高优先级检查 (严重漏洞)

- [ ] **Ability 审计**
  - 资产类型是否有 `copy` 或 `drop`？
  - Hot Potato (Receipt) 是否有 `drop`？

- [ ] **Capability 审计**
  - AdminCap 是否被 `share_object`？
  - 敏感操作是否需要 Cap？

- [ ] **泛型类型验证**
  - 是否验证了 `Coin<T>` 的 T？
  - 是否可能被假币攻击？

### 🟠 中优先级检查 (高危漏洞)

- [ ] **精度损失**
  - 除法顺序是否正确 (先乘后除)？
  - 是否有舍入错误累积？

- [ ] **位运算**
  - 是否有位移溢出？
  - 位运算结果是否被验证？

- [ ] **对象所有权**
  - key+store 对象的转移是否受控？
  - 是否有意外的对象冻结风险？

### 🟡 低优先级检查 (中危漏洞)

- [ ] **MEV / 交易排序**
  - 价格敏感操作是否有保护？
  - 是否有抢跑风险？

- [ ] **随机数**
  - 是否使用了 Object ID 作为随机源？
  - 是否正确使用了链上随机数？

- [ ] **闪电贷防护**
  - 预言机是否依赖实时价格？
  - 奖励机制是否可被闪电贷利用？
"""

# =============================================================================
# 导出函数
# =============================================================================

def get_full_security_knowledge() -> str:
    """获取完整的安全知识，用于学习"""
    return "\n\n".join([
        LANGUAGE_LEVEL_PROTECTIONS,
        SECURITY_PATTERNS,
        REAL_SECURITY_CONCERNS,
        FALSE_POSITIVE_GUIDE,
        AUDIT_CHECKLIST,
    ])


def get_auditor_context() -> str:
    """获取审计员上下文，用于注入到 Auditor Agent"""
    return "\n\n".join([
        "# Sui Move 安全知识 (审计参考)",
        LANGUAGE_LEVEL_PROTECTIONS,
        REAL_SECURITY_CONCERNS,
        FALSE_POSITIVE_GUIDE,
    ])


def get_false_positive_guide() -> str:
    """获取误报判断指南"""
    return FALSE_POSITIVE_GUIDE


def get_checklist() -> str:
    """获取审计检查清单"""
    return AUDIT_CHECKLIST


# =============================================================================
# 结构化知识 (供程序使用)
# =============================================================================

# 语言级保护列表 - 这些问题在 Sui Move 中通常是误报
# 🔥 v2.5.13: 重构，添加 underflow 和 vector_bounds 支持，使用 exclude_keywords
PROTECTED_VULNERABILITY_TYPES = {
    # 🔥 v2.5.13: 算术溢出 - 只有 +, -, *, / 自动保护，位移除外
    "arithmetic_overflow": {
        "description": "算术溢出/上溢",
        "protection": "Move VM 对 +, -, *, / 自动溢出检查，溢出时 abort",
        "exception": None,
        "false_positive_keywords": [
            "加法溢出", "乘法溢出", "上溢", "overflow",
            "addition overflow", "multiplication overflow",
            "可能溢出", "溢出风险",
        ],
        "exclude_keywords": ["<<", ">>", "位移", "shift", "shl", "shr"],
    },
    # 🔥 v2.5.13: 算术下溢 - Move 减法也自动保护
    "arithmetic_underflow": {
        "description": "算术下溢",
        "protection": "Move VM 对减法自动下溢检查，下溢时 abort",
        "exception": None,
        "false_positive_keywords": [
            "减法下溢", "下溢风险", "下溢", "underflow",
            "subtraction underflow", "可能下溢",
            "减法操作存在下溢", "减法存在下溢",
        ],
        "exclude_keywords": [],
    },
    # 🔥 v2.5.13: 向量越界 - Move vector 自动边界检查
    "vector_bounds": {
        "description": "向量越界访问",
        "protection": "Move vector::borrow/pop_back 自动边界检查，越界时 abort",
        "exception": None,
        "false_positive_keywords": [
            "越界",  # 🔥 通用关键词，匹配所有 "xxx越界" 场景
            "向量越界", "数组越界", "越界访问", "索引越界",
            "vector out of bounds", "array out of bounds",
            "index out of bounds", "越界风险", "bounds check",
            "可能越界", "out of bounds",
        ],
        "exclude_keywords": [],
    },
    # 保留原有条目
    "overflow_bypass": {
        "description": "整数溢出绕过验证",
        "protection": "Move VM 自动 abort",
        "exception": None,  # 🔥 v2.5.13: 移除 exception，用 exclude_keywords 代替
        "false_positive_keywords": ["绕过", "bypass", "回绕", "wrap"],
        "exclude_keywords": ["<<", ">>", "位移", "shift"],
    },
    "reentrancy": {
        "description": "重入攻击",
        "protection": "无动态调度",
        "exception": None,
        "false_positive_keywords": ["重入", "reentrancy", "recursive", "re-entry", "reentrant"],
        "exclude_keywords": [],
    },
    "double_spend": {
        "description": "双花攻击",
        "protection": "线性类型系统",
        "exception": "struct with copy ability",
        "false_positive_keywords": ["双花", "double spend", "duplicate"],
        "exclude_keywords": [],
    },
    "init_replay": {
        "description": "init 重复调用",
        "protection": "Sui 运行时",
        "exception": None,
        "false_positive_keywords": ["重复初始化", "re-init", "init.*again"],
        "exclude_keywords": [],
    },
    "txcontext_forge": {
        "description": "TxContext 伪造",
        "protection": "VM 注入",
        "exception": None,
        "false_positive_keywords": ["伪造.*TxContext", "forge.*context"],
        "exclude_keywords": [],
    },
    "memory_safety": {
        "description": "内存安全问题",
        "protection": "Borrow Checker",
        "exception": None,
        "false_positive_keywords": ["悬垂", "dangling", "use after", "memory leak"],
        "exclude_keywords": [],
    },
}

# 真正需要关注的漏洞类型
REAL_VULNERABILITY_TYPES = {
    "ability_misuse": {
        "description": "Ability 滥用",
        "severity": "CRITICAL",
        "patterns": ["copy.*drop", "has drop.*Receipt", "has copy.*Token"],
    },
    "shared_capability": {
        "description": "Capability 被共享",
        "severity": "CRITICAL",
        "patterns": ["share_object.*Cap", "public_share.*Admin"],
    },
    "generic_type_attack": {
        "description": "泛型类型攻击",
        "severity": "HIGH",
        "patterns": ["Coin<T>.*without.*type.*check"],
    },
    "precision_loss": {
        "description": "精度损失",
        "severity": "HIGH",
        "patterns": ["/ .* \\*", "divide.*before.*multiply"],
    },
    "bitwise_overflow": {
        "description": "位运算溢出",
        "severity": "HIGH",
        "patterns": ["<< ", ">> ", "shift"],
    },
}


def is_likely_false_positive(vuln_type: str, description: str) -> tuple:
    """
    判断是否可能是误报

    🔥 v2.5.13: 重构逻辑，支持 exclude_keywords
    🔥 v2.5.23: 添加真实漏洞保护，防止类型检查缺失等真实漏洞被误过滤

    Returns:
        (is_false_positive: bool, reason: str)
    """
    import re
    desc_lower = description.lower()
    vuln_type_lower = vuln_type.lower()

    # 🔥 v2.5.23: 真实漏洞保护 - 这些是开发者逻辑错误，不是语言级误报
    # 类型检查缺失漏洞：开发者忘记验证泛型类型参数是否匹配
    # 例如：闪电贷借出 Coin<A> 但归还时未验证还的也是 Coin<A>
    # 🔥 v2.5.24: 扩展关键词，覆盖"资产一致性"、"type_name"等变体
    real_vulnerability_keywords = [
        # 类型检查缺失
        "类型一致", "类型不一致", "类型检查", "类型验证",
        "type.*consist", "type.*mismatch", "type.*check", "type.*validation",
        "类型混淆", "type.*confusion", "coin.*类型",
        # 🔥 v2.5.24: 资产一致性相关 (原始漏洞描述常用词)
        "资产一致", "资产.*一致", "资产类型", "asset.*type", "asset.*consist",
        "未验证.*资产", "资产.*未.*验证", "资产.*未.*校验",
        # 🔥 v2.5.24: type_name 字段相关
        "type_name", "typename", "类型名", "类型字段",
        "忽略.*type", "ignore.*type", "discard.*type",
        # 泛型类型攻击
        "泛型.*未.*验证", "generic.*not.*valid", "泛型.*攻击",
        # 闪电贷类型问题
        "闪贷.*类型", "flashloan.*type", "还款.*类型", "repay.*type",
        "借出.*还", "borrow.*repay.*different",
        "闪贷.*一致", "闪贷.*资产", "flashloan.*asset",
        # 🔥 v2.5.24: 归还/还款相关
        "归还.*验证", "归还.*检查", "归还.*一致", "归还.*类型",
        "repay.*验证", "repay.*检查", "repay.*valid",
        # 其他真实逻辑漏洞关键词
        "未验证.*类型", "未校验.*类型", "未检查.*类型",
        # 🔥 v2.5.24: 结构体字段被丢弃 (常见漏洞模式)
        "字段.*忽略", "字段.*丢弃", "field.*ignored", "field.*discarded",
        "_.*忽略", "用.*_.*丢弃",
    ]

    for kw in real_vulnerability_keywords:
        kw_lower = kw.lower()
        if ".*" in kw_lower:
            if re.search(kw_lower, desc_lower):
                return False, ""  # 不是误报，是真实漏洞
        elif kw_lower in desc_lower:
            return False, ""  # 不是误报，是真实漏洞

    for vtype, info in PROTECTED_VULNERABILITY_TYPES.items():
        # 检查是否匹配保护类型
        matched = False

        # 1. 检查漏洞类型名是否匹配
        if vtype in vuln_type_lower:
            matched = True

        # 2. 检查关键词是否匹配 (支持正则)
        if not matched:
            for kw in info.get("false_positive_keywords", []):
                kw_lower = kw.lower()
                if ".*" in kw_lower:
                    # 正则模式
                    if re.search(kw_lower, desc_lower):
                        matched = True
                        break
                elif kw_lower in desc_lower:
                    matched = True
                    break

        if not matched:
            continue

        # 3. 🔥 v2.5.13: 检查排除关键词 (如果存在位移相关词，不过滤)
        exclude_keywords = info.get("exclude_keywords", [])
        if exclude_keywords:
            excluded = any(
                ex_kw.lower() in desc_lower for ex_kw in exclude_keywords
            )
            if excluded:
                # 描述中包含排除关键词，跳过此保护类型
                continue

        # 4. 检查是否有需要人工审查的例外情况
        if info.get("exception"):
            return False, f"需要检查是否存在例外情况: {info['exception']}"

        # 5. 确认为误报
        return True, f"Sui Move 语言级保护: {info['protection']}"

    return False, ""
