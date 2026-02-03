"""
Move 安全机制知识库 - v2.5.25

🔥 v2.5.25 重大更新: 所有安全机制知识都要求"先检查代码再判断"
- 每个条目添加 "🎯 判断流程" 部分
- 每个条目添加 "⚠️ 仍是真实漏洞的情况" 部分
- 防止 AI 只看到"有机制"就误判为"安全"

直接注入到 Verifier prompt 中，不需要 Agent 主动查询。
根据漏洞关键词自动匹配相关知识。

主题列表 (14个):
- operators: ⚠️ 运算符区分 (< vs <<)
- overflow: 算术溢出保护
- reentrancy: 重入攻击免疫
- type_safety: 泛型类型系统安全
- capability: Capability 访问控制 (含 _: &AdminCap 模式)
- layered_design: 🆕 分层设计模式 (底层模块被上层保护)
- hot_potato: Hot Potato 模式
- init_protection: init() 函数保护
- private_function: 函数可见性保护
- shared_object: 共享对象模式
- vector_safety: Vector 边界检查
- borrow_checker: Borrow Checker 所有权模型
- sui_object: Sui Object 模型安全
- bit_shift: ⚠️ 位移溢出危险
"""

from typing import List, Set

# =============================================================================
# Move 安全机制知识 (精简版，用于 prompt 注入)
# =============================================================================

MOVE_SECURITY_KNOWLEDGE = {
    "operators": """### ⚠️ Move 运算符区分 (常见混淆)
**比较运算符** (返回 bool):
- `<`  小于
- `>`  大于
- `<=` 小于等于
- `>=` 大于等于
- `==` 等于
- `!=` 不等于

**位运算符** (返回整数):
- `<<` 左移 (bit shift left)
- `>>` 右移 (bit shift right)
- `|`  按位或
- `&`  按位与
- `^`  按位异或

**常见混淆案例**:
```move
assert!(role < 128, E);     // < 是比较，检查 role 是否小于 128
*perms = *perms | (1 << role);  // << 才是位移
```
上面的 `role < 128` 是**边界检查**，不是位移操作！

**分析代码时务必区分**:
- `x < 128` → 比较运算，检查 x 是否小于 128
- `x << 7`  → 位移运算，将 x 左移 7 位""",

    "overflow": """### 算术溢出/下溢保护 (Move 语言级) ⚠️ 参考规则

**Move 语言保护**: Move VM 对 +, -, *, / 自动进行溢出/下溢检查
- 溢出/下溢时交易 **abort**，不会静默回绕
- **不需要** SafeMath，这是 Solidity 的模式

⚠️ **仍是真实漏洞的情况**:
- 涉及位移操作 (<<, >>) → 位移**不受保护**，可能溢出!
- 使用 `wrapping_add/sub/mul` 的代码 → 故意允许溢出
- 开发者逻辑错误导致的计算问题

🎯 **判断逻辑**:
- 纯算术溢出 (非位移) → 通常是误报
- 位移溢出或逻辑错误 → 需要审查代码""",

    "reentrancy": """### 重入攻击免疫 (Move 语言级)

**Move 语言保护:**
- Move 没有动态调度 (dynamic dispatch)
- 所有函数调用在编译时确定，无法运行时改变
- 没有 Solidity 的 fallback/receive 回调
- 资源在任何时刻只能被一个执行上下文访问

**结论**: 传统重入攻击在 Move 中**不可能发生**

**🎯 判断流程:**
1. **确认是否真的是"重入"**: 漏洞描述是否指传统重入？还是被误标了？
2. **检查是否是其他问题**: 可能是状态不一致、逻辑错误等被误标为"重入"
3. **检查跨合约调用**: 虽然不能重入，但跨合约调用的状态管理是否正确？

⚠️ **可能被误标为"重入"的真实问题:**
- **状态更新顺序错误**: 先转账后更新余额 (虽然不能重入，但逻辑可能有问题)
- **跨模块状态不一致**: 模块 A 和模块 B 的状态更新不同步
- **闪电贷攻击**: 不是重入，但可能被误标

**如果漏洞描述确实是传统重入攻击 → 误报**""",

    "type_safety": """### 泛型类型系统安全 (Move 语言级) ⚠️ 注意开发者逻辑错误

**Move 类型系统保护**:
- 泛型参数 T 在编译时确定，无法运行时"构造任意类型"
- `bag::remove<K, V>()` 必须 V 与存储的实际类型精确匹配
- `type_name::get<T>()` 返回的类型路径是唯一的，包含完整包 ID
- Move 无法把 Coin<A> 伪造成 Coin<B>

⚠️ **仍是真实漏洞的情况 (开发者逻辑错误)**:
- **类型检查缺失**: 开发者忘记验证泛型参数是否匹配预期
  - 例: 闪电贷借出 Coin<A>，但归还时未检查是否也是 Coin<A>
  - 例: Receipt 中记录了类型，但归还时忽略了类型字段
- **类型不一致**: 两个相关操作使用了不同的类型参数
  - 例: 借款用类型 A，还款用类型 B (都是池中合法类型，但不匹配)

🔴 **关键漏洞模式 - 字段被丢弃**:
```move
// 危险! type_name 字段被 _ 忽略，没有用于验证
let FlashReceipt { pool_id, type_name: _, amount } = receipt;
//                          ^^^^^^^^^^^ 真实漏洞!
```
正确做法应该是:
```move
let FlashReceipt { pool_id, type_name, amount } = receipt;
assert!(type_name::get<T>() == type_name, E_TYPE_MISMATCH);
```

🎯 **判断逻辑**:
- "类型伪造"、"构造任意类型" → 通常是误报 (语言级保护)
- "类型检查缺失"、"类型不一致"、"未验证类型" → 可能是真实漏洞 (开发者错误)
- "字段被忽略"、"type_name: _" → 很可能是真实漏洞 (需检查该字段是否应被验证)""",

    "capability": """### Capability 访问控制模式 (Sui 设计模式)

**Capability 模式原理:**
```move
public fun some_function(_: &AdminCap, ...)  // ← 需要 AdminCap 才能调用
public entry fun do_action(_: &OwnerCap, ...)  // ← 需要 OwnerCap 才能调用
```

**🎯 判断流程 (必须先检查代码!):**
1. **确认 Cap 参数存在**: 查看函数签名是否有 `&AdminCap`, `&OwnerCap` 等
2. **确认 Cap 来源安全**: Cap 是在 init() 中创建并转给部署者的吗？
3. **确认 Cap 没有被共享**: `share_object(admin_cap)` 会让任何人都能调用！
4. **确认权限粒度正确**: 这个操作是否应该需要更高级别的权限？

⚠️ **仍是真实漏洞的情况:**
- **Cap 被共享**: `transfer::share_object(admin_cap)` → 任何人都是管理员
- **Cap 创建位置错误**: Cap 在非 init() 函数中创建，可被多次调用
- **权限粒度不足**: 用 UserCap 控制应该用 AdminCap 的操作
- **Cap 检查被绕过**: 函数 A 需要 Cap，但函数 B 不需要却能完成同样操作

**常见误报 (需先确认以上检查通过):**
- "缺少访问控制" → 如果有 `&XXXCap` 参数且来源安全 → 误报
- "任意用户可调用" → 如果需要 Capability → 误报""",

    "layered_design": """### 分层设计模式 (模块化架构)

**典型分层结构:**
```
上层模块 (如 config.move):
  public fun add_role(_: &AdminCap, ...) {
    acl::add_role(...)  // 调用底层
  }

底层模块 (如 acl.move):
  public fun add_role(acl, member, role)  // 无 Cap，但只被上层调用
```

**🎯 判断流程 (必须先检查代码!):**
1. **找到所有调用者**: 使用工具查找谁调用了这个底层函数
2. **检查每个调用者的权限**: 所有调用者都有 Cap 检查吗？
3. **确认没有直接暴露**: 底层函数是 public 还是 public(package)？
4. **检查是否有绕过路径**: 是否存在不经过上层直接调用底层的方式？

⚠️ **仍是真实漏洞的情况:**
- **上层也没有权限检查**: 上层函数也是 public 且没有 Cap
- **存在多个调用路径**: 上层 A 有权限，但上层 B 没有
- **底层是 public 而非 public(package)**: 外部可直接调用
- **权限检查不一致**: 部分操作有检查，部分没有

**常见误报 (需先确认以上检查通过):**
- "底层函数无权限检查" → 如果**所有**上层调用者都有 Cap → 误报
- "公开函数可被任意调用" → 如果是 public(package) 或上层有控制 → 误报""",

    "hot_potato": """### Hot Potato 模式 (闪电贷强制还款)
- Receipt 结构体只有 `key` 没有 `drop` 能力
- 必须调用 `repay()` 消费 Receipt，否则交易失败
- 这是编译器强制的，**无法绕过**
- **常见误报**: "闪电贷无强制还款机制" - 检查 Receipt 是否有 drop 能力

⚠️ **Hot Potato 不保护类型检查！以下仍是真实漏洞:**
- **类型不一致**: 借 Coin<A> 但还 Coin<B> (两种都是池中合法币种)
- **type_name 未验证**: Receipt 记录了 type_name，但 repay 时用 `_` 忽略了它
- **泛型参数未校验**: `repay<T>` 只检查 T 是否在池中，没检查是否等于借出类型

🔴 **关键代码模式 (真实漏洞)**:
```move
// 危险! type_name 被忽略 (用 _ 丢弃)
let FlashReceipt { pool_id, type_name: _, amount } = receipt;
```
这意味着攻击者可以借高价值代币A，用低价值代币B还款！""",

    "init_protection": """### init() 函数保护 (Sui 运行时)

**Sui 运行时保护:**
- `init(witness, ctx)` 只在模块发布时由 Sui 运行时调用
- **只能调用一次**，外部无法调用
- One-Time Witness (OTW) 只有 `drop` 能力，用后即销毁

**🎯 判断流程:**
1. **确认漏洞是否关于 init 重复调用**: 如果是 → 误报
2. **检查 init 内部逻辑**: init 只调用一次，但逻辑本身可能有问题
3. **检查 Capability 分配**: init 中创建的 Cap 是否正确分配？

⚠️ **仍是真实漏洞的情况:**
- **init 逻辑错误**: init 内部的权限分配、初始状态设置有问题
- **Cap 分配错误**: `transfer::share_object(admin_cap)` 而不是给部署者
- **敏感对象共享**: init 中错误地共享了应该私有的对象
- **初始参数硬编码错误**: 如费率、地址等硬编码错误

**常见误报:**
- "init 可被重复调用" → 运行时保证只调用一次 → 误报
- "OTW 可被伪造" → OTW 由运行时注入 → 误报

**但如果漏洞是关于 init 内部逻辑 → 需要检查代码确认**""",

    "private_function": """### 函数可见性保护 (Move 语言级)

**可见性级别:**
- `fun` (无 public): 私有函数，只能模块内部调用
- `public(package) fun`: 只能同一 package 内调用
- `public fun`: 外部可调用
- `entry fun`: 只能作为交易入口

**🎯 判断流程 (必须先检查代码!):**
1. **确认函数的实际可见性**: 读取代码确认是 fun/public(package)/public
2. **检查调用链**: 私有函数被哪些公开函数调用？那些公开函数有权限检查吗？
3. **检查同 package 内的调用者**: public(package) 函数被谁调用？

⚠️ **仍是真实漏洞的情况:**
- **公开函数调用私有函数**: 私有函数安全，但调用它的公开函数没有权限检查
- **同 package 内有不安全调用者**: public(package) 函数被同 package 的公开函数无权限调用
- **entry 函数参数验证不足**: entry 函数是入口，参数可能被恶意构造

**常见误报 (需先确认以上检查通过):**
- "私有函数缺少访问控制" → 如果调用链上有权限检查 → 误报
- "public(package) 可被调用" → 只能包内调用，检查包内调用者 → 可能是误报""",

    "shared_object": """### 共享对象模式 (Sui 设计模式)

**共享对象原理:**
- `share_object()` 使对象全局可访问
- 访问权限需通过代码逻辑控制 (Capability、ACL 或业务检查)
- Sui 共识层提供并发安全

**🎯 判断流程 (必须先检查代码!):**
1. **检查所有修改函数**: 哪些函数可以修改这个共享对象？
2. **逐个检查权限控制**: 每个修改函数是否有 Cap 检查或其他访问控制？
3. **检查敏感字段**: 关键字段（如余额、价格）的修改是否受保护？
4. **检查初始化逻辑**: 对象创建后是否正确设置了初始状态？

⚠️ **仍是真实漏洞的情况:**
- **修改函数无权限检查**: `public fun set_price(&mut obj, price)` 无 Cap
- **部分函数有检查，部分没有**: 不一致的权限模型
- **敏感操作暴露**: 如 `withdraw` 函数任何人都能调用
- **初始化状态错误**: 对象创建时权限配置不正确

**常见误报 (需先确认以上检查通过):**
- "共享对象可被任意修改" → 如果**所有**修改函数都有权限检查 → 误报""",

    "vector_safety": """### Vector 边界检查 (Move 语言级) ⚠️ 参考规则

**Move 语言保护**: Move 的 vector 操作自动边界检查
- `vector::borrow(v, i)` → 越界时 **abort**
- `vector::borrow_mut(v, i)` → 越界时 **abort**
- `vector::pop_back(v)` → 空 vector 时 **abort**
- `vector::remove(v, i)` → 越界时 **abort**

⚠️ **仍需审查的情况**:
- 两个向量长度不一致导致的逻辑错误
- 开发者遗漏的边界条件检查

🎯 **判断逻辑**:
- 纯越界访问 → 通常是误报 (Move 自动 abort)
- 向量长度不匹配导致的逻辑问题 → 可能是真实漏洞""",

    "borrow_checker": """### Borrow Checker 所有权模型 (Move 语言级)

**Move Borrow Checker 保护:**
- 编译时验证引用的有效性
- 同一时刻只能有一个可变引用 (`&mut`) 或多个不可变引用 (`&`)
- 引用不能超过被引用值的生命周期
- 不存在悬垂引用 (dangling reference)

**🎯 判断流程:**
1. **确认漏洞是否关于引用安全**: 悬垂引用、use-after-free 等
2. **检查是否被误标**: 可能是其他逻辑问题被误标为引用问题
3. **检查代码逻辑**: 虽然引用安全，但业务逻辑是否正确？

⚠️ **可能被误标为"引用问题"的真实问题:**
- **逻辑错误**: 引用的对象状态不是预期的
- **时序问题**: 先读后写的顺序导致读到过期数据
- **并发问题**: 共享对象的并发访问逻辑错误

**如果漏洞描述确实是 use-after-free/悬垂引用 → 误报 (编译器已阻止)**
**如果是其他逻辑问题 → 需要具体分析代码**""",

    "sui_object": """### Sui Object 模型安全 (Sui 运行时)

**Sui Object 类型:**
- **Owned Object**: 只有所有者能使用，单签名验证
- **Shared Object**: 全局可访问，但修改需通过函数逻辑控制
- **Immutable Object**: 发布后不可修改，freeze_object() 创建

**Sui 运行时保护:**
- 对象 ID 唯一，无法伪造
- 所有权由运行时验证

**🎯 判断流程 (必须先检查代码!):**
1. **确认对象类型**: 是 Owned、Shared 还是 Immutable？
2. **检查 transfer 调用**: transfer 是在什么上下文中调用的？有权限检查吗？
3. **检查共享对象的修改函数**: 如果是 Shared，谁能修改它？
4. **检查对象创建和初始化**: 对象是否正确初始化？所有权是否正确分配？

⚠️ **仍是真实漏洞的情况:**
- **transfer 无权限检查**: `public fun transfer_nft(nft) { transfer::transfer(nft, ...) }` 任何人可转移
- **共享对象修改无控制**: 如前所述
- **对象所有权分配错误**: 应该给用户的对象给了合约
- **freeze 时机错误**: 应该冻结的对象没有冻结

**常见误报 (需先确认以上检查通过):**
- "对象可被任意转移" → 如果 transfer 有权限检查 → 误报
- "对象 ID 可伪造" → 运行时保证唯一性 → 误报""",

    "bit_shift": """### ⚠️ 位移操作危险 (Move 特殊行为)
**重要警告**: Move 位移操作 (<<, >>) 与算术运算不同！
- 算术运算 (+, -, *, /): 溢出时 **abort**
- 位移运算 (<<, >>): 溢出时 **静默截断，不会 abort**！

**安全模式** (可能是误报):
- `1 << role` 其中 role < 128 - 小常量位移，结果不会溢出
- ACL 权限位设置配合边界检查
- 位移量是编译时常量且在安全范围内

**危险模式** (需要审查):
- 用户可控值的位移: `user_value << 64`
- 大数值数学计算中的位移: `price << 64`
- 自定义的 checked_shift 函数 - 检查条件可能有误
- 位移结果参与金额/价格计算""",
}

# =============================================================================
# 关键词 -> 知识主题映射
# =============================================================================

KEYWORD_TO_TOPICS = {
    # 运算符相关 (防止 < 和 << 混淆)
    "位移": ["operators", "bit_shift"],
    "shift": ["operators", "bit_shift"],
    "<<": ["operators", "bit_shift"],
    ">>": ["operators", "bit_shift"],
    "左移": ["operators", "bit_shift"],
    "右移": ["operators", "bit_shift"],
    "< 128": ["operators"],  # 常见边界检查，可能被误认为位移
    "< 64": ["operators"],
    "role <": ["operators"],  # ACL 边界检查

    # 溢出相关
    "overflow": ["overflow"],
    "溢出": ["overflow"],
    "arithmetic": ["overflow"],
    "算术": ["overflow"],
    "加法": ["overflow"],
    "乘法": ["overflow"],
    "除法": ["overflow"],
    "underflow": ["overflow"],
    "下溢": ["overflow"],

    # 重入相关
    "reentrancy": ["reentrancy"],
    "reentrant": ["reentrancy"],
    "重入": ["reentrancy"],
    "re-entry": ["reentrancy"],

    # 类型相关
    "type confusion": ["type_safety"],
    "类型混淆": ["type_safety"],
    "arbitrary type": ["type_safety"],
    "任意类型": ["type_safety"],
    "任意代币": ["type_safety"],
    "forge type": ["type_safety"],
    "伪造类型": ["type_safety"],
    "coin<": ["type_safety"],
    "泛型": ["type_safety"],

    # 权限相关 (包含分层设计判断)
    "access control": ["capability", "private_function", "layered_design"],
    "access_control": ["capability", "private_function", "layered_design"],  # 下划线版本
    "访问控制": ["capability", "private_function", "layered_design"],
    "permission": ["capability", "layered_design"],
    "权限": ["capability", "layered_design"],
    "unauthorized": ["capability", "private_function", "layered_design"],
    "未授权": ["capability", "private_function", "layered_design"],
    "任意用户": ["capability", "private_function", "layered_design"],
    "任意调用": ["capability", "private_function", "layered_design"],
    "anyone can": ["capability", "private_function", "layered_design"],
    "missing.*check": ["capability", "layered_design"],
    "缺少.*检查": ["capability", "layered_design"],
    "admincap": ["capability"],
    "ownercap": ["capability"],
    "_:": ["capability"],  # 下划线参数模式
    "acl": ["capability", "layered_design"],  # ACL 模块常见分层
    "辅助模块": ["layered_design"],
    "底层": ["layered_design"],
    "helper": ["layered_design"],
    "utils": ["layered_design"],

    # 闪电贷相关 - 🔥 v2.5.24: 同时注入 type_safety 知识，防止忽略类型检查漏洞
    "flash loan": ["hot_potato", "type_safety"],
    "flashloan": ["hot_potato", "type_safety"],
    "闪电贷": ["hot_potato", "type_safety"],
    "flash swap": ["hot_potato", "type_safety"],
    "receipt": ["hot_potato", "type_safety"],
    "还款": ["hot_potato", "type_safety"],
    "repay": ["hot_potato", "type_safety"],
    "hot potato": ["hot_potato"],
    "强制还款": ["hot_potato"],
    # 🔥 v2.5.24: 资产一致性关键词
    "资产一致": ["type_safety"],
    "资产类型": ["type_safety"],
    "type_name": ["type_safety"],
    "归还.*验证": ["type_safety"],

    # 初始化相关
    "init": ["init_protection"],
    "初始化": ["init_protection"],
    "重复调用": ["init_protection"],
    "one-time witness": ["init_protection"],
    "otw": ["init_protection"],

    # 可见性相关
    "public function": ["private_function"],
    "公开函数": ["private_function"],
    "internal function": ["private_function"],
    "内部函数": ["private_function"],
    "package": ["private_function"],

    # 共享对象相关
    "shared object": ["shared_object"],
    "共享对象": ["shared_object"],
    "global access": ["shared_object"],

    # 数组相关
    "vector": ["vector_safety"],
    "array": ["vector_safety"],
    "数组": ["vector_safety"],
    "index out": ["vector_safety"],
    "越界": ["vector_safety"],
    "bounds": ["vector_safety"],

    # Borrow Checker 相关
    "borrow": ["borrow_checker"],
    "借用": ["borrow_checker"],
    "reference": ["borrow_checker"],
    "引用": ["borrow_checker"],
    "&mut": ["borrow_checker"],
    "mutable reference": ["borrow_checker"],
    "dangling": ["borrow_checker"],
    "悬垂": ["borrow_checker"],
    "use after": ["borrow_checker"],
    "lifetime": ["borrow_checker"],
    "生命周期": ["borrow_checker"],

    # Sui Object 相关
    "object": ["sui_object"],
    "对象": ["sui_object"],
    "owned object": ["sui_object"],
    "shared object": ["sui_object", "shared_object"],
    "immutable object": ["sui_object"],
    "transfer": ["sui_object"],
    "转移": ["sui_object"],
    "freeze": ["sui_object"],
    "object id": ["sui_object"],
}


def get_relevant_knowledge(finding: dict) -> str:
    """
    根据漏洞描述自动提取相关 Move 安全知识

    Args:
        finding: 漏洞发现字典，包含 title, description, category 等

    Returns:
        相关知识字符串，用于注入到 Verifier prompt
    """
    # 提取文本
    title = finding.get("title", "")
    description = finding.get("description", "")
    category = finding.get("category", "")
    combined = f"{title} {description} {category}".lower()

    # 匹配相关主题
    matched_topics: Set[str] = set()

    for keyword, topics in KEYWORD_TO_TOPICS.items():
        # 支持简单的正则模式
        if ".*" in keyword:
            import re
            if re.search(keyword, combined):
                matched_topics.update(topics)
        elif keyword in combined:
            matched_topics.update(topics)

    if not matched_topics:
        return ""

    # 构建知识字符串 (最多 3 个主题)
    knowledge_parts = []
    for topic in list(matched_topics)[:3]:
        if topic in MOVE_SECURITY_KNOWLEDGE:
            knowledge_parts.append(MOVE_SECURITY_KNOWLEDGE[topic])

    if not knowledge_parts:
        return ""

    return f"""
## 🔥 Move 安全机制参考 - ⚠️ 必须先检查代码再判断!

以下是与此漏洞相关的 Move/Sui 安全机制。

🔴 **重要原则:**
1. **不能只看机制名就判断安全** - 必须检查代码确认机制是否真正生效
2. **语言级保护防不了开发者逻辑错误** - 如忘记检查类型、错误的权限分配
3. **按照"判断流程"逐步检查** - 不要跳过任何步骤

{chr(10).join(knowledge_parts)}

---
"""


def get_all_knowledge_summary() -> str:
    """
    获取所有知识的摘要 (用于 System Prompt)

    🔥 v2.5.23: 改为参考规则，强调开发者逻辑错误仍是真实漏洞
    """
    return """
## ⚠️ Move 安全机制参考 - 必须先检查代码再判断!

🔴 **核心原则:**
- **不能只看机制名就说安全** - 必须检查代码确认机制是否真正生效
- **语言级保护防不了开发者逻辑错误** - 如忘记类型检查、错误的权限分配
- 每个知识条目都有"判断流程"，**必须逐步检查**

## Move/Sui 语言级保护 (仅防特定攻击模式)

| 保护机制 | 能防什么 | 防不了什么 |
|---------|---------|-----------|
| 算术溢出检查 | +,-,*,/ 溢出回绕 | 位移溢出、逻辑计算错误 |
| 无动态调度 | 传统重入攻击 | 状态管理错误、闪电贷攻击 |
| 类型系统 | 运行时伪造类型 | 开发者忘记验证类型参数 |
| Hot Potato | 丢弃 Receipt | 还款时类型不匹配 |
| Capability | 无 Cap 调用 | Cap 被共享、权限粒度错误 |
| init 只调用一次 | 重复初始化 | init 内部逻辑错误 |

## 🔴 开发者逻辑错误 (语言保护不了!)

| 漏洞模式 | 示例 |
|---------|------|
| **类型检查缺失** | 借 Coin<A> 还 Coin<B>，`type_name: _` 被丢弃 |
| **权限分配错误** | `share_object(admin_cap)` 让任何人都是管理员 |
| **检查不完整** | 部分路径有权限检查，部分没有 |
| **字段被忽略** | 结构体解构时用 `_` 丢弃关键字段 |
| **逻辑不一致** | 借款和还款使用不同的条件 |

## 判断流程 (每次都要做!)

1. **读取相关代码** - 不能只看漏洞描述
2. **确认机制是否存在** - Cap 真的存在吗？Receipt 真的没有 drop 吗？
3. **确认机制是否生效** - Cap 没被共享？类型检查没被跳过？
4. **检查所有路径** - 是否所有调用路径都有保护？
5. **最终判断** - 只有以上都确认后才能判断误报
"""
