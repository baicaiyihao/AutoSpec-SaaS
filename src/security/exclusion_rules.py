"""
排除规则模块 - 过滤明显的非安全漏洞

v2.5.0: 从 engine.py 提取，独立管理
v2.5.1: 新增 Sui Move 安全模式排除规则 (规则 7-12)
v2.5.4: 新增 Mock/CTF 项目排除规则 (规则 18-19)
        - 修复 rule_14 mock 函数检测逻辑，支持外部模块 mock
        - 新增 rule_18 检测调用会 abort 的框架函数
        - 新增 rule_19 检测 CTF/测试项目特征
v2.5.5: 新增生产级合约审计规则 (规则 20-22)
        - 基于 Cetus CLMM 审计分析
        - rule_20: #[test_only] 测试专用函数过滤
        - rule_21: 低层模块设计模式识别 (acl, math 等)
        - rule_22: 被 Wrapper 保护的内部函数 (*_internal)
v2.5.14: 新增误报过滤规则 (规则 28-31)
        - 基于 Cetus CLMM 审计误报分析
        - rule_28: Sui Publisher 访问控制模式 (Publisher 是发布者专属)
        - rule_29: 管理员权限内的业务决策 (有权限检查的参数范围问题)
        - rule_30: 版本保护安全特性 (version >= before_version 是安全设计)
        - rule_31: 用户自愿承担的风险 (fix_amount 等函数的滑点风险)
v2.5.15: 新增通用误报过滤规则 (规则 32-39)
        - 基于 Cetus CLMM 源码深度分析
        - rule_32: 参数在源头已验证 (Partner fee_rate 等)
        - rule_33: 交易原子性保护 (Move 交易失败会回滚，无状态不一致)
        - rule_34: 故意的零值断言 (ref_fee_amount == 0 是设计意图)
        - rule_35: 精度截断 vs 溢出 (有范围检查的 u128->u64 是精度问题)
        - rule_36: 动态字段内部状态管理 (pending 等内部状态)
        - rule_37: 公开 Getter 函数无需权限控制
        - rule_38: 滑点参数由用户控制 (sqrt_price_limit)
        - rule_39: 频率/速率限制是治理问题 (有角色检查时)
v2.5.16: 深度误报过滤 (规则 40-45, 修复 rule_8, rule_37)
        - 基于 Cetus CLMM 审计 43 个确认漏洞的深度分析
        - 修复 rule_8: 也检查描述中是否提到 public(package)
        - 修复 rule_37: 增加信息暴露相关关键词
        - rule_40: Sui 对象所有权模型 (&Position 参数 = 所有者验证)
        - rule_41: Move copy/drop 能力保护 (编译器强制类型安全)
        - rule_42: 深度防御是安全实践 (双重检查不是漏洞)
        - rule_43: 代码质量问题 vs 安全漏洞 (循环优化等)
        - rule_44: Sui Display 模式 (transfer 给用户是正常设计)
        - rule_45: 区块链数据天然公开 (暴露状态不是漏洞)
v2.5.17: 通用资源伪造检测 (规则 49)
        - rule_49: Move 资源无法伪造 (类型系统保证 struct 只能由定义模块创建)
        - 过滤 "伪造 Tick/Position/Pool 数据" 等误报
        - Move 没有反射/序列化绕过机制，类型安全是语言级保证
v2.5.18: 设计选择与数学特性 (规则 50-53)
        - rule_50: 设计选择不是漏洞 (向上取整保护协议、费用分配比例是业务决策)
        - rule_51: 精度截断是数学特性 (定点数系统都有精度损失，无攻击向量不是漏洞)
        - rule_52: 编译时确定的值 (type_name 编译时确定，用户无法操控)
        - rule_53: 无效的漏洞格式 (Location 为空、代码为 N/A 等无效报告)
v2.5.19: 语义和猜测性漏洞 (规则 54-55)
        - rule_54: 状态字段语义是设计选择 (is_pause 语义由开发者定义，不是漏洞)
        - rule_55: 猜测性漏洞 ("虽未显示"、"若其实现中" 等猜测性描述)
        - 增强 rule_36: 动态字段借用相关误报检测
        - 增强 rule_51: 精度截断覆盖 fee_delta, fixed-point math
v2.5.20: 注释代码和管理员功能 (规则 56-57)
        - rule_56: 注释掉的代码不是运行时漏洞 (开发者可能有意为之)
        - rule_57: 管理员功能是设计选择 (有权限检查的 emergency_pause 等)
v2.5.21: 命名问题和治理设计 (规则 58-59)
        - rule_58: 拼写错误/命名问题不是安全漏洞 (upper_socre 等命名错误)
        - rule_59: 治理延迟是设计选择 (即时更新 vs timelock 是设计决策)
v2.5.22: Move 类型安全和管理员操作 (规则 60-62)
        - rule_60: 管理员操作的重放问题 (mint_cap 多次调用是设计选择)
        - rule_61: 管理员输入验证 (URL 格式等由管理员控制)
        - rule_62: Move 类型名碰撞不可能 (type_name 包含完整路径，攻击者无法伪造)
        - 增强 rule_50: 增加 "逻辑错误", "激励不足" 关键词
v2.5.23: 真实漏洞保护 (修复类型检查漏洞误过滤)
        - 修复 is_likely_false_positive: 添加真实漏洞关键词保护
        - 类型检查缺失是开发者逻辑错误，不是语言级误报
        - 保护关键词: "类型一致", "类型检查", "类型混淆", "泛型未验证" 等

使用方式:
    from src.security.exclusion_rules import apply_exclusion_rules

    to_verify, filtered = apply_exclusion_rules(raw_findings)
"""

import re
from typing import Dict, Any, List, Tuple, Callable
from dataclasses import dataclass

# 🔥 v2.5.8: 导入安全知识库的误报检测函数
try:
    from src.prompts.sui_move_security_knowledge import is_likely_false_positive
    HAS_SECURITY_KNOWLEDGE = True
except ImportError:
    HAS_SECURITY_KNOWLEDGE = False
    def is_likely_false_positive(vuln_type: str, description: str) -> tuple:
        return False, ""


# ============================================================================
# 🔥 v2.5.9: 排除规则配置
# ============================================================================
#
# =============================================================================
# 🔥 v2.5.13: 软过滤模式 - 平衡假阴性和假阳性
# =============================================================================
#
# 过滤模式说明：
# - DISABLE_ALL_EXCLUSION_RULES = True: 完全禁用，所有发现交给 AI（假阳性高）
# - SOFT_FILTER_MODE = True: 软过滤，规则命中的发现标记但不删除，AI 收到提示（推荐）
# - 两者都为 False: 硬过滤，规则命中直接删除（假阴性风险）
#
DISABLE_ALL_EXCLUSION_RULES = False  # 不再完全禁用
SOFT_FILTER_MODE = True  # 🔥 启用软过滤：标记但不删除，给 AI 提示

# 如果不想完全禁用，可以只禁用可能导致假阴性的规则
# 这些规则假设"使用了安全机制=安全"，但没考虑"使用了但忘记验证"的情况
DANGEROUS_RULES = [
    "rule_24",  # move_type_safety - 导致 week2 闪电贷漏洞被过滤
    "rule_49",  # resource_forge_impossible - 可能过滤开发者逻辑错误
    "rule_62",  # type_name_collision_impossible - 类型碰撞不可能≠类型验证正确
]


@dataclass
class ExclusionRule:
    """排除规则定义"""
    id: str                          # 规则 ID (如 "rule_7")
    name: str                        # 规则名称
    description: str                 # 规则描述
    check: Callable[[Dict[str, Any], str, str, str], bool]  # 检查函数
    reason: str                      # 过滤原因
    hard_filter: bool = False        # 🔥 v2.5.15: 是否硬过滤（即使 SOFT_FILTER_MODE=True）


# 🔥 v2.5.15: 高确信度规则 - 即使软过滤模式下也直接删除
# 这些规则基于 Sui Move 语言/运行时保证，不会有假阴性
HIGH_CONFIDENCE_RULES = [
    # === 语言/运行时级别保证 (17条) ===
    "rule_1",   # init_function - Sui 运行时保证只能发布时调用一次
    "rule_2",   # witness_forge - witness 类型路径唯一，无法伪造
    "rule_3",   # private_call - private 函数语言层面阻止外部调用
    "rule_4",   # txcontext_forge - TxContext 由运行时注入
    "rule_6",   # cross_module_forge - 跨模块对象无法伪造
    "rule_6b",  # reentrancy_immunity - Move 语言无动态调用，无重入
    "rule_6d",  # arithmetic_underflow - 算术下溢自动 abort
    "rule_6e",  # vector_bounds_safety - 向量越界自动 abort
    "rule_6g",  # arithmetic_overflow - 🔥 v2.5.24: 算术溢出自动 abort (不含位移!)
    "rule_8",   # package_visibility - public(package) 语言级保护
    "rule_11",  # clock_dependency - Clock 是 Sui 可信时间源
    "rule_33",  # transaction_atomicity_safety - Move/Sui 交易原子性
    "rule_40",  # sui_object_ownership - Sui 对象引用=所有者
    "rule_41",  # move_copy_drop_safety - Move 能力系统编译时强制
    "rule_48",  # readonly_reference_exposure - &T 只读引用是安全的
    "rule_52",  # compile_time_value - type_name 编译时确定
    "rule_67",  # hot_potato_protection - 🔥 v2.5.24: Hot Potato Receipt 无法伪造

    # === 非安全问题 (18条) ===
    "rule_6f",  # code_style_not_vulnerability - 代码风格问题
    "rule_10",  # event_function - Event 发射不影响状态
    "rule_13",  # hardcoded_constant - 硬编码常量是代码风格
    "rule_14",  # mock_function - Mock/测试函数 (abort 0 占位)
    "rule_15",  # pure_getter - 纯 getter 只读状态
    "rule_16",  # debug_assertion - 调试/断言信息
    "rule_19",  # ctf_test_project - CTF/测试项目
    "rule_20",  # test_only_function - #[test_only] / #[test] 函数
    "rule_23",  # deprecated_function - 废弃函数 abort 是预期
    "rule_37",  # public_getter_no_acl - 纯读取函数无需 ACL
    "rule_43",  # code_quality_not_security - 代码质量问题
    "rule_45",  # blockchain_public_data - 区块链数据天然公开
    "rule_47",  # correct_permission_model - 描述说权限正确
    "rule_53",  # invalid_finding_format - 无效漏洞格式
    "rule_55",  # speculative_vulnerability - 猜测性漏洞
    "rule_56",  # commented_code_issue - 注释掉的代码
    "rule_58",  # typo_naming_issue - 拼写/命名问题
    "rule_66",  # readonly_function_public - 只读函数公开是正常的
]


# ============================================================================
# Sui Move 语言层面保护规则 (规则 1-6)
# ============================================================================

def check_init_function_issue(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 1: init 函数相关问题"""
    if func_name != "init":
        return False
    return any(kw in combined for kw in [
        # 重复调用相关
        "reentrant", "重入", "重复调用", "multiple call", "再次调用",
        "重复初始化", "re-init", "double init", "多次调用", "already init",
        # 权限/身份验证相关
        "身份验证", "权限", "permission", "authorization", "access control",
        "未验证", "no check", "missing check", "缺少验证", "任意用户",
        "any user", "arbitrary", "调用者"
    ])


def check_witness_forge(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 2: witness 类型伪造"""
    if "witness" not in combined:
        return False
    return any(kw in combined for kw in [
        "forge", "fake", "伪造", "构造", "create"
    ])


def check_private_direct_call(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 3: private 函数直接调用"""
    visibility = finding.get("visibility", "")
    if visibility != "private":
        return False
    return any(kw in combined for kw in [
        "direct call", "直接调用", "external call", "外部调用"
    ])


def check_txcontext_forge(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 4: TxContext 伪造"""
    if "txcontext" not in combined:
        return False
    return any(kw in combined for kw in [
        "forge", "fake", "伪造", "spoof", "manipulate"
    ])


def check_overflow_bypass(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 5: 算术溢出绕过验证 (仅限普通算术运算 +, -, *, /)

    ⚠️ 重要: 此规则仅适用于 **普通算术运算** 溢出！
    - 普通算术 (+, -, *, /): Move VM 溢出时 **abort**，无法绕过
    - 位移运算 (<<, >>): Move VM 溢出时 **静默截断**，不会 abort！
    - wrapping_* 函数: 明确设计为回绕，**不会 abort**！

    因此，如果漏洞涉及位移或 wrapping_* 函数，**不应被此规则过滤**！
    2025 年 Cetus $223M 被盗就是因为位移溢出静默截断。
    """
    if not any(kw in combined for kw in ["overflow", "溢出", "wrapping"]):
        return False

    # ⚠️ 位移操作溢出不会 abort，不应被过滤！
    bit_shift_keywords = [
        "<<", ">>", "位移", "shift", "shl", "shr",
        "left shift", "right shift", "左移", "右移",
        "checked_shl", "checked_shr", "checked_shlw"
    ]
    if any(kw in combined for kw in bit_shift_keywords):
        return False  # 位移相关的溢出问题不过滤

    # ⚠️ wrapping_* 函数明确设计为回绕，不应被过滤！
    wrapping_keywords = [
        "wrapping_add", "wrapping_sub", "wrapping_mul", "wrapping_div",
        "wrapping_shl", "wrapping_shr"
    ]
    if any(kw in combined for kw in wrapping_keywords):
        return False  # wrapping_* 函数相关的问题不过滤

    return any(bypass_kw in combined for bypass_kw in [
        "bypass", "绕过", "circumvent", "avoid", "skip", "evade",
        "回绕", "wrap around", "wrap to", "become small", "变小"
    ])


def check_cross_module_forge(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 6: 跨模块对象伪造"""
    if not any(kw in combined for kw in ["伪造对象", "fake object", "forge object", "construct.*struct"]):
        return False
    return any(cross_kw in combined for cross_kw in [
        "跨模块", "cross module", "external module", "another module", "other module"
    ])


def check_reentrancy_immunity(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 6b: 重入攻击免疫 (Move 语言级保护)

    Move 语言从设计上就免疫重入攻击：
    1. 没有动态调度 (dynamic dispatch) - 所有函数调用在编译时确定
    2. 没有 Solidity 的 fallback/receive 回调机制
    3. 资源在任何时刻只能被一个执行上下文访问
    4. 借用检查器 (borrow checker) 防止同时多个可变引用

    **结论**: Move 中重入攻击**不可能发生**，这是 Solidity 特有的漏洞模式。

    🔥 v2.5.14: 添加负向关键词，避免将"重入式"比喻误判为真正的重入攻击
    """
    reentrancy_keywords = [
        "reentrancy", "reentrant", "re-entry", "re-entrancy",
        "重入攻击", "递归调用攻击",
        "callback attack", "回调攻击",
        "cross-function reentrancy", "跨函数重入"
    ]

    # 🔥 v2.5.14: "重入"单独出现时需要更严格的检查
    # 因为"重入式"常被用作比喻，不是真正的重入攻击
    has_reentrancy_keyword = any(kw in combined for kw in reentrancy_keywords)
    has_simple_reentrancy = "重入" in combined and not has_reentrancy_keyword

    if not has_reentrancy_keyword and not has_simple_reentrancy:
        return False

    # 🔥 v2.5.14: 负向关键词 - 这些表明不是真正的重入攻击
    negative_keywords = [
        # 类型混淆相关
        "类型混淆", "type confusion", "TypeName", "typename",
        # 池创建相关 - "重入式池创建" 是比喻用法
        "池创建", "pool creation", "create_pool",
        # 逻辑错误相关
        "逻辑错误", "logic error", "字节序", "比较逻辑",
        # 权限相关
        "权限提升", "privilege escalation", "权限绕过",
        # 其他比喻用法
        "重入式", "类重入",  # "重入式攻击" 是比喻，不是真正的 reentrancy
    ]

    # 如果包含负向关键词，说明"重入"是比喻用法，不应过滤
    if any(neg in combined for neg in negative_keywords):
        return False

    # 🔥 v2.5.14: 额外检查 - 真正的重入攻击应该涉及以下模式
    real_reentrancy_patterns = [
        "external call", "外部调用",
        "callback", "回调",
        "fallback", "receive",
        "先转账后更新", "check-effects-interactions",
        "状态更新顺序", "state update order"
    ]

    # 如果有真正的重入攻击模式，才过滤
    if any(pattern in combined.lower() for pattern in real_reentrancy_patterns):
        return True

    # 如果只有 "重入攻击" 关键词但没有具体模式，也过滤（保守策略）
    if has_reentrancy_keyword:
        return True

    # 简单的"重入"出现但没有攻击模式，不过滤
    return False


def check_move_language_protection(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 6c: Move 语言级保护 (基于 sui_move_security_knowledge.py)

    调用安全知识库中的 is_likely_false_positive 函数，
    检查漏洞是否被 Move 语言级机制保护。

    覆盖的保护类型:
    - overflow_bypass: 算术溢出绕过 (Move VM 自动 abort)
    - reentrancy: 重入攻击 (无动态调度)
    - double_spend: 双花攻击 (线性类型系统)
    - init_replay: init 重复调用 (Sui 运行时)
    - txcontext_forge: TxContext 伪造 (VM 注入)
    - memory_safety: 内存安全 (Borrow Checker)

    🔥 v2.5.14: 添加逻辑漏洞保护，防止将开发者逻辑错误误判为语言级保护
    """
    if not HAS_SECURITY_KNOWLEDGE:
        return False

    # 🔥 v2.5.14: 开发者逻辑错误关键词 - 这些是真实漏洞，不应被语言级保护过滤
    logic_bug_keywords = [
        # 状态/条件检查缺失
        "缺少", "缺失", "未检查", "未验证", "未校验", "忘记",
        "missing", "lack", "without check", "no validation",
        # 逻辑错误
        "逻辑错误", "logic error", "逻辑缺陷", "logic flaw",
        "条件错误", "条件恒", "恒成立", "恒为",
        "always true", "always false", "tautology",
        # 状态管理问题
        "暂停状态", "pause", "状态检测", "状态检查",
        "时间范围", "time range", "有效期",
        # 黑名单/白名单失效
        "黑名单失效", "白名单失效", "绕过", "bypass",
        "deny.*失效", "allow.*失效",
        # 权限/验证缺失
        "权限.*缺", "验证.*缺", "校验.*缺",
        "操控", "manipulat",
    ]

    # 如果包含逻辑错误关键词，说明是开发者错误，不应过滤
    combined_lower = combined.lower()
    for kw in logic_bug_keywords:
        kw_lower = kw.lower()
        if kw_lower in combined_lower:
            return False  # 不过滤，这是真实的逻辑漏洞

    # 获取漏洞类型和描述
    vuln_type = finding.get("category", "") + " " + finding.get("title", "")
    description = combined

    # 调用知识库的误报检测函数
    is_fp, reason = is_likely_false_positive(vuln_type, description)

    # 如果知识库判断是误报，返回 True
    return is_fp


def check_arithmetic_underflow(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 6d: 算术下溢保护 (Move 语言级)

    🔥 v2.5.13 新增

    Move VM 对减法操作自动进行下溢检查：
    - 减法结果为负数时交易 abort
    - 不会静默回绕到 MAX_U64
    - **不需要** SafeMath，这是 Solidity 的模式

    **常见误报**:
    - "减法操作存在下溢风险" - Move 已自动保护
    - "减法可能导致下溢" - Move 已自动保护
    """
    underflow_keywords = [
        "下溢", "underflow", "减法溢出", "subtraction overflow",
        "减法操作存在下溢", "减法下溢", "可能下溢",
    ]

    if not any(kw in combined for kw in underflow_keywords):
        return False

    # 位移操作不受保护，不应过滤
    bit_shift_keywords = ["<<", ">>", "位移", "shift", "shl", "shr"]
    if any(kw in combined for kw in bit_shift_keywords):
        return False

    return True


def check_vector_bounds_safety(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 6e: 向量边界检查保护 (Move 语言级)

    🔥 v2.5.13 新增

    Move 的 vector 操作自动进行边界检查：
    - `vector::borrow(v, i)` - 越界时自动 abort
    - `vector::borrow_mut(v, i)` - 越界时自动 abort
    - `vector::pop_back(v)` - 空 vector 时自动 abort
    - `vector::remove(v, i)` - 越界时自动 abort

    **常见误报**:
    - "向量越界访问风险" - Move 已自动检查
    - "数组索引可能越界" - Move 已自动检查
    - "vector out of bounds" - Move 已自动检查
    """
    bounds_keywords = [
        "越界", "out of bounds", "bounds", "索引越界",
        "向量越界", "数组越界", "index out of",
        "vector.*越界", "数组.*越界",
    ]

    if not any(kw in combined for kw in bounds_keywords):
        return False

    # 确认是 vector/数组相关
    vector_context = ["vector", "数组", "array", "index", "索引", "borrow"]
    if not any(ctx in combined for ctx in vector_context):
        return False

    return True


def check_arithmetic_overflow(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 6g: 算术溢出保护 (Move 语言级)

    🔥 v2.5.24 新增

    Move VM 对普通算术运算 (+, -, *) 自动进行溢出检查：
    - 加法 overflow: 交易 abort
    - 减法 underflow: 交易 abort
    - 乘法 overflow: 交易 abort
    - **不需要** SafeMath，这是 Solidity 的模式

    ⚠️ 例外情况 (这些**不应被过滤**):
    - 位移运算 (<<, >>): 溢出时**静默截断**，不会 abort！
    - wrapping_* 函数: 设计为回绕，不会 abort！

    **常见误报**:
    - "缺少溢出保护" - Move 已自动保护
    - "溢出可能导致..." - Move 溢出时会 abort
    - "未防止溢出" - Move 已自动保护
    - "可能溢出" - Move 溢出时会 abort
    """
    # 检查是否是溢出相关漏洞
    overflow_keywords = [
        "溢出", "overflow", "缺少溢出保护", "未防止溢出", "可能溢出",
        "溢出风险", "overflow risk", "overflow protection", "溢出保护",
        "arithmetic overflow", "integer overflow", "算术溢出"
    ]

    if not any(kw in combined for kw in overflow_keywords):
        return False

    # ⚠️ 位移操作溢出不会 abort，**不应被过滤**！
    bit_shift_keywords = [
        "<<", ">>", "位移", "shift", "shl", "shr",
        "left shift", "right shift", "左移", "右移",
        "checked_shl", "checked_shr", "checked_shlw"
    ]
    if any(kw in combined for kw in bit_shift_keywords):
        return False  # 位移相关的溢出问题不过滤

    # ⚠️ wrapping_* 函数明确设计为回绕，**不应被过滤**！
    wrapping_keywords = [
        "wrapping_add", "wrapping_sub", "wrapping_mul", "wrapping_div",
        "wrapping_shl", "wrapping_shr"
    ]
    if any(kw in combined for kw in wrapping_keywords):
        return False  # wrapping_* 函数相关的问题不过滤

    # 确认是普通算术运算相关
    arithmetic_context = [
        "+", "-", "*", "加法", "减法", "乘法", "加", "减", "乘",
        "addition", "subtraction", "multiplication",
        "position_index", "amount", "balance", "counter", "index",
        "amount_owned", "fee_owned", "liquidity"
    ]
    if any(ctx in combined for ctx in arithmetic_context):
        return True

    return False


# ============================================================================
# Sui Move 安全模式排除规则 (规则 7-12) - v2.5.1 新增
# 基于 Cetus CLMM 等生产级合约分析
# ============================================================================

def check_capability_access_control(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 7: Capability-Based 权限控制模式

    Sui Move 使用 Capability 模式进行权限控制：
    - `_: &AdminCap` 作为参数意味着调用者必须持有该 Cap
    - 这是 Sui Move 的标准权限模式，不是漏洞

    常见的 Capability 类型：
    - AdminCap, OwnerCap, MinterCap, BurnCap
    - TreasuryCap (铸币权限)
    - Publisher (发布者权限)
    - PoolCreationCap, UpgradeCap 等

    🔥 v2.5.7: 也包括 ACL-based 权限检查
    - check_*_role() 函数调用
    - has_role() 检查
    - is_authorized() 检查

    🔥 v2.5.14: 检测"权限检查不完整"的情况，不应过滤
    """
    # 检查描述是否涉及权限问题 (大小写不敏感)
    combined_lower = combined.lower()
    if not any(kw in combined_lower for kw in [
        "无权限", "no access control", "missing access control", "missing permission", "缺少权限",
        "任意用户", "任意调用", "any user", "anyone can", "unrestricted",
        "未验证调用者", "未验证身份", "without verification", "unchecked caller",
        "unauthorized", "allows unauthorized",  # 🔥 v2.5.7: 更多英文关键词
        # 🔥 v2.5.15: "Cap 参数未使用" 类型的误报
        "未使用", "unused", "not used", "形同虚设", "权限控制缺失", "权限缺失",
        "权限绕过", "权限验证缺失", "access control.*bypass", "permission bypass"
    ]):
        return False

    # 🔥 v2.5.14: 权限检查不完整的情况 - 这是真实漏洞
    # 例如："仅检查全局角色" "只检查角色" "权限不完整"
    incomplete_auth_keywords = [
        "仅检查", "只检查", "仅验证", "只验证",
        "only check", "only verif",
        "不完整", "incomplete", "insufficient",
        "全局角色", "global role",
        "未验证.*控制权", "未验证.*所有权",
        "未检查.*所属", "未校验.*关联",
    ]
    for kw in incomplete_auth_keywords:
        if kw in combined_lower:
            return False  # 权限检查不完整是真实漏洞，不过滤

    # 🔥 v2.5.16: 也检查完整函数代码，不仅是代码片段
    # 因为权限检查通常在函数开头，而代码片段可能只是函数的一部分
    func_context = finding.get("_phase2_func_context", {})
    full_function_code = func_context.get("function_code", "")
    code_to_check = code + "\n" + full_function_code

    # 检查代码中是否有 Capability 参数
    cap_patterns = [
        r"_:\s*&\w*[Cc]ap",           # _: &AdminCap, _: &OwnerCap
        r"_:\s*&mut\s*\w*[Cc]ap",     # _: &mut TreasuryCap
        r"\w+:\s*&\w*[Cc]ap",         # admin_cap: &AdminCap, partner_cap: &PartnerCap
        r"&\w*[Cc]ap<",               # &TreasuryCap<T>
        r"&Publisher",                 # &Publisher
    ]
    import re
    for pattern in cap_patterns:
        if re.search(pattern, code_to_check):
            return True

    # 🔥 v2.5.7: 检查 ACL-based 权限检查函数
    acl_patterns = [
        r"check_\w+_role\(",           # check_pool_manager_role(), check_admin_role()
        r"has_role\(",                 # has_role(acl, sender, ROLE)
        r"is_authorized\(",            # is_authorized(config, sender)
        r"assert!\s*\([^)]*\.id\s*==", # assert!(cap.id == object::id(...))
        r"assert!\s*\(\w+_cap\.\w+_id\s*==",  # assert!(partner_cap.partner_id == ...)
    ]
    for pattern in acl_patterns:
        if re.search(pattern, code_to_check):
            return True

    return False


def check_package_visibility(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 8: public(package) 可见性

    `public(package)` 函数只能被同一 package 内的其他模块调用，
    外部无法直接调用，不需要额外的权限检查。

    🔥 v2.5.16: 增强检测 - 也检查完整函数代码和签名
    """
    combined_lower = combined.lower()

    # 检查是否是关于访问控制的漏洞
    acl_keywords = [
        "无权限", "no access control", "missing access control", "missing permission",
        "public function", "公开函数", "external access", "外部访问",
        "unauthorized", "allows unauthorized", "缺少权限", "任意用户", "任意调用",
        "any user", "anyone can", "missing role check", "缺乏.*验证", "缺少.*验证",
        "缺乏对调用者权限", "缺少调用者权限"
    ]
    if not any(kw in combined_lower for kw in acl_keywords):
        return False

    # 🔥 v2.5.16: 也检查完整函数代码和签名
    func_context = finding.get("_phase2_func_context", {})
    full_function_code = func_context.get("function_code", "")
    signature = func_context.get("signature", "")
    code_to_check = code + "\n" + full_function_code + "\n" + signature

    # 检查代码或描述中是否提到 public(package)
    if "public(package)" in code_to_check:
        return True
    if "public(package)" in combined_lower:
        return True
    # 中文描述可能会写成 "标记为 public(package)"
    if "标记为" in combined_lower and "package" in combined_lower:
        return True
    return False


def check_shared_object_design(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 9: 共享对象设计模式

    Sui 的共享对象 (Shared Object) 是设计模式：
    - share_object() 使对象全局可访问
    - 但修改权限通过 ACL、Capability 或业务逻辑控制
    - 不应因为"共享"就认为是漏洞
    """
    if not any(kw in combined for kw in [
        "shared object", "共享对象", "全局访问", "global access",
        "任意修改", "arbitrary modification"
    ]):
        return False

    # 检查是否有相关的权限检查
    acl_patterns = [
        "check_", "has_role", "is_authorized", "assert!", "require",
        "ACL", "acl::", "config::", "permission"
    ]
    for pattern in acl_patterns:
        if pattern in code:
            return True
    return False


def check_event_function(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 10: Event 发射函数

    Event 函数用于链上日志记录：
    - 不涉及状态修改
    - 不需要返回值校验
    - 常见模式：event::emit(), emit!()
    """
    if "event" not in combined and "emit" not in combined:
        return False

    # 检查函数名或代码是否涉及 event
    event_patterns = ["emit_", "event::", "emit!", "Event", "emit("]
    return any(p in code or p in func_name for p in event_patterns)


def check_clock_dependency(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 11: Clock 时间依赖 (仅限时间源操控问题)

    使用 &Clock 获取链上时间是标准模式：
    - sui::clock::Clock 是 Sui 提供的可信时间源
    - 不能被用户操控
    - 不是时间戳依赖攻击

    🔥 v2.5.6: 仅过滤声称 Clock 可被操控/伪造的漏洞
    不过滤业务逻辑问题 (如时间差计算、奖励膨胀等)
    """
    # 🔥 v2.5.6: 只过滤声称 Clock 本身可被操控的漏洞
    # 不过滤使用 Clock 的业务逻辑漏洞
    clock_manipulation_keywords = [
        "伪造时间", "fake time", "forge time", "manipulate clock",
        "操控clock", "fake clock", "spoof timestamp", "伪造时间戳",
        "block.timestamp", "block timestamp"  # EVM 风格的时间戳操控
    ]

    if not any(kw in combined.lower() for kw in clock_manipulation_keywords):
        return False

    # 确认代码使用 Sui Clock (不是 EVM block.timestamp)
    if "&Clock" in code or "clock::" in code or "sui::clock" in code:
        return True

    return False


def check_treasury_cap_proof(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 12: TreasuryCap 所有权证明

    使用 &TreasuryCap<T> 或 &mut TreasuryCap<T> 作为参数
    表示调用者是该代币的所有者/管理者，这是 Sui 的标准模式。
    """
    if not any(kw in combined for kw in [
        "mint", "铸币", "burn", "销毁", "token", "代币", "coin"
    ]):
        return False

    if "TreasuryCap" in code or "treasury_cap" in code.lower():
        return True
    return False


# ============================================================================
# 非安全问题排除规则 (规则 13-17) - v2.5.0 原有
# ============================================================================

def check_hardcoded_constant(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 13: 硬编码常量 (错误码、初始值、配置参数)"""
    if not any(kw in combined for kw in [
        "硬编码", "hardcode", "hard-code", "hard code", "magic number",
        "constant value", "固定值", "literal value"
    ]):
        return False
    return any(val_kw in combined for val_kw in [
        "error code", "错误码", "错误代码", "初始值", "initial value",
        "配置", "config", "parameter", "参数", "threshold", "阈值",
        "fee", "rate", "比率", "费率", "0", "1", "100"
    ])


def check_mock_function(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 14: Mock/测试函数 (abort 0 占位实现)

    检测模式:
    1. abort 0 / abort(0) - 常见的 placeholder
    2. 函数体只有 abort 语句
    3. 外部模块 mock (如 sui::object, sui::transfer)
    """
    if not code:
        return False
    code_lower = code.lower()

    # 检测 abort 0 模式 (常见的 mock/placeholder)
    has_abort_0 = "abort 0" in code_lower or "abort(0)" in code_lower

    if has_abort_0:
        # 检查是否是外部模块的 mock 实现
        external_mock_patterns = [
            "sui::object",
            "sui::transfer",
            "sui::tx_context",
            "sui::coin",
            "object::new",
            "object::delete",
            "transfer::public",
            "transfer::share",
            "transfer::freeze",
            "public_freeze_object",
            "public_share_object",
            "public_transfer",
        ]
        for pattern in external_mock_patterns:
            if pattern in code_lower or pattern in func_name.lower():
                return True

        # 检查函数体是否只有 abort 语句 (纯 mock)
        # 简化的代码片段通常只包含 { abort 0 } 或类似模式
        import re
        # 移除注释和空白后检查
        code_stripped = re.sub(r'//.*', '', code_lower)  # 移除单行注释
        code_stripped = re.sub(r'/\*.*?\*/', '', code_stripped, flags=re.DOTALL)  # 移除多行注释
        code_stripped = ' '.join(code_stripped.split())  # 规范化空白

        # 检查是否是简单的 abort 函数体
        if re.search(r'\{\s*abort\s*\(?\s*0\s*\)?\s*\}', code_stripped):
            return True

        # event/emit 相关函数 (保留原有逻辑)
        if "emit" in func_name.lower() or "event" in combined:
            return True

    return False


def check_pure_getter(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 15: 纯 getter 函数 (只读状态)

    🔥 v2.5.6: 基于代码分析判断，而非仅靠函数名
    🔥 v2.5.6-fix: 更保守的判断 - 必须满足所有条件才过滤

    纯 getter 特征:
    - 函数名包含 getter 模式 (get_, _of, borrow_, is_, has_)
    - 函数体很短 (1-3 行有效代码)
    - 只有字段访问 (obj.field)
    - 无算术操作符
    - 无复杂函数调用
    """
    if not code or len(code.strip()) == 0:
        return False

    # 🔥 v2.5.6-fix: 首先检查函数名是否像 getter
    func_lower = func_name.lower()
    getter_name_patterns = [
        'get_', 'borrow_', 'is_', 'has_', 'can_',
        '_of', '_at', '_by', '_for',
    ]
    is_getter_name = any(p in func_lower for p in getter_name_patterns)

    # 如果函数名不像 getter，且漏洞描述包含关键安全问题，不要过滤
    security_keywords = [
        'overflow', '溢出', 'underflow', '下溢',
        'access control', '权限', '访问控制',
        'slippage', '滑点',
        'reentrancy', '重入',
        'dos', 'denial', '拒绝服务',
        'manipulation', '操纵',
        'bypass', '绕过',
    ]
    if not is_getter_name and any(kw in combined for kw in security_keywords):
        return False

    # 提取函数体 (去掉函数签名)
    code_lines = code.strip().split('\n')
    # 跳过函数签名行
    body_lines = []
    in_body = False
    brace_count = 0
    for line in code_lines:
        stripped = line.strip()
        if not in_body:
            if '{' in stripped:
                in_body = True
                brace_count += stripped.count('{') - stripped.count('}')
                # 取 { 之后的内容
                after_brace = stripped.split('{', 1)[-1].strip()
                if after_brace and after_brace != '}':
                    body_lines.append(after_brace.rstrip('}').strip())
        else:
            brace_count += stripped.count('{') - stripped.count('}')
            if stripped and stripped != '}':
                body_lines.append(stripped.rstrip('}').strip())
            if brace_count <= 0:
                break

    # 过滤空行和纯注释
    body_lines = [l for l in body_lines if l and not l.startswith('//')]

    # 🔥 v2.5.6-fix: 如果找不到函数体，不要过滤
    if len(body_lines) == 0:
        return False

    # 纯 getter 函数体应该很短 (1-3 行)
    if len(body_lines) > 3:
        return False

    body_text = ' '.join(body_lines)

    # 🔥 检查是否有算术操作 (不是纯 getter)
    arithmetic_ops = [' + ', ' - ', ' * ', ' / ', ' % ', '<<', '>>', '+=', '-=', '*=', '/=']
    if any(op in body_text for op in arithmetic_ops):
        return False

    # 🔥 检查是否有复杂函数调用 (排除简单的 borrow)
    # 纯 getter 不应该调用计算函数
    complex_call_patterns = [
        'math::', 'calc', 'compute', 'convert', 'mul_', 'div_', 'add_', 'sub_',
        'sqrt', 'pow', 'log', 'exp', 'floor', 'ceil', 'round',
        'vector::', 'table::', 'linked_table::'
    ]
    if any(p in body_text.lower() for p in complex_call_patterns):
        return False

    # 🔥 v2.5.6-fix: 检查是否只是简单字段访问
    # 纯 getter 模式: obj.field, &obj.field, *obj.field, self.field
    simple_getter_pattern = re.compile(
        r'^[\w&*]*\s*[\w_]+\.[\w_]+\s*$|'  # obj.field
        r'^[\w_]+\s*$|'  # 单个变量返回
        r'^\*?&?\s*[\w_]+\.[\w_]+\s*$'  # &obj.field 或 *obj.field
    )

    # 如果每行都是简单访问或返回，则是纯 getter
    has_field_access = False
    for line in body_lines:
        # 去掉 return 关键字
        check_line = line.replace('return', '').strip().rstrip(',').rstrip(';')
        if not check_line:
            continue
        # 检查是否是简单模式
        if simple_getter_pattern.match(check_line):
            has_field_access = True
        elif '(' in check_line:
            # 允许一些简单的调用如 borrow, option::some
            if not any(s in check_line.lower() for s in ['borrow', 'option::', 'some(', 'none']):
                return False

    # 🔥 v2.5.6-fix: 必须有实际的字段访问才算 getter
    return has_field_access


def check_debug_assertion(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 16: 断言/调试信息"""
    return any(kw in combined for kw in [
        "assert error", "断言错误码", "panic message", "错误信息",
        "debug", "调试", "可调试性", "debuggability"
    ])


def check_low_severity(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 17: LOW 严重性问题"""
    severity = finding.get("severity", "").lower()
    return severity == "low"


def check_mock_call_site(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 18: 调用 Mock/Stub 框架函数

    检测描述中提到框架函数 "会 abort" 或 "always aborts" 的情况。
    这通常是因为测试/CTF 环境使用了 mock 实现，不是真实漏洞。

    常见的 mock 框架函数:
    - sui::object::new, sui::object::delete
    - sui::transfer::*, sui::coin::*
    - public_freeze_object, public_share_object, public_transfer
    """
    # 检查描述是否提到框架函数会 abort
    abort_keywords = [
        "abort", "中止", "aborts", "会abort", "会 abort",
        "abort(0)", "abort 0", "直接abort", "总是abort",
        "always abort", "will abort", "导致abort"
    ]
    if not any(kw in combined for kw in abort_keywords):
        return False

    # 检查是否涉及 Sui 框架函数
    framework_functions = [
        # object 模块
        "object::new", "object::delete", "object::id",
        # transfer 模块
        "transfer::", "public_freeze", "public_share", "public_transfer",
        "freeze_object", "share_object",
        # coin 模块
        "coin::mint", "coin::burn", "coin::split", "coin::join",
        # tx_context 模块
        "tx_context::", "sender", "fresh_object_address",
    ]
    return any(func in combined or func in code.lower() for func in framework_functions)


def check_ctf_test_project(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 19: CTF/测试项目特征

    检测明显的 CTF 或测试项目特征，这类项目通常:
    - 使用简化的 mock 实现
    - 包含 "challenge", "ctf", "test" 等关键词
    - 故意存在漏洞用于教学目的
    """
    # 检查是否是关于 mock 函数调用失败的漏洞
    mock_failure_patterns = [
        "实际会中止", "实际上会", "导致函数abort", "无法成功",
        "会直接abort", "会 abort", "abort导致", "abort 导致",
        "mock", "stub", "placeholder", "占位"
    ]
    if any(p in combined for p in mock_failure_patterns):
        # 进一步确认是框架函数相关
        framework_refs = [
            "object::new", "public_freeze", "public_share", "public_transfer",
            "transfer::", "coin::", "新生成的 uid", "uid"
        ]
        if any(f in combined or f in code.lower() for f in framework_refs):
            return True

    return False


# ============================================================================
# 🔥 v2.5.5 新增排除规则 (规则 20-22)
# 基于 Cetus CLMM 审计分析结果
# ============================================================================

def check_test_only_function(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 20: #[test_only] 测试专用函数

    Sui Move 的 #[test_only] 属性标记的函数:
    - 仅在测试环境可用
    - 生产构建时被完全移除
    - 不应被视为安全漏洞

    检测模式:
    1. 代码中包含 #[test_only] 属性
    2. 函数名包含 _test, _for_test, test_ 模式
    3. 使用 create_for_testing 等测试专用函数
    """
    # 1. 检查代码中的 #[test_only] 属性
    if "#[test_only]" in code or "#[test]" in code:
        return True

    # 2. 检查函数名模式
    func_lower = func_name.lower()
    if (func_lower.startswith("test_") or
        func_lower.endswith("_test") or
        func_lower.endswith("_for_test")):
        return True

    # 3. 检查是否使用测试专用函数
    test_only_functions = [
        "create_for_testing",
        "new_for_testing",
        "mint_for_testing",
        "burn_for_testing",
        "destroy_for_testing",
    ]
    if any(tf in code.lower() for tf in test_only_functions):
        return True

    return False


def check_low_level_module_design(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 21: 低层模块设计模式 (通用)

    Sui Move 常见的模块分层设计:
    - 低层模块 (如 acl, math, utils) 不做权限检查
    - 高层模块通过 wrapper 函数添加权限检查
    - 这是正确的设计模式，不是漏洞

    通用检测条件:
    1. 描述提到"缺少权限检查"或"任意用户可调用"
    2. 模块名包含通用低层模式 (math, utils, types, lib, helper, common)
    3. 函数是 public 但非 entry (工具函数模式)
    """
    # 检查是否是权限相关问题
    if not any(kw in combined for kw in [
        "no access control", "missing permission", "缺少权限", "无权限",
        "任意用户", "任意调用", "any user", "anyone can"
    ]):
        return False

    # 检查是否是低层模块 (通用模式)
    location = finding.get("location", {})
    module_name = location.get("module", "").lower()

    # 🔥 v2.5.6: 从多个来源提取模块名 (兼容不同格式)
    location_str = str(location).lower()

    # 🔥 v2.5.6: 通用低层模块基础词根 (用于后缀匹配)
    # 匹配模式: xxx_math, xxx_utils, xxx_acl 等
    low_level_suffixes = [
        # 权限/访问控制底层
        "acl", "access", "role", "permission", "auth",
        # 数学/计算库
        "math", "calc", "compute", "arithmetic",
        # 工具/辅助模块
        "utils", "util", "helper", "helpers", "common", "lib", "core",
        # 类型/常量定义
        "types", "type", "constants", "const", "errors", "error",
        # 数据结构
        "vector", "table", "bag", "set", "map", "list", "queue",
        # 整数类型模块
        "i32", "i64", "i128", "u256", "u128", "i256",
        # 编解码/序列化
        "codec", "encoder", "decoder", "serializer",
    ]

    import re
    for suffix in low_level_suffixes:
        # 1. 精确匹配模块名 (如 "acl", "math")
        if module_name == suffix:
            return True
        # 2. 后缀匹配 (如 "xxx::acl", "tick_math", "full_math")
        if module_name.endswith(f"::{suffix}") or module_name.endswith(f"_{suffix}"):
            return True
        # 3. 正则匹配 location 字符串 (如 "acl::add_role", "tick_math::compute")
        # 匹配 "模块名::" 模式
        pattern = rf'(?:^|[/:_])({suffix})(?:::|\.move)'
        if re.search(pattern, location_str):
            return True

    return False


def check_wrapper_protected_function(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 22: 被 Wrapper 保护的函数

    检测函数虽然本身没有权限检查，但存在带权限检查的 wrapper 函数:
    - 原始函数: acl::set_roles (无权限)
    - Wrapper 函数: config::set_roles (有 AdminCap)

    检测模式:
    1. 漏洞描述提到权限问题
    2. 函数名暗示有对应的 wrapper (如 xxx_internal, raw_xxx)
    3. 代码片段显示这是内部实现函数
    """
    # 检查是否是权限相关问题
    if not any(kw in combined for kw in [
        "no access control", "missing permission", "缺少权限", "无权限",
        "任意用户", "任意调用"
    ]):
        return False

    # 检查函数名是否暗示内部实现
    internal_patterns = [
        "_internal", "_impl", "_raw", "_core", "_base",
        "do_", "execute_", "process_"
    ]
    func_lower = func_name.lower()
    if any(p in func_lower for p in internal_patterns):
        return True

    # 检查是否是 public(package) 或 friend 可见性
    if "public(package)" in code or "public(friend)" in code:
        return True

    return False


def check_deprecated_function(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 23: 废弃函数 (Deprecated Function)

    检测已标记为废弃的函数:
    - 函数体包含 `abort EDeprecated` 或类似的废弃错误
    - 这些函数设计为不可调用，abort 是预期行为
    - 不应被视为 DoS 漏洞

    检测模式:
    1. 代码包含 abort EDeprecated / abort EMethodDeprecated
    2. 代码包含 abort + deprecated 相关错误码
    3. 漏洞描述提到"总是 abort"或"拒绝服务"
    """
    if not code:
        return False

    code_lower = code.lower()

    # 检查是否包含废弃相关的 abort
    deprecated_patterns = [
        "abort edeprecated",
        "abort emethoddeprecated",
        "abort e_deprecated",
        "abort e_method_deprecated",
        "abort deprecated",
        # 数字形式的错误码也可能用于废弃
        "edeprec",
    ]

    for pattern in deprecated_patterns:
        if pattern in code_lower:
            return True

    # 检查漏洞描述是否提到"废弃"+"abort"或"DoS"
    if any(kw in combined for kw in ["deprecated", "废弃", "弃用"]):
        if any(abort_kw in combined for abort_kw in [
            "abort", "中止", "拒绝服务", "dos", "denial"
        ]):
            return True

    return False


def check_move_type_safety(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 24: Move 泛型类型系统安全

    🔥 v2.5.7 新增

    Move 的泛型类型系统提供编译时类型安全：
    - bag::remove<K, V>() 必须 V 与存储的实际类型匹配
    - 泛型参数 T 是编译时确定的，无法在运行时"构造"任意类型
    - type_name::get<T>() 返回的类型路径是唯一的，无法伪造

    常见误报模式：
    - "任意代币铸造" - 误解 bag/table 的泛型类型检查
    - "类型混淆攻击" - 误解 Move 编译时类型检查
    - "指定任意类型 T" - 误解泛型参数的工作原理
    """
    # 检查描述是否涉及泛型类型混淆
    type_confusion_keywords = [
        "任意代币铸造", "任意类型", "任意 coin", "任意coin",
        "指定任意", "arbitrary type", "arbitrary coin",
        "类型混淆", "type confusion", "forge type",
        "伪造类型", "fake type", "构造类型"
    ]
    if not any(kw in combined for kw in type_confusion_keywords):
        return False

    # 检查代码中是否使用了 Move 标准库的类型安全操作
    type_safe_patterns = [
        "bag::remove<",           # bag 移除需要类型匹配
        "bag::borrow<",           # bag 借用需要类型匹配
        "table::remove<",         # table 移除需要类型匹配
        "table::borrow<",         # table 借用需要类型匹配
        "balance::value<",        # balance 值获取
        "coin::from_balance<",    # coin 转换
        "type_name::get<",        # 类型名获取
        "type_name::with_defining_ids<",  # 完整类型路径
    ]
    if any(p in code for p in type_safe_patterns):
        return True

    return False


def check_private_function_access(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 25: 私有函数不需要访问控制

    🔥 v2.5.7 新增

    Move 中的私有函数 (使用 `fun` 而非 `public fun` 或 `public(package) fun`)
    只能被同一模块内的其他函数调用，不能被外部直接调用。

    因此，"缺少访问控制"类型的漏洞不适用于私有函数 - 访问控制由模块可见性天然保证。

    常见误报模式：
    - "私有函数缺少访问控制" - 私有函数本身就不可外部访问
    - "internal function missing permission check" - 内部函数由调用者负责权限检查
    """
    import re

    # 检查描述是否涉及访问控制问题
    combined_lower = combined.lower()
    access_keywords = [
        "无权限", "缺少权限", "缺少访问控制", "missing access control",
        "missing permission", "no access control", "unauthorized",
        "任意用户", "任意调用", "any user", "anyone can"
    ]
    if not any(kw in combined_lower for kw in access_keywords):
        return False

    # 检查函数是否为私有函数 (不是 public, public(package), entry)
    # 私有函数定义格式: fun func_name(...) 或 fun func_name<T>(...)
    # 非私有函数: public fun, public(package) fun, entry fun
    func_def_pattern = rf"(public\s*(\(package\))?\s+)?fun\s+{re.escape(func_name)}\s*[<(]"
    match = re.search(func_def_pattern, code)

    if match:
        # 如果匹配到的不包含 "public"，则是私有函数
        if match.group(1) is None:  # 没有 public 前缀
            return True

    # 检查代码开头是否明确是私有函数
    if code.strip().startswith("fun ") and not code.strip().startswith("fun("):
        # 纯 "fun " 开头，检查不是其他变体
        first_line = code.strip().split('\n')[0]
        if not any(prefix in first_line for prefix in ["public ", "entry "]):
            return True

    return False


# ============================================================================
# 🔥 v2.5.8 新增排除规则 (规则 26)
# ============================================================================

def check_code_style_not_vulnerability(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 6f: 代码风格问题不是安全漏洞

    🔥 v2.5.13 新增

    某些 "漏洞" 实际上是代码风格建议，不是真正的安全问题：
    - "调用顺序不当" - 只要所有检查都执行了，顺序通常不影响安全性
    - "调用位置不当" - 同上
    - "缺少二次确认" - 设计选择，不是漏洞

    **判断标准**:
    - 描述涉及 "调用顺序"、"调用位置"、"顺序不当" 等
    - 代码显示所有必要的检查都存在
    """
    style_keywords = [
        "调用顺序不当", "调用位置不当", "顺序不当",
        "call order", "order of calls", "reorder",
        "应该在...之前", "应该在...之后",
        "缺少二次确认", "二次确认机制",
    ]

    if not any(kw in combined for kw in style_keywords):
        return False

    # 检查代码是否包含相关的检查函数 (说明检查确实存在)
    check_patterns = [
        "checked_package_version",
        "check_.*_role",
        "assert!",
    ]
    import re
    has_checks = any(re.search(p, code) for p in check_patterns)

    # 如果有检查存在，且描述只是关于顺序/位置，则是代码风格问题
    return has_checks


def check_dos_via_safe_abort(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 26: DoS via Safe Abort (Move 安全机制)

    Move 的 abort 是语言级安全机制：
    - 算术溢出、边界检查失败时 abort
    - checked_shlw, checked_add 等安全函数触发 abort
    - 交易失败但资金安全，不是真正的漏洞

    这类 "DoS" 是正常的安全行为，不应被视为漏洞。

    🔥 v2.5.14: 添加更多真实漏洞检测，避免过滤信息泄露等问题
    """
    combined_lower = combined.lower()

    # 必须是 DoS 相关的漏洞
    dos_keywords = [
        "dos", "denial", "拒绝服务", "gas exhaustion", "gas 耗尽",
        "资源耗尽", "交易失败", "transaction fail", "导致失败",
        "可能导致中止", "触发中止"
    ]
    if not any(kw in combined_lower for kw in dos_keywords):
        return False

    # 🔥 v2.5.14: 如果涉及其他安全问题，不应仅因为有 DoS 就过滤
    real_security_issues = [
        # 信息泄露
        "信息泄露", "information leak", "information disclosure",
        "泄露", "disclosure", "暴露敏感",
        # 权限问题
        "权限检查前", "before.*permission", "before.*auth",
        "权限绕过", "permission bypass",
        # 顺序问题
        "执行顺序", "order of", "检查前", "验证前",
        # 其他安全问题
        "重放", "replay", "攻击", "attack"
    ]
    if any(issue in combined_lower for issue in real_security_issues):
        return False  # 有其他安全问题，不过滤

    # 检查是否是通过安全函数触发的 abort
    safe_abort_patterns = [
        # 安全数学函数
        "checked_shl", "checked_shr", "checked_add", "checked_sub", "checked_mul",
        "math_u128::", "math_u256::", "overflowing",
        # 边界检查
        "assert!", "abort", "overflow", "溢出检查",
        # Move 安全机制
        "move vm", "move 虚拟机", "自动检查", "自动 abort"
    ]
    if any(p in combined_lower or p in code.lower() for p in safe_abort_patterns):
        # 确认不涉及资金损失
        fund_loss_keywords = [
            "drain", "steal", "盗取", "资金损失", "fund loss",
            "被盗", "窃取", "转移资金"
        ]
        if not any(kw in combined_lower for kw in fund_loss_keywords):
            return True

    return False


def check_bit_shift_constant_safe(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 26: 小常量位移操作 (安全模式)

    ⚠️ 重要: Move 位移操作 (<<, >>) 溢出时 **不会 abort**，会静默截断！
    这与加减乘除不同，是 2025 年 Cetus $223M 被盗的根本原因。

    **危险模式** (不应过滤):
    - `user_value << 64` - 用户可控的值位移可能静默溢出
    - `checked_shlw` 等函数如果检查条件有误，仍可被绕过

    **安全模式** (可以过滤):
    - `1 << role` 其中 role < 128 - 小常量位移，结果不会溢出
    - ACL 权限位设置: `*perms | (1 << role)` 配合边界检查

    此规则 **只过滤** 小常量位移 + 有边界检查的情况。
    """
    combined_lower = combined.lower()

    # 检查是否涉及位移操作
    shift_keywords = [
        "位移", "shift", "<<", ">>", "左移", "右移",
        "bit shift", "bitshift", "位操作"
    ]
    if not any(kw in combined_lower for kw in shift_keywords):
        return False

    # 🔥 关键安全检查: 如果漏洞描述涉及数学计算/流动性/价格，不要过滤！
    # 这些是 Cetus 类型漏洞的高危区域
    dangerous_context = [
        "liquidity", "流动性", "price", "价格", "sqrt",
        "delta", "amount", "swap", "math", "计算",
        "checked_shl", "shlw", "overflow", "溢出",
        "truncat", "截断", "wrap"
    ]
    if any(kw in combined_lower for kw in dangerous_context):
        return False  # 不过滤，需要人工审查

    # 检查是否是 ACL/权限位操作 (相对安全的场景)
    acl_context = [
        "acl", "role", "permission", "权限", "perm",
        "bitmask", "位掩码", "flag", "权限提升"
    ]
    if not any(p in combined_lower or p in func_name.lower() for p in acl_context):
        return False  # 非 ACL 场景，不过滤

    # 检查代码是否是小常量位移模式: `1 << x` 或 `(1 << x)`
    small_constant_shift = re.search(r'\b1\s*<<\s*\w+', code)
    if not small_constant_shift:
        return False  # 不是小常量位移，不过滤

    # 检查是否有位移量边界检查
    bounds_check_patterns = [
        r'<\s*128\b',  # < 128 (u128)
        r'<\s*64\b',   # < 64 (u64)
        r'assert!\s*\([^)]*<\s*\d+',  # assert!(x < N)
    ]

    code_lower = code.lower()
    for pattern in bounds_check_patterns:
        if re.search(pattern, code_lower):
            return True  # 有边界检查，安全

    return False


# ============================================================================
# 🔥 v2.5.14 新增规则 (规则 28-31)
# 基于 Cetus CLMM 审计误报分析
# ============================================================================

def check_publisher_access_control(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 28: Sui Publisher 访问控制模式

    Publisher 在 Sui 中是安全的权限控制机制:
    - 只能通过 package::claim() 在 init 函数中创建
    - 每个模块只有一个 Publisher，只有包发布者拥有
    - package::from_module<T>(publisher) 验证 Publisher 来自特定模块

    常见误报模式:
    - "Publisher 权限校验不足" - 实际上 Publisher 本身就是权限证明
    - "任意者可篡改 display" - 只有 Publisher 持有者才能调用
    """
    combined_lower = combined.lower()
    code_lower = code.lower() if code else ""

    # 检查是否涉及 Publisher
    if "publisher" not in combined_lower:
        return False

    # 检查是否有 package::from_module 验证
    publisher_check_patterns = [
        "package::from_module",
        "from_module<",
        "from_module::<",
        "publisher_from_module",
    ]
    if any(p.lower() in code_lower for p in publisher_check_patterns):
        return True

    # 检查误报关键词模式
    fp_keywords = [
        "权限校验不足", "任意者", "篡改显示", "无权限控制",
        "insufficient auth", "arbitrary", "tamper display",
        "权限不足", "缺少权限", "missing auth"
    ]
    if any(kw in combined_lower for kw in fp_keywords):
        # 如果代码包含 Publisher 参数，说明已有权限控制
        if "publisher" in code_lower and ("&publisher" in code_lower or "publisher:" in code_lower):
            return True

    return False


def check_admin_business_decision(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 29: 管理员权限内的业务决策

    如果函数有角色/权限检查，且漏洞是关于参数范围/配置的，
    这是管理员的业务决策而非安全漏洞。

    例如:
    - "费率可设为零" - 管理员可能在促销期设置零费率
    - "时间范围无上限" - 管理员可能需要设置长期有效的合作
    - "URL 无格式验证" - 管理员应该知道输入正确的 URL
    """
    combined_lower = combined.lower()
    code_lower = code.lower() if code else ""

    # 检查是否有角色权限检查
    role_check_patterns = [
        "check_pool_manager_role",
        "check_partner_manager_role",
        "check_rewarder_manager_role",
        "check_emergency_pause_role",
        "check_admin_role",
        "check_fee_tier_manager_role",
        "check_governance_role",
        # 通用模式
        "check_", "_role(",
        "has_role",
        "require_role",
    ]
    has_role_check = any(p.lower() in code_lower for p in role_check_patterns)

    # 也检查 Capability 模式
    cap_patterns = [
        "&admincap", "&admin_cap", "&governancecap",
        "&managercap", "&manager_cap", "&ownercap"
    ]
    has_cap_check = any(p in code_lower for p in cap_patterns)

    if not has_role_check and not has_cap_check:
        return False

    # 检查是否是参数范围/配置问题 (管理员业务决策)
    config_issue_keywords = [
        # 零值设置
        "设置为零", "set to zero", "fee_rate = 0", "rate = 0",
        "可设为零", "可以为零", "允许为零",
        # 范围/边界问题
        "无下限", "无上限", "no lower bound", "no upper bound",
        "下限检查", "上限检查", "缺少下限", "缺少上限",
        "过长", "过短", "too long", "too short",
        "有效期", "validity period", "time range",
        "极端值", "extreme value",
        # URL/字符串问题
        "url 验证", "url 格式", "url 内容", "url有效性",
        "字符串长度", "string length", "格式校验",
        # 费率/参数配置
        "费率", "fee rate", "emission", "reward rate",
    ]

    if any(kw in combined_lower for kw in config_issue_keywords):
        return True

    return False


def check_version_protection_feature(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 30: 版本保护安全特性

    版本检查 (version >= before_version) 是防止降级攻击的安全特性，
    不应被视为漏洞。

    常见误报:
    - "version >= before_version 可能阻止合法恢复操作"
    - 实际上这是防止恢复到有漏洞的旧版本
    """
    combined_lower = combined.lower()

    # 检查是否涉及版本相关
    if "version" not in combined_lower:
        return False

    # 检查是否是版本保护特性被误判
    protection_keywords = [
        "阻止合法恢复", "阻止恢复", "恢复操作",
        "prevent recovery", "block recovery",
        "version >=", "version >",
        "降级", "回滚", "downgrade", "rollback",
        "before_version", "beforeversion",
        "运维灵活性", "flexibility"
    ]

    if any(kw in combined_lower for kw in protection_keywords):
        return True

    return False


def check_user_voluntary_risk(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 31: 用户自愿承担的风险

    某些功能设计上就是让用户自己承担风险的，不应视为漏洞:
    - fix_amount 系列函数: 用户选择固定某一边的数量
    - 无滑点保护: 用户可以通过前端设置滑点
    - sqrt_price_limit: 用户自己设置价格限制
    """
    combined_lower = combined.lower()
    code_lower = code.lower() if code else ""

    # 用户自愿风险的函数模式
    voluntary_patterns = [
        "fix_coin", "fix_amount", "fixed_amount",
        "no_slippage", "without_slippage"
    ]

    func_is_voluntary = any(p in func_name.lower() for p in voluntary_patterns)

    # 用户自愿风险的漏洞描述
    voluntary_keywords = [
        "滑点保护", "slippage protection", "slippage tolerance",
        "price limit", "价格限制", "用户设置",
        "imbalanced deposit", "不平衡存款",
        "fixed amount", "固定数量",
        "may lead to", "可能导致"  # 可能性语言通常表示非确定性风险
    ]

    if func_is_voluntary and any(kw in combined_lower for kw in voluntary_keywords):
        return True

    # 检查是否是关于用户可控参数的范围问题
    user_param_keywords = [
        "unvalidated", "未验证", "用户输入",
        "user input", "user-provided", "用户提供"
    ]

    # 如果是用户输入且只是"可能导致"而非"将会导致"
    if any(kw in combined_lower for kw in user_param_keywords):
        if "may" in combined_lower or "可能" in combined_lower:
            # 检查是否有基本的非零检查
            if "amount > 0" in code_lower or "assert!(amount" in code_lower:
                return True

    return False


def check_parameter_validated_at_source(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 32: 参数在源头已验证

    某些参数在创建时已被验证，使用时无需再次验证:
    - Partner 的 ref_fee_rate 在 create_partner 时已检查 < MAX_PARTNER_FEE_RATE
    - 池子的 tick_spacing 在创建时已验证是有效值
    - Config 的 fee_rate 在设置时已检查范围

    如果漏洞是"使用时未验证 X"，但 X 在创建时已验证，这是设计意图。
    """
    combined_lower = combined.lower()

    # Partner fee rate 相关
    partner_fee_patterns = [
        "ref_fee_rate", "referral fee", "推荐费率", "partner fee",
        "费率未验证", "fee rate not validated", "零费率滥用"
    ]
    if any(p in combined_lower for p in partner_fee_patterns):
        # 检查是否是 Partner 对象获取的费率
        if "partner" in combined_lower or "partner::" in (code or "").lower():
            return True

    # Tick spacing 相关
    if "tick_spacing" in combined_lower:
        if "未验证" in combined_lower or "not validated" in combined_lower:
            # tick_spacing 在 create_pool 时已验证
            return True

    return False


def check_transaction_atomicity_safety(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 33: 交易原子性保护

    Move/Sui 交易是原子的 - 如果任何操作失败，整个交易回滚。
    因此"状态污染"、"状态不一致"在单个交易内不可能发生。

    常见误报:
    - "状态修改在验证前执行" - 如果验证失败，状态修改也会回滚
    - "balance::join 失败导致状态不一致" - 失败会回滚整个交易
    - "checks-effects-interactions 违反" - 这是 Solidity 模式，Move 不需要
    - "slippage check after state change" - Move 交易原子性保护，assert 失败会回滚全部状态
    """
    combined_lower = combined.lower()

    # 状态不一致相关
    atomicity_keywords = [
        "状态不一致", "state inconsist", "状态污染", "state pollution",
        "无法回滚", "cannot rollback", "can't rollback",
        "checks-effects-interactions", "验证前执行", "before validation",
        "状态已被改变", "state already changed"
    ]

    if any(kw in combined_lower for kw in atomicity_keywords):
        # 检查是否是单交易内的状态问题
        if "交易" in combined_lower or "transaction" in combined_lower:
            return False  # 跨交易问题可能是真正的问题
        return True  # 单交易内状态问题不存在

    # 🔥 v2.5.24: 检查 "slippage check after state change" 模式
    # Move 交易是原子的，如果 slippage assert 失败，整个交易回滚
    slippage_after_keywords = [
        "slippage.*after", "after.*slippage", "check.*after",
        "applied after", "performed after", "执行后检查",
        "检查在.*之后", "验证在.*之后"
    ]

    for pattern in slippage_after_keywords:
        if re.search(pattern, combined_lower):
            # 确认是 slippage/滑点相关
            if any(kw in combined_lower for kw in ["slippage", "滑点", "min_amount", "minimum"]):
                return True

    return False


def check_intentional_zero_assertion(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 34: 故意的零值断言

    某些 `assert!(x == 0)` 是故意的设计:
    - flash_swap/flash_loan 不带 partner 时，ref_fee_amount 必须为 0
    - 这是设计意图，不是漏洞

    常见误报:
    - "强制要求 ref_fee_amount == 0 可能被利用" - 这是非 partner 路径的正确行为
    """
    combined_lower = combined.lower()
    code_lower = (code or "").lower()

    # 检查是否是关于 == 0 断言的漏洞
    zero_assertion_keywords = [
        "== 0", "等于零", "强制等于零", "必须为零",
        "固定等于 0", "固定为 0"
    ]
    if not any(kw in combined_lower for kw in zero_assertion_keywords):
        return False

    # 检查是否是 ref_fee 相关
    if "ref_fee" in combined_lower or "ref_fee" in code_lower:
        # 非 partner 路径的 ref_fee 必须为 0 是正确的
        if "without partner" in combined_lower or "非 partner" in combined_lower:
            return True
        # 检查函数名是否是不带 partner 的版本
        if func_name and "partner" not in func_name.lower():
            if "flash_swap" in func_name.lower() or "flash_loan" in func_name.lower():
                return True

    return False


def check_precision_not_overflow(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 35: 精度截断 vs 溢出

    u128 -> u64 的类型转换是精度问题，不是溢出问题。
    Move 的类型转换 `(x as u64)` 在 x > u64::MAX 时会 abort。

    如果漏洞标记为 "overflow" 但实际是精度/截断问题，严重性应降低。
    """
    combined_lower = combined.lower()
    code_lower = (code or "").lower()

    # 检查是否是截断/精度问题被标记为 overflow
    finding_category = finding.get("category", "").lower()
    if finding_category != "overflow":
        return False

    # 检查是否涉及类型转换
    truncation_keywords = [
        "截断", "truncat", "精度", "precision",
        "as u64", "as u32", "转换为 u64", "转换为 u32",
        "信息丢失", "information loss", "中间结果"
    ]

    if any(kw in combined_lower or kw in code_lower for kw in truncation_keywords):
        # 检查是否有范围检查
        range_check_patterns = [
            "<= u64::max", "<= 18446744073709551615",
            "u64::max_value()", "max_value() as u128"
        ]
        if any(p in code_lower for p in range_check_patterns):
            return True  # 有范围检查的截断不是漏洞

    return False


def check_dynamic_field_internal_state(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 36: 动态字段内部状态管理

    动态字段用于内部状态管理时，exists 检查可能在调用链的其他地方完成。
    例如: pending_add_liquidity 先 add，clear 时不需要再检查 exists。

    常见误报:
    - "dynamic_field::borrow_mut 未检查存在性" - 可能是内部状态管理
    - "可能导致 panic" - panic 是安全的失败模式
    """
    combined_lower = combined.lower()
    code_lower = (code or "").lower()

    # 检查是否涉及 dynamic_field
    if "dynamic_field" not in combined_lower and "dynamic_field" not in code_lower:
        return False

    # 内部状态管理函数通常有特定模式
    internal_state_patterns = [
        "pending", "internal", "counter", "count",
        "bookkeeping", "记账", "计数"
    ]

    # 如果函数名或描述暗示是内部状态管理
    if any(p in func_name.lower() for p in internal_state_patterns):
        return True

    # 如果漏洞是关于 panic/abort/运行时错误
    panic_keywords = [
        "panic", "abort", "运行时错误", "runtime error",
        "抛出异常", "中断执行",
        # 🔥 v2.5.18: 新增更多关键词
        "可能导致.*错误", "may cause.*error", "导致运行时",
        "存在性.*借用", "borrow.*exist", "未验证.*存在"
    ]
    if any(kw in combined_lower for kw in panic_keywords):
        # panic/abort 是安全的失败模式
        # Move 的 abort 保证交易原子性回滚，资金安全
        return True

    # 🔥 v2.5.18: 如果是关于 "直接借用" 可能失败的情况
    if "借用" in combined_lower or "borrow" in combined_lower:
        if any(fail_kw in combined_lower for fail_kw in [
            "可能导致", "可能引发", "may cause", "could cause",
            "存在性", "existence", "不存在", "not exist"
        ]):
            return True

    return False


def check_public_getter_no_acl(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 37: 公开 Getter 函数无需权限控制

    纯读取函数（getters）返回公开信息，不需要访问控制:
    - get_* 函数
    - *_info 函数
    - 只读取 public 字段的函数

    这些函数不修改状态，暴露的信息本来就是公开的。

    🔥 v2.5.16: 增强关键词匹配
    - 新增: "公开函数未校验", "公开接口暴露", "暴露内部状态", "信息泄露"
    """
    combined_lower = combined.lower()
    func_lower = func_name.lower() if func_name else ""

    # 🔥 v2.5.16: 检查是否是关于访问控制或信息暴露的漏洞
    acl_keywords = [
        "缺少访问控制", "缺乏访问控制", "无访问控制",
        "no access control", "missing access control",
        "权限控制", "未验证调用者",
        # 🔥 v2.5.16: 新增 - 信息暴露相关关键词
        "公开函数未校验", "公开接口暴露", "暴露内部状态",
        "信息泄露", "information leak", "information exposure",
        "越权信息泄露", "助涨枚举攻击",
    ]
    if not any(kw in combined_lower for kw in acl_keywords):
        return False

    # 检查是否是 getter 函数
    getter_patterns = [
        "get_", "info", "view", "query", "fetch",
        "is_", "has_", "check_", "current_", "count", "_count"
    ]

    if any(func_lower.startswith(p) or f"::{p}" in func_lower or func_lower.endswith(p) for p in getter_patterns):
        # 检查是否有状态修改
        state_modify_keywords = [
            "&mut", "borrow_mut", "remove", "add(",
            "transfer", "delete", "update", "set_"
        ]
        code_lower = (code or "").lower()
        if not any(kw in code_lower for kw in state_modify_keywords):
            return True  # 纯读取函数无需 ACL

    # 🔥 v2.5.16: 特殊处理 - 如果描述中明确提到"暴露内部状态长度"或类似信息泄露
    # 这类信息本来就是公开的（链上数据全部可见）
    info_leak_specific = [
        "暴露内部状态长度", "长度信息", "状态长度",
        "tick 数量", "position 数量", "rewards 数量"
    ]
    if any(kw in combined_lower for kw in info_leak_specific):
        return True

    return False


def check_slippage_user_parameter(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 38: 滑点参数由用户控制

    滑点保护参数（如 sqrt_price_limit, min_amount_out）是用户提供的，
    用户自己决定可接受的滑点范围。合约不应强制滑点限制。

    常见误报:
    - "sqrt_price_limit 未验证合理性" - 用户自己决定
    - "无滑点保护" - 这是用户的选择
    """
    combined_lower = combined.lower()

    slippage_keywords = [
        "sqrt_price_limit", "滑点", "slippage",
        "price limit", "价格限制", "min_amount", "max_amount"
    ]

    if not any(kw in combined_lower for kw in slippage_keywords):
        return False

    # 检查是否是关于参数验证的问题
    validation_keywords = [
        "未验证", "未校验", "not validated", "unvalidated",
        "合理范围", "reasonable range", "合理性"
    ]

    if any(kw in combined_lower for kw in validation_keywords):
        return True  # 滑点参数是用户责任

    return False


def check_frequency_governance_issue(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 39: 频率/速率限制是治理问题

    某些操作的频率限制应该在治理层面处理，而不是合约层面:
    - "可频繁调用" - 治理/多签可以控制
    - "无更新频率限制" - 这是治理决策

    如果有角色检查，频率控制是管理员的责任。
    """
    combined_lower = combined.lower()
    code_lower = (code or "").lower()

    # 检查是否有角色权限检查
    role_check = any(p in code_lower for p in [
        "check_", "_role(", "has_role", "admincap", "managercap"
    ])

    if not role_check:
        return False

    # 频率/速率相关问题
    frequency_keywords = [
        "频繁调用", "频率限制", "更新频率", "频率",
        "frequency", "rate limit", "throttle",
        "高频修改", "大幅调整", "无限制调用"
    ]

    if any(kw in combined_lower for kw in frequency_keywords):
        return True

    return False


# ============================================================================
# 🔥 v2.5.16 新增规则 (规则 40-45)
# 基于 Cetus CLMM 审计深度误报分析
# ============================================================================

def check_sui_object_ownership(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 40: Sui 对象所有权模型

    Sui 的对象所有权模型提供天然的访问控制:
    - 函数参数 `position_nft: &Position` 或 `&mut Position`
    - 调用者必须是对象的所有者才能传递该引用
    - 这是 Sui 运行时强制的，无法绕过

    常见误报:
    - "未验证 position_nft 所属用户权限" - Sui 所有权已验证
    - "任意人可以操作 position" - 不可能，必须是所有者
    - "缺乏对调用者权限的验证" - 对于 owned object，所有权即权限
    """
    combined_lower = combined.lower()

    # 检查是否是关于访问控制的漏洞
    acl_keywords = [
        "未验证", "所属用户权限", "任意人", "任意用户",
        "缺乏对调用者权限", "缺少调用者权限",
        "unauthorized", "any user", "anyone can",
        "position 所有者", "position_nft 所有者"
    ]
    if not any(kw in combined_lower for kw in acl_keywords):
        return False

    # 检查代码中是否有对象引用参数 (表示需要所有权)
    # &Position, &mut Position, &Pool, &mut Pool 等
    owned_object_patterns = [
        r":\s*&(mut\s+)?Position\b",      # position_nft: &Position
        r":\s*&(mut\s+)?Pool\b",           # pool: &Pool
        r":\s*&(mut\s+)?Partner\b",        # partner: &Partner
        r"_nft:\s*&",                       # *_nft: &Type
    ]
    import re
    for pattern in owned_object_patterns:
        if re.search(pattern, code):
            return True

    # 如果描述提到 position_nft 参数但抱怨权限问题
    if "position_nft" in combined_lower and any(kw in combined_lower for kw in ["权限", "验证", "任意"]):
        return True

    return False


def check_move_copy_drop_safety(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 41: Move copy/drop 能力保护

    Move 的能力系统 (abilities) 在编译时强制类型安全:
    - 没有 `copy` 能力的类型不能复制
    - 没有 `drop` 能力的类型不能丢弃
    - 解引用 (*ref) 只有在类型有 copy 能力时才允许

    如果代码能编译通过，说明类型有正确的能力。

    常见误报:
    - "返回解引用的值可能导致资源复制问题" - 如果编译通过就是安全的
    - "对象可能被意外移动" - Move 借用检查器防止这种情况
    """
    combined_lower = combined.lower()

    # 检查是否是关于资源复制/移动的问题
    resource_keywords = [
        "资源复制", "resource copy", "解引用", "dereference",
        "意外移动", "unexpected move", "move semantics",
        "复制问题", "copy problem", "资源泄漏", "resource leak",
        "违反唯一性", "uniqueness violation"
    ]
    if not any(kw in combined_lower for kw in resource_keywords):
        return False

    # 如果代码中有 *ref 解引用操作
    if "*" in code and ("borrow" in code.lower() or "option::" in code.lower()):
        # Move 编译器强制 copy ability，如果编译通过就是安全的
        return True

    # 明确提到解引用问题
    if "解引用" in combined_lower or "*tick" in combined_lower or "*position" in combined_lower:
        return True

    return False


def check_defense_in_depth(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 42: 深度防御是安全实践

    双重检查 (double checking) 是安全的深度防御实践:
    - 先检查是否存在，再操作
    - 操作后再验证结果
    - 这是安全编码最佳实践，不是漏洞

    常见误报:
    - "双重检查可能掩盖漏洞" - 这是安全实践
    - "冗余检查" - 冗余检查更安全
    """
    combined_lower = combined.lower()

    # 检查是否抱怨双重检查
    double_check_keywords = [
        "双重检查", "double check", "redundant check",
        "冗余检查", "重复检查", "多次检查",
        "掩盖", "mask", "hide"
    ]
    if not any(kw in combined_lower for kw in double_check_keywords):
        return False

    # 如果漏洞类型是关于检查的安全问题
    if "检查" in combined_lower and ("对象" in combined_lower or "position" in combined_lower or "id" in combined_lower):
        return True

    return False


def check_code_quality_not_security(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 43: 代码质量问题 vs 安全漏洞

    某些问题是代码质量/性能问题，不是安全漏洞:
    - 循环优化 (缓存 vector length)
    - 变量命名
    - 代码风格
    - 编译器优化建议

    常见误报:
    - "循环中索引递增可能因编译器优化引发无限循环风险" - 这是代码质量
    - "可能性能退化至 O(n²)" - 这是性能问题
    - "当前安全，但模式危险" - 如果当前安全就不是漏洞
    """
    combined_lower = combined.lower()

    # 代码质量关键词
    quality_keywords = [
        "编译器优化", "compiler optimization", "性能退化",
        "performance degradation", "o(n²)", "o(n^2)",
        "当前安全", "currently safe", "模式危险",
        "pattern dangerous", "代码风格", "code style",
        "缓存长度", "cache length"
    ]
    if any(kw in combined_lower for kw in quality_keywords):
        return True

    # 如果描述说"当前安全"或"理论上不会"
    safe_phrases = [
        "当前安全", "理论上不会", "不会直接", "仍能正确运行",
        "不可能在 move", "无限循环风险"  # 如果同时说"风险"和"Move"通常是假设性的
    ]
    if any(phrase in combined_lower for phrase in safe_phrases):
        # 额外检查：如果同时有"风险"但没有具体攻击向量
        if "风险" in combined_lower and "攻击" not in combined_lower:
            return True

    return False


def check_sui_display_pattern(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 44: Sui Display 模式

    Sui 的 Display 对象用于 NFT 元数据展示:
    - Display<T> 对象定义 NFT 的显示字段
    - transfer::public_transfer(display, sender) 是标准模式
    - Display 给用户持有是正常的设计

    常见误报:
    - "Display 对象误发给用户" - 这是正常设计
    - "Display 资源脱离管理" - Display 本来就是用户的
    """
    combined_lower = combined.lower()

    # 检查是否关于 Display 的问题
    if "display" not in combined_lower:
        return False

    # Display 相关误报关键词
    display_fp_keywords = [
        "误发给用户", "transfer to user", "资源泄漏",
        "脱离管理", "重复更新", "ui 混乱",
        # 🔥 v2.5.16: 新增
        "立即转移", "无法被合约追踪", "无法追踪",
        "创建后", "转移给"
    ]
    if any(kw in combined_lower for kw in display_fp_keywords):
        return True

    return False


def check_publisher_init_transfer(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 46: Publisher 在 init 中转移是标准模式

    🔥 v2.5.16 新增

    Sui 的 Publisher 模式:
    - package::claim<T>(otw, ctx) 在 init 中创建 Publisher
    - transfer::public_transfer(publisher, sender) 转移给发布者
    - 这是 Sui 的标准模式，Publisher 就是给发布者持有的

    常见误报:
    - "Publisher Transfer Grants Full Module Control" - 这是设计意图
    - "Publisher 转移给 sender" - 这是正常行为
    """
    combined_lower = combined.lower()
    func_lower = func_name.lower() if func_name else ""

    # 检查是否关于 Publisher 的问题
    if "publisher" not in combined_lower:
        return False

    # 如果是 init 函数
    if func_lower == "init" or "init" in func_lower:
        # Publisher 在 init 中的任何操作都是正常的
        if any(kw in combined_lower for kw in ["transfer", "转移", "控制", "control"]):
            return True

    # Publisher transfer 相关
    publisher_fp_keywords = [
        "publisher transfer", "publisher 转移",
        "full module control", "完全控制",
        "grants.*control", "授予.*控制"
    ]
    if any(kw in combined_lower for kw in publisher_fp_keywords):
        return True

    return False


def check_correct_permission_model(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 47: 描述说权限模型正确

    🔥 v2.5.16 新增

    如果漏洞描述本身说"权限模型正确"或"设计正确"，
    那就不应该被标记为漏洞。

    常见误报:
    - "权限模型正确但存在潜在风险" - 正确就不是漏洞
    - "设计合理但可能被滥用" - 合理设计不是漏洞
    """
    combined_lower = combined.lower()

    # 检查描述是否说正确/合理
    correct_keywords = [
        "权限模型正确", "设计正确", "模型正确",
        "permission model correct", "design correct",
        "正确但存在潜在", "合理但",
        "正确但可能", "设计合理但"
    ]
    if any(kw in combined_lower for kw in correct_keywords):
        return True

    return False


def check_readonly_reference_exposure(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 48: 只读引用暴露不是安全问题

    🔥 v2.5.16 新增

    Move 的引用系统:
    - &T 是只读引用，无法修改数据
    - 暴露 &PositionInfo 等只读引用是安全的
    - 这是提供数据访问的标准方式

    常见误报:
    - "公开暴露内部资源引用可能导致对象安全问题" - 只读引用是安全的
    - "暴露 &Type 引用" - 只读不可修改
    """
    combined_lower = combined.lower()

    # 检查是否关于引用暴露
    if "引用" not in combined_lower and "reference" not in combined_lower:
        return False

    # 检查是否是关于暴露/安全问题
    exposure_keywords = [
        "暴露", "公开", "expose", "public",
        "安全问题", "security issue", "对象安全"
    ]
    if not any(kw in combined_lower for kw in exposure_keywords):
        return False

    # 检查是否是只读引用 (& 而不是 &mut)
    code_lower = (code or "").lower()
    if "&mut" in code_lower:
        return False  # 可变引用需要审查

    # 如果代码中有 & 但没有 &mut，是只读引用
    if "& " in code or "&position" in code_lower or "&pool" in code_lower:
        return True

    # 特殊：如果提到 "只读" 或 "虽为只读"
    if "只读" in combined_lower or "read-only" in combined_lower:
        return True

    return False


def check_blockchain_public_data(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 45: 区块链数据天然公开

    区块链上的所有数据都是公开的:
    - 任何人都可以读取链上状态
    - getter 函数只是提供便捷访问
    - "暴露状态"不是漏洞，因为数据本来就公开

    常见误报:
    - "暴露内部状态" - 链上状态本来就公开
    - "助涨枚举攻击" - 链上数据随时可读
    - "信息泄露" - 对于公开区块链没有意义
    - "enables attackers to scan" - 链上数据本来就可以扫描

    🔥 v2.5.16: 增强匹配 - 公开查询函数
    """
    combined_lower = combined.lower()
    func_lower = func_name.lower() if func_name else ""

    # 检查是否关于信息泄露/暴露
    info_leak_keywords = [
        "暴露", "泄露", "leak", "expose", "exposing",
        "枚举攻击", "enumeration", "信息泄露",
        "scan for", "扫描", "targeting", "target"
    ]
    if not any(kw in combined_lower for kw in info_leak_keywords):
        return False

    # 检查是否是关于公开状态/查询的
    public_state_keywords = [
        "状态", "state", "数量", "count", "长度", "length",
        "分布", "distribution", "流动性", "liquidity",
        # 🔥 v2.5.16: 新增 - 查询/位置相关
        "position", "vulnerable", "attacked", "query", "inquiry",
        "check", "检查", "查询"
    ]
    if any(kw in combined_lower for kw in public_state_keywords):
        return True

    # 🔥 v2.5.16: 如果是 is_* 或 get_* 函数，这是纯查询
    if func_lower.startswith("is_") or func_lower.startswith("get_"):
        # 如果描述涉及"公开"或"anyone can"
        if any(kw in combined_lower for kw in ["public", "anyone", "任何人", "publicly"]):
            return True

    return False


def check_resource_forge_impossible(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 49: Move 资源无法伪造

    Move 类型系统的核心安全保证:
    1. struct 只能由定义它的模块创建 (module-level encapsulation)
    2. 即使是有 copy/drop 的类型也只能在定义模块内创建
    3. 外部模块只能使用公开的构造函数（如果有的话）
    4. 没有反射/序列化绕过机制

    常见误报:
    - "伪造 Tick 数据" - Tick 只能由 tick.move 模块创建
    - "伪造 Position" - Position 只能由 position.move 模块创建
    - "构造恶意资源" - Move 不允许跨模块构造资源
    - "fake/forge object" - 类型系统强制阻止

    🔥 v2.5.17: 通用资源伪造检测 (不限于跨模块)
    """
    combined_lower = combined.lower()

    # 伪造相关关键词
    forge_keywords = [
        "伪造", "fake", "forge", "forged", "forging",
        "构造恶意", "构造假", "创建假", "create fake",
        "malicious.*data", "恶意.*数据"
    ]

    if not any(kw in combined_lower for kw in forge_keywords):
        return False

    # 资源/数据类型关键词 - 这些是 Move struct 类型
    resource_keywords = [
        "tick", "position", "pool", "coin", "balance",
        "object", "resource", "struct", "资源", "对象",
        "数据", "data", "状态", "state"
    ]

    if any(kw in combined_lower for kw in resource_keywords):
        # 确认是关于类型伪造的漏洞
        # 排除：真正的逻辑漏洞（如价格操纵、数值计算错误）
        logic_bug_keywords = [
            "价格操纵", "price manipulation", "flash loan",
            "闪电贷", "oracle", "预言机", "计算错误"
        ]
        if any(kw in combined_lower for kw in logic_bug_keywords):
            return False  # 这些是真正的逻辑漏洞，不是伪造问题

        return True

    return False


def check_design_choice_not_vulnerability(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 50: 设计选择不是漏洞

    某些代码行为是故意的设计选择，不是安全漏洞：
    1. 向上取整 (ceil) - 保护协议免受舍入误差损失
    2. 费用分配比例 - 业务模型决策
    3. 从协议费中分配推荐费 - 合理的商业模式

    🔥 v2.5.18: 过滤设计选择类误报
    """
    combined_lower = combined.lower()

    # 向上取整相关 - 这是保护协议的设计
    ceil_keywords = [
        "向上取整", "ceil", "round up", "mul_div_ceil",
        "多付", "overpay", "多收"
    ]
    if any(kw in combined_lower for kw in ceil_keywords):
        # 如果说的是费用计算用 ceil，这是设计选择
        if any(fee_kw in combined_lower for fee_kw in ["fee", "费用", "手续费"]):
            return True

    # 费用分配比例 - 业务决策
    fee_allocation_keywords = [
        "分配比例", "allocation ratio", "fee distribution",
        "基于.*计算", "from protocol fee", "从协议费",
        "ref_fee", "推荐费", "referral fee"
    ]
    if any(kw in combined_lower for kw in fee_allocation_keywords):
        # 如果只是说分配比例"异常"或"不一致"或"逻辑错误"，这是设计选择
        # 🔥 v2.5.22: 增加 "逻辑错误", "激励不足" 关键词
        design_concern_keywords = [
            "异常", "不一致", "混淆", "unusual",
            "逻辑错误", "logic error", "激励不足", "incentive"
        ]
        if any(design_kw in combined_lower for design_kw in design_concern_keywords):
            return True

    return False


def check_precision_truncation_math(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 51: 精度截断是数学特性，不是安全漏洞

    所有定点数/整数系统都有精度损失：
    1. 右移 (>> / shr) 会丢失低位
    2. 除法会丢失余数
    3. 这是数学特性，不是安全漏洞

    只有当精度损失可被攻击者利用时才是漏洞（如反复交易累积）

    🔥 v2.5.18: 过滤精度截断类误报
    🔥 v2.5.19: 增强 - 覆盖 fee_delta, fixed-point math 等
    """
    combined_lower = combined.lower()
    code_lower = (code or "").lower()

    # 精度截断相关关键词
    precision_keywords = [
        "精度截断", "精度损失", "precision loss", "truncation", "truncating",
        "向下取整", "floor", "round down", "rounding down",
        "丢失.*精度", "lose precision", "loss of precision",
        "mul_shr", "右移", "shift right",
        # 🔥 v2.5.19: 新增
        "fixed-point", "定点", "lower.*bits", "低位"
    ]

    if not any(kw in combined_lower for kw in precision_keywords):
        return False

    # 🔥 v2.5.19: 如果是 fee/reward delta 计算的精度问题，这是定点数数学特性
    fee_reward_context = [
        "fee_delta", "fee delta", "reward_delta", "reward delta",
        "points_delta", "growth_delta",
        "lost fee", "lost reward", "lost point"
    ]
    if any(kw in combined_lower for kw in fee_reward_context):
        # 这是 DeFi 定点数计算的常见模式，不是安全漏洞
        return True

    # 如果描述中说"可能导致用户损失"但没有具体攻击路径，这是数学特性
    vague_impact = [
        "可能导致", "可能造成", "may cause", "could lead to",
        "长期累积", "微小", "negligible",
        # 🔥 v2.5.19: 新增
        "may fail to accumulate", "leading to", "fail to"
    ]
    if any(kw in combined_lower for kw in vague_impact):
        # 排除：有具体攻击向量的情况
        attack_vectors = [
            "反复交易", "套利", "arbitrage", "exploit",
            "攻击者可以", "attacker can", "malicious"
        ]
        if not any(kw in combined_lower for kw in attack_vectors):
            return True

    return False


def check_compile_time_value(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 52: 编译时确定的值不能被用户操控

    某些值在编译时就确定了，用户无法操控：
    1. type_name - 类型名称是编译时确定的
    2. 模块名/包名 - 编译时确定
    3. 常量值 - 编译时确定

    🔥 v2.5.18: 过滤编译时值相关误报
    """
    combined_lower = combined.lower()

    # type_name 相关
    if "type_name" in combined_lower or "typename" in combined_lower:
        # 如果说 type_name 可能过长或被操控
        if any(kw in combined_lower for kw in ["过长", "too long", "操控", "manipulate", "用户输入"]):
            return True

    # 向量长度 + type_name 组合
    if "向量" in combined_lower or "vector" in combined_lower:
        if "type" in combined_lower and any(kw in combined_lower for kw in ["长度", "length"]):
            return True

    return False


def check_invalid_finding_format(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 53: 无效的漏洞格式

    过滤格式不完整的漏洞报告：
    1. Location 为空或无效
    2. 没有具体代码引用
    3. N/A 作为关键字段

    🔥 v2.5.18: 过滤无效格式漏洞
    """
    location = finding.get("location", {})

    # 检查 location 是否为空或无效
    if isinstance(location, dict):
        func = location.get("function", "")
        module = location.get("module", "")
        if not func and not module:
            return True
        if func == "{}" or module == "{}":
            return True

    # 检查是否所有关键字段都是 N/A
    code_snippet = finding.get("code", "") or finding.get("vulnerable_code", "")
    recommendation = finding.get("recommendation", "")

    if code_snippet == "N/A" and recommendation == "N/A":
        return True

    return False


def check_state_field_semantics(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 54: 状态字段语义是设计选择

    状态字段（如 is_pause, status）的语义由开发者定义：
    1. is_pause 何时为 true 是业务决策
    2. 状态枚举的含义是设计选择
    3. 事件触发条件是业务逻辑

    "可能导致语义不一致" 或 "容易引起误解" 不是安全漏洞

    🔥 v2.5.19: 过滤状态语义相关误报
    """
    combined_lower = combined.lower()

    # 状态字段相关关键词
    state_keywords = [
        "is_pause", "is_paused", "status", "state",
        "标志位", "flag", "布尔", "boolean"
    ]

    if not any(kw in combined_lower for kw in state_keywords):
        return False

    # 语义/理解相关关键词 - 这些是设计选择
    semantics_keywords = [
        "语义不一致", "semantic", "inconsisten",
        "容易引起误解", "misleading", "confusing",
        "前端", "监控", "ui", "display",
        "可用性", "availability"
    ]

    if any(kw in combined_lower for kw in semantics_keywords):
        return True

    return False


def check_speculative_vulnerability(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 55: 猜测性漏洞

    过滤基于猜测而非实际代码分析的漏洞：
    1. "虽未显示在此处" - 没有看到实际代码
    2. "若其实现中" - 对实现的猜测
    3. 低置信度 + 模糊描述

    🔥 v2.5.19: 过滤猜测性漏洞
    """
    combined_lower = combined.lower()

    # 猜测性语言
    speculative_keywords = [
        "虽未显示", "although not shown", "not visible",
        "若其实现", "if its implementation", "if the implementation",
        "从命名看", "from the name", "judging by name",
        "可能会", "might", "perhaps",
        "假设", "assume", "assuming"
    ]

    if any(kw in combined_lower for kw in speculative_keywords):
        return True

    return False


def check_commented_code_issue(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 56: 注释掉的代码不是运行时漏洞

    注释掉的代码是代码审查问题，不是运行时安全漏洞：
    1. 注释掉的代码不会被执行
    2. 开发者可能有意为之（设计选择）
    3. 这是代码风格/质量问题

    🔥 v2.5.20: 过滤注释代码相关误报
    """
    combined_lower = combined.lower()
    code_lower = (code or "").lower()

    # 注释代码相关关键词
    comment_keywords = [
        "注释掉", "commented out", "commented-out",
        "//", "被注释", "注释的"
    ]

    if any(kw in combined_lower for kw in comment_keywords):
        # 确认是关于注释掉的代码
        if any(code_kw in combined_lower for code_kw in [
            "权限检查", "permission check", "role check",
            "验证", "validation", "assert"
        ]):
            return True

    # 检查 vulnerable code 是否以 // 开头
    if code_lower.startswith("//"):
        return True

    return False


def check_admin_function_design(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 57: 管理员功能是设计选择

    管理员/紧急功能的"风险"是设计的一部分：
    1. emergency_pause 需要管理员权限才能调用
    2. 有权限检查的管理功能不是漏洞
    3. "可能导致协议冻结" 是紧急功能的预期行为

    🔥 v2.5.20: 过滤管理员功能误报
    """
    combined_lower = combined.lower()
    code_lower = (code or "").lower()

    # 管理员/紧急功能关键词
    admin_keywords = [
        "emergency", "紧急", "pause", "暂停",
        "admin", "管理员", "owner", "authority"
    ]

    if not any(kw in combined_lower or kw in func_name.lower() for kw in admin_keywords):
        return False

    # 检查是否有权限检查
    permission_check_patterns = [
        "check_.*role", "check_.*permission", "check_.*admin",
        "verify.*role", "assert.*role", "require.*role"
    ]

    # 如果代码中有权限检查，且漏洞描述是关于"可能被触发"
    if any(p in code_lower for p in ["check_", "role", "permission"]):
        trigger_concerns = [
            "可被.*触发", "可能导致.*冻结", "永久冻结",
            "may cause.*freeze", "protocol freeze"
        ]
        if any(kw in combined_lower for kw in trigger_concerns):
            return True

    return False


def check_typo_naming_issue(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 58: 拼写错误/命名问题不是安全漏洞

    变量名拼写错误是代码风格问题：
    1. 代码仍然正确执行
    2. 只影响可读性和维护性
    3. 不影响运行时安全

    🔥 v2.5.21: 过滤命名/拼写问题
    """
    combined_lower = combined.lower()

    # 拼写/命名错误关键词
    typo_keywords = [
        "拼写错误", "typo", "spelling error", "misspell",
        "命名错误", "naming error", "variable name",
        "重命名", "rename", "命名规范"
    ]

    if any(kw in combined_lower for kw in typo_keywords):
        # 确认是关于命名问题而非逻辑错误
        logic_keywords = ["导致逻辑错误", "causes logic error", "wrong value"]
        if not any(kw in combined_lower for kw in logic_keywords):
            return True

    # 特殊：如果描述说"维护风险"而非安全风险
    if "维护" in combined_lower or "maintenance" in combined_lower:
        if "可读性" in combined_lower or "readability" in combined_lower:
            return True

    return False


def check_type_name_collision_impossible(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 60: Move 类型名碰撞不可能

    Move 类型系统的安全保证：
    1. type_name::with_defining_ids<T>() 返回完整路径：包地址::模块::类型
    2. 包地址由发布者控制，攻击者无法伪造
    3. 不同包的相同类型名有不同的完整路径
    4. "类型注入" 或 "类型碰撞" 在 Move 中不可能

    🔥 v2.5.22: 过滤类型碰撞相关误报
    """
    combined_lower = combined.lower()

    # 类型碰撞/注入相关关键词
    collision_keywords = [
        "类型.*碰撞", "type.*collision", "类型.*注入", "type.*inject",
        "同名类型", "same.*type.*name", "共享同一键", "share.*key",
        "类型键", "type.*key"
    ]

    if not any(kw in combined_lower for kw in collision_keywords):
        return False

    # 检查是否使用 type_name
    if "type_name" in combined_lower or "typename" in combined_lower:
        # Move 的 type_name 包含完整路径，碰撞不可能
        return True

    return False


def check_governance_delay_design(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 59: 治理延迟是设计选择

    即时更新 vs 延迟更新是治理设计选择：
    1. 很多协议的管理员操作是即时的
    2. 延迟机制是可选的安全增强，不是必需
    3. 有权限检查的即时更新不是漏洞

    🔥 v2.5.21: 过滤治理延迟相关误报
    """
    combined_lower = combined.lower()

    # 延迟相关关键词
    delay_keywords = [
        "delay", "延迟", "timelock", "时间锁",
        "confirmation", "确认步骤", "two-step", "两步",
        "challenge period", "挑战期"
    ]

    if not any(kw in combined_lower for kw in delay_keywords):
        return False

    # 如果说缺少延迟
    missing_delay = [
        "lack of", "缺乏", "missing", "缺少",
        "without", "未设置", "没有"
    ]

    if any(kw in combined_lower for kw in missing_delay):
        # 这是设计选择，不是漏洞
        return True

    return False


def check_admin_replay_protection(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 60: 管理员操作的重放问题是设计选择

    管理员操作是否需要防重放取决于业务设计：
    1. mint_cap 多次调用可能是允许的
    2. 有权限检查的操作由管理员控制
    3. "重复铸造" 或 "多次调用" 可能是预期行为

    🔥 v2.5.22: 过滤管理员重放相关误报
    """
    combined_lower = combined.lower()
    code_lower = (code or "").lower()

    # 重放/重复相关关键词
    replay_keywords = [
        "重放攻击", "replay attack", "重复.*铸造", "重复.*mint",
        "多次.*调用", "multiple.*call", "多个.*cap",
        "未防御重放", "未防止重复"
    ]

    if not any(kw in combined_lower for kw in replay_keywords):
        return False

    # 检查是否有管理员权限检查
    admin_check_patterns = [
        "check_.*role", "check_.*manager", "check_.*admin",
        "pool_manager", "admin_cap", "manager_role"
    ]

    if any(p in code_lower for p in admin_check_patterns):
        # 有管理员权限检查，重放由管理员控制
        return True

    # 如果描述说"权限检查存在"
    if "权限检查" in combined_lower and "存在" in combined_lower:
        return True

    return False


def check_admin_input_validation(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 61: 有管理员权限的输入验证不是安全漏洞

    管理员操作的输入验证是可选的：
    1. URL 长度/格式校验 - 管理员应该知道输入什么
    2. 字符串长度限制 - 代码质量问题
    3. 有权限检查的函数，输入由管理员控制

    🔥 v2.5.22: 过滤管理员输入验证相关误报
    """
    combined_lower = combined.lower()
    code_lower = (code or "").lower()

    # 输入验证相关关键词
    validation_keywords = [
        "长度", "length", "格式", "format",
        "有效性校验", "validation", "校验",
        "url", "字符串", "string"
    ]

    if not any(kw in combined_lower for kw in validation_keywords):
        return False

    # 检查是否有管理员权限检查
    admin_check_patterns = [
        "check_.*role", "check_.*manager", "check_.*admin",
        "pool_manager_role", "admin_role"
    ]

    if any(p in code_lower for p in admin_check_patterns):
        # 有管理员权限检查，输入由管理员控制
        return True

    # 如果是关于 URL 的验证
    if "url" in combined_lower:
        if any(kw in combined_lower for kw in ["缺少", "missing", "未", "lack"]):
            # 检查代码中是否有权限检查
            if "check_" in code_lower and "role" in code_lower:
                return True

    return False


# ============================================================================
# 🔥 v2.5.14: DeFi 通用设计模式规则
# ============================================================================

def check_flash_loan_permissionless(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 62: 闪电贷无许可设计是正常的

    闪电贷 (Flash Loan) 是 DeFi 基本原语：
    1. 设计上就是无许可的 - 任何人都可以借
    2. 安全性由原子性保证 - 同一交易内必须归还
    3. "未验证调用者" 不是漏洞，是设计特性
    """
    combined_lower = combined.lower()

    # 必须是闪电贷相关
    flash_keywords = ["flash_loan", "flashloan", "flash loan", "闪电贷", "闪贷", "flash_swap"]
    if not any(kw in combined_lower for kw in flash_keywords):
        return False

    # 如果是关于"未验证调用者"或"无许可" - 这是闪电贷的设计特性
    permissionless_issues = [
        "未验证调用者", "无权限", "任意用户", "任意调用",
        "no.*permission", "anyone can", "未验证身份", "permissionless"
    ]
    if any(p in combined_lower for p in permissionless_issues):
        return True

    return False


def check_fee_growth_wrapping(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 62b: Fee/Reward Growth 使用 wrapping 是 CLMM 协议的设计模式

    CLMM 协议（如 Uniswap v3、Cetus）中，fee growth 和 reward growth 使用
    wrapping arithmetic 是标准设计：
    - growth_global 会不断累加，最终溢出回绕
    - 通过快照差值计算实际应得费用/奖励
    - 这是故意设计，不是漏洞
    """
    combined_lower = combined.lower()

    # 必须涉及 fee/reward growth
    growth_keywords = [
        "fee_growth", "reward_growth", "points_growth", "growth_global",
        "fee growth", "reward growth", "points growth"
    ]
    if not any(kw in combined_lower for kw in growth_keywords):
        return False

    # 如果是关于 wrapping 导致的回绕 - 这是设计特性
    wrapping_issues = [
        "wrapping_add", "wrapping_sub", "回绕", "wrap around", "overflow"
    ]
    if any(p in combined_lower for p in wrapping_issues):
        return True

    return False


def check_allowlist_denylist_priority(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 63: 允许/拒绝列表优先级是设计选择

    Allow/Deny 列表的优先级是架构决策，不是漏洞。
    """
    combined_lower = combined.lower()

    # 必须涉及 allow/deny 列表
    if not any(kw in combined_lower for kw in ["allow", "deny", "whitelist", "blacklist", "白名单", "黑名单"]):
        return False

    # 如果是关于优先级冲突 - 这是设计选择
    if any(p in combined_lower for p in ["同时在", "优先级", "矛盾", "冲突", "行为不明确"]):
        return True

    return False


def check_defensive_abort_invalid_input(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 64: 无效输入导致的 abort 是防御机制，不是漏洞

    Move 的 abort 是正常的错误处理：
    - 除零 abort: 无效输入时的保护
    - 边界检查 abort: 防止非法状态

    除非 abort 会导致资金损失，否则不是漏洞。
    """
    combined_lower = combined.lower()

    # 必须是 abort 相关
    if not any(kw in combined_lower for kw in ["abort", "崩溃", "除零", "division by zero"]):
        return False

    # 如果涉及资金损失，不过滤
    if any(kw in combined_lower for kw in ["资金损失", "fund loss", "drain", "steal", "盗取"]):
        return False

    # 无效输入导致的 abort 是正常防御
    invalid_input_patterns = [
        "liquidity.*0", "流动性.*0", "amount.*0", "数量.*0",
        "price.*0", "价格.*0", "invalid.*input", "无效.*输入"
    ]
    if any(p in combined_lower for p in invalid_input_patterns):
        return True

    return False


def check_readonly_function_public(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 65: 只读函数公开访问是正常的

    判断只读的方式：检查代码中是否只有不可变引用 (&) 而没有可变引用 (&mut)
    """
    combined_lower = combined.lower()

    # 必须是关于"公开访问"或"无权限"的问题
    if not any(kw in combined_lower for kw in ["任意用户", "任意调用", "无权限", "未验证", "public"]):
        return False

    # 通过代码分析判断是否只读：没有 &mut 参数，也没有修改操作
    code_lower = (code or "").lower()

    # 如果有可变引用，可能会修改状态
    if "&mut " in code_lower:
        return False

    # 如果只有不可变引用，是只读函数
    if "&" in code_lower and "mut" not in code_lower:
        return True

    return False


def check_hot_potato_protection(finding: Dict, func_name: str, combined: str, code: str) -> bool:
    """规则 67: Hot Potato (烫手山芋) 模式保护

    🔥 v2.5.24 新增

    Sui Move 的 Hot Potato 模式用于强制执行特定操作序列：
    - Receipt 类型（如 FlashLoanReceipt, AddLiquidityReceipt）没有 store 能力
    - 用户无法存储、转移或伪造这些类型
    - 必须在同一交易中通过指定函数"还回"

    **常见误报**:
    - "FlashLoanReceipt 缺乏来源验证" - Hot Potato 已保证来源
    - "Receipt 可被伪造" - Receipt 没有 store 能力，无法伪造
    - "伪造还款绕过检查" - Hot Potato 模式已防护

    **原理**:
    - 只有定义模块能创建 Receipt 结构体
    - Receipt 无 store 能力，无法跨交易传递
    - Receipt 无 drop 能力，必须被"消费"

    ⚠️ **不过滤的情况 (真实漏洞)**:
    - 类型检查缺失: 借 Coin<A> 但还 Coin<B>
    - type_name 字段被忽略: `type_name: _`
    - 资产类型不一致
    """
    combined_lower = combined.lower()

    # 🔥 v2.5.24: 真实漏洞保护 - 类型检查缺失不应被过滤
    real_vulnerability_keywords = [
        "类型一致", "类型不一致", "类型检查", "类型验证", "类型缺失",
        "type.*consist", "type.*mismatch", "type.*check", "type.*valid",
        "资产一致", "资产类型", "资产.*验证",
        "type_name", "typename",
        "未验证.*类型", "未校验.*类型",
        "归还.*类型", "还款.*类型", "repay.*type",
        # 🔥 关键: 字段被忽略的模式
        "字段.*忽略", "field.*ignored", "_.*丢弃", "丢弃.*字段",
    ]

    import re
    for kw in real_vulnerability_keywords:
        kw_lower = kw.lower()
        if ".*" in kw_lower:
            if re.search(kw_lower, combined_lower):
                return False  # 不过滤，这是真实漏洞
        elif kw_lower in combined_lower:
            return False  # 不过滤，这是真实漏洞

    # 必须是关于 Receipt 类型伪造的问题
    receipt_keywords = [
        "receipt", "potato", "flashloan", "flash_loan", "flash loan",
        "addliquidity", "add_liquidity", "还款", "伪造",
        "FlashLoanReceipt", "FlashSwapReceipt", "AddLiquidityReceipt"
    ]

    if not any(kw.lower() in combined_lower for kw in receipt_keywords):
        return False

    # 检查是否是关于伪造/绕过的漏洞
    forge_keywords = [
        "伪造", "forge", "fake", "bypass", "绕过", "构造虚假",
        "缺乏来源验证", "lack.*verification", "without verification",
        "任意构造", "arbitrary"
    ]

    if any(kw in combined_lower for kw in forge_keywords):
        # 确认是 Receipt 类型的伪造问题
        if "receipt" in combined_lower:
            return True
        # 确认是闪电贷/流动性相关
        if any(kw in combined_lower for kw in ["flash", "liquidity", "loan", "swap"]):
            return True

    return False


# ============================================================================
# 规则注册表
# ============================================================================

EXCLUSION_RULES: List[ExclusionRule] = [
    # ========================================
    # Sui Move 语言层面保护 (规则 1-6)
    # ========================================
    ExclusionRule(
        id="rule_1",
        name="init_function",
        description="init(witness, ctx) 函数相关问题",
        check=check_init_function_issue,
        reason="Sui init(witness, ctx) 由运行时保护，只能发布时调用一次，外部无法调用"
    ),
    ExclusionRule(
        id="rule_2",
        name="witness_forge",
        description="witness 类型伪造",
        check=check_witness_forge,
        reason="witness 类型路径唯一，无法跨模块伪造"
    ),
    ExclusionRule(
        id="rule_3",
        name="private_call",
        description="private 函数直接调用",
        check=check_private_direct_call,
        reason="private 函数 Move 语言层面阻止外部调用"
    ),
    ExclusionRule(
        id="rule_4",
        name="txcontext_forge",
        description="TxContext 伪造",
        check=check_txcontext_forge,
        reason="TxContext 由运行时注入，无法伪造"
    ),
    ExclusionRule(
        id="rule_5",
        name="overflow_bypass",
        description="算术溢出绕过验证 (仅 +,-,*,/)",
        check=check_overflow_bypass,
        reason="Move 算术运算 (+,-,*,/) 溢出会 abort 交易 (注意: 位移运算 <<,>> 不会 abort)"
    ),
    ExclusionRule(
        id="rule_6",
        name="cross_module_forge",
        description="跨模块对象伪造",
        check=check_cross_module_forge,
        reason="Sui 类型系统阻止跨模块构造私有结构体"
    ),
    ExclusionRule(
        id="rule_6b",
        name="reentrancy_immunity",
        description="重入攻击免疫",
        check=check_reentrancy_immunity,
        reason="Move 无动态调度和回调机制，重入攻击不可能发生"
    ),
    ExclusionRule(
        id="rule_6c",
        name="move_language_protection",
        description="Move 语言级保护 (知识库)",
        check=check_move_language_protection,
        reason="Sui Move 语言级安全机制保护"
    ),
    # 🔥 v2.5.13 新增规则
    ExclusionRule(
        id="rule_6d",
        name="arithmetic_underflow",
        description="算术下溢保护 (Move 语言级)",
        check=check_arithmetic_underflow,
        reason="Move VM 对减法自动下溢检查，下溢时交易 abort，不会静默回绕"
    ),
    ExclusionRule(
        id="rule_6e",
        name="vector_bounds_safety",
        description="向量边界检查保护 (Move 语言级)",
        check=check_vector_bounds_safety,
        reason="Move vector::borrow/pop_back 自动边界检查，越界时交易 abort"
    ),
    ExclusionRule(
        id="rule_6f",
        name="code_style_not_vulnerability",
        description="代码风格问题 (非安全漏洞)",
        check=check_code_style_not_vulnerability,
        reason="调用顺序/位置是代码风格问题，只要所有检查都执行了就是安全的"
    ),
    # 🔥 v2.5.24 新增规则
    ExclusionRule(
        id="rule_6g",
        name="arithmetic_overflow",
        description="算术溢出保护 (Move 语言级)",
        check=check_arithmetic_overflow,
        reason="Move VM 对 +,-,* 自动溢出检查，溢出时交易 abort (注意: 位移 <<,>> 不会 abort!)"
    ),

    # ========================================
    # Sui Move 安全模式排除 (规则 7-12) - v2.5.1 新增
    # 基于 Cetus CLMM 等生产级合约分析
    # ========================================
    ExclusionRule(
        id="rule_7",
        name="capability_access_control",
        description="Capability-Based 权限控制",
        check=check_capability_access_control,
        reason="函数使用 Capability 参数 (如 &AdminCap) 进行权限控制，这是 Sui Move 标准模式"
    ),
    ExclusionRule(
        id="rule_8",
        name="package_visibility",
        description="public(package) 可见性",
        check=check_package_visibility,
        reason="public(package) 函数只能被同包模块调用，外部无法访问"
    ),
    ExclusionRule(
        id="rule_9",
        name="shared_object_design",
        description="共享对象设计模式",
        check=check_shared_object_design,
        reason="共享对象是 Sui 的设计模式，修改权限通过 ACL/Capability 控制"
    ),
    ExclusionRule(
        id="rule_10",
        name="event_function",
        description="Event 发射函数",
        check=check_event_function,
        reason="Event 函数用于链上日志记录，不涉及状态修改"
    ),
    ExclusionRule(
        id="rule_11",
        name="clock_dependency",
        description="Clock 时间依赖",
        check=check_clock_dependency,
        reason="sui::clock::Clock 是 Sui 提供的可信时间源，不能被用户操控"
    ),
    ExclusionRule(
        id="rule_12",
        name="treasury_cap_proof",
        description="TreasuryCap 所有权证明",
        check=check_treasury_cap_proof,
        reason="TreasuryCap 参数表示调用者是代币所有者/管理者"
    ),

    # ========================================
    # 非安全问题排除 (规则 13-17) - v2.5.0 原有
    # ========================================
    ExclusionRule(
        id="rule_13",
        name="hardcoded_constant",
        description="硬编码常量",
        check=check_hardcoded_constant,
        reason="硬编码常量是代码风格问题，非安全漏洞"
    ),
    ExclusionRule(
        id="rule_14",
        name="mock_function",
        description="Mock/测试函数",
        check=check_mock_function,
        reason="abort 0 是 mock/placeholder 实现，非实际漏洞"
    ),
    ExclusionRule(
        id="rule_15",
        name="pure_getter",
        description="纯 getter 函数",
        check=check_pure_getter,
        reason="纯 getter 函数只读状态，无安全风险"
    ),
    ExclusionRule(
        id="rule_16",
        name="debug_assertion",
        description="断言/调试信息",
        check=check_debug_assertion,
        reason="调试/断言信息是开发体验问题，非安全漏洞"
    ),
    ExclusionRule(
        id="rule_17",
        name="low_severity",
        description="LOW 严重性问题",
        check=check_low_severity,
        reason="LOW 严重性问题不纳入安全审计报告"
    ),

    # ========================================
    # Mock/CTF 项目排除 (规则 18-19) - v2.5.4 新增
    # ========================================
    ExclusionRule(
        id="rule_18",
        name="mock_call_site",
        description="调用 Mock/Stub 框架函数",
        check=check_mock_call_site,
        reason="框架函数 (object::new, transfer::*) 在测试环境是 mock 实现，会 abort 是预期行为"
    ),
    ExclusionRule(
        id="rule_19",
        name="ctf_test_project",
        description="CTF/测试项目特征",
        check=check_ctf_test_project,
        reason="CTF/测试项目使用 mock 框架函数，abort 行为不是真实漏洞"
    ),

    # ========================================
    # 🔥 v2.5.5 新增规则 (规则 20-22)
    # 基于 Cetus CLMM 审计分析
    # ========================================
    ExclusionRule(
        id="rule_20",
        name="test_only_function",
        description="#[test_only] 测试专用函数",
        check=check_test_only_function,
        reason="#[test_only] 函数仅在测试环境可用，生产构建时被移除，不是安全漏洞"
    ),
    ExclusionRule(
        id="rule_21",
        name="low_level_module_design",
        description="低层模块设计模式",
        check=check_low_level_module_design,
        reason="低层模块 (acl, math) 设计为无权限检查，由上层 wrapper 添加权限控制"
    ),
    ExclusionRule(
        id="rule_22",
        name="wrapper_protected_function",
        description="被 Wrapper 保护的内部函数",
        check=check_wrapper_protected_function,
        reason="内部实现函数 (*_internal) 由带权限检查的 wrapper 函数调用，不直接暴露"
    ),
    ExclusionRule(
        id="rule_23",
        name="deprecated_function",
        description="废弃函数 (abort EDeprecated)",
        check=check_deprecated_function,
        reason="废弃函数设计为不可调用，abort 是预期行为，不是 DoS 漏洞"
    ),

    # ========================================
    # 🔥 v2.5.7 新增规则 (规则 24-25)
    # ========================================
    ExclusionRule(
        id="rule_24",
        name="move_type_safety",
        description="Move 泛型类型系统安全",
        check=check_move_type_safety,
        reason="Move 泛型类型系统在编译时确保类型安全，bag/table 操作需要类型精确匹配，无法'构造任意类型'"
    ),
    ExclusionRule(
        id="rule_25",
        name="private_function_access",
        description="私有函数不需要访问控制",
        check=check_private_function_access,
        reason="私有函数 (非 public) 只能被同模块内函数调用，无法被外部直接访问，模块可见性天然提供访问控制"
    ),

    # ========================================
    # 🔥 v2.5.8 新增 (规则 26-27)
    # ========================================
    ExclusionRule(
        id="rule_26",
        name="dos_via_safe_abort",
        description="DoS via Safe Abort (Move 安全机制)",
        check=check_dos_via_safe_abort,
        reason="Move abort 是安全机制，交易失败但资金安全。checked_* 等函数触发的 abort 是正常防护行为，不是漏洞"
    ),
    ExclusionRule(
        id="rule_27",
        name="bit_shift_constant_safe",
        description="小常量位移操作 (ACL 权限位)",
        check=check_bit_shift_constant_safe,
        reason="ACL 权限位设置 (1 << role) 配合边界检查是安全的。注意: 非常量位移或数学计算中的位移需要人工审查 (Cetus $223M 漏洞类型)"
    ),

    # ========================================
    # 🔥 v2.5.14 新增规则 (规则 28-31)
    # 基于 Cetus CLMM 审计误报分析
    # ========================================
    ExclusionRule(
        id="rule_28",
        name="publisher_access_control",
        description="Sui Publisher 访问控制模式",
        check=check_publisher_access_control,
        reason="Publisher 只能由包发布者通过 package::claim 在 init 中创建，是有效的权限控制机制"
    ),
    ExclusionRule(
        id="rule_29",
        name="admin_business_decision",
        description="管理员权限内的业务决策",
        check=check_admin_business_decision,
        reason="有角色检查的情况下，参数范围/配置是管理员的业务决策，非安全漏洞"
    ),
    ExclusionRule(
        id="rule_30",
        name="version_protection_feature",
        description="版本保护安全特性",
        check=check_version_protection_feature,
        reason="版本检查 (version >= before_version) 是防止降级攻击的安全设计，不是漏洞"
    ),
    ExclusionRule(
        id="rule_31",
        name="user_voluntary_risk",
        description="用户自愿承担的风险",
        check=check_user_voluntary_risk,
        reason="fix_amount 等函数设计上让用户自己承担滑点风险，有基本检查即可"
    ),
    ExclusionRule(
        id="rule_32",
        name="parameter_validated_at_source",
        description="参数在源头已验证",
        check=check_parameter_validated_at_source,
        reason="Partner 的 ref_fee_rate 等参数在创建时已验证，使用时无需再次验证"
    ),
    ExclusionRule(
        id="rule_33",
        name="transaction_atomicity_safety",
        description="交易原子性保护",
        check=check_transaction_atomicity_safety,
        reason="Move/Sui 交易是原子的，失败时整个交易回滚，不存在'状态不一致'问题"
    ),
    ExclusionRule(
        id="rule_34",
        name="intentional_zero_assertion",
        description="故意的零值断言",
        check=check_intentional_zero_assertion,
        reason="非 Partner 路径的 ref_fee_amount == 0 是正确设计，不是漏洞"
    ),
    ExclusionRule(
        id="rule_35",
        name="precision_not_overflow",
        description="精度截断 vs 溢出",
        check=check_precision_not_overflow,
        reason="u128->u64 类型转换有范围检查时是精度问题，不是溢出漏洞"
    ),
    ExclusionRule(
        id="rule_36",
        name="dynamic_field_internal_state",
        description="动态字段内部状态管理",
        check=check_dynamic_field_internal_state,
        reason="内部状态管理的 dynamic_field 操作在调用链中已保证安全，panic 是安全失败模式"
    ),
    ExclusionRule(
        id="rule_37",
        name="public_getter_no_acl",
        description="公开 Getter 函数无需权限控制",
        check=check_public_getter_no_acl,
        reason="纯读取函数不修改状态，暴露的是公开信息，无需访问控制"
    ),
    ExclusionRule(
        id="rule_38",
        name="slippage_user_parameter",
        description="滑点参数由用户控制",
        check=check_slippage_user_parameter,
        reason="sqrt_price_limit 等滑点参数是用户提供的，用户自己决定可接受的滑点"
    ),
    ExclusionRule(
        id="rule_39",
        name="frequency_governance_issue",
        description="频率/速率限制是治理问题",
        check=check_frequency_governance_issue,
        reason="有角色检查的函数，调用频率应由治理/多签控制，不是合约层面的漏洞"
    ),

    # ========================================
    # 🔥 v2.5.16 新增规则 (规则 40-45)
    # 基于 Cetus CLMM 审计深度误报分析
    # ========================================
    ExclusionRule(
        id="rule_40",
        name="sui_object_ownership",
        description="Sui 对象所有权模型",
        check=check_sui_object_ownership,
        reason="Sui 对象引用参数 (&Position, &mut Position) 表示调用者必须是所有者，运行时强制检查"
    ),
    ExclusionRule(
        id="rule_41",
        name="move_copy_drop_safety",
        description="Move copy/drop 能力保护",
        check=check_move_copy_drop_safety,
        reason="Move 能力系统在编译时强制类型安全，解引用只有在类型有 copy 能力时才允许"
    ),
    ExclusionRule(
        id="rule_42",
        name="defense_in_depth",
        description="深度防御是安全实践",
        check=check_defense_in_depth,
        reason="双重检查是安全的深度防御实践，冗余检查更安全，不是漏洞"
    ),
    ExclusionRule(
        id="rule_43",
        name="code_quality_not_security",
        description="代码质量问题 vs 安全漏洞",
        check=check_code_quality_not_security,
        reason="循环优化、性能问题等是代码质量问题，如果描述说'当前安全'就不是安全漏洞"
    ),
    ExclusionRule(
        id="rule_44",
        name="sui_display_pattern",
        description="Sui Display 模式",
        check=check_sui_display_pattern,
        reason="Display<T> 对象转移给用户是 Sui NFT 的标准模式，不是资源泄漏"
    ),
    ExclusionRule(
        id="rule_45",
        name="blockchain_public_data",
        description="区块链数据天然公开",
        check=check_blockchain_public_data,
        reason="区块链上所有数据都是公开的，'暴露状态信息'对于公开区块链没有意义"
    ),
    ExclusionRule(
        id="rule_46",
        name="publisher_init_transfer",
        description="Publisher 在 init 中转移",
        check=check_publisher_init_transfer,
        reason="Publisher 在 init 中转移给 sender 是 Sui 标准模式，Publisher 本就是给发布者持有"
    ),
    ExclusionRule(
        id="rule_47",
        name="correct_permission_model",
        description="描述说权限模型正确",
        check=check_correct_permission_model,
        reason="如果漏洞描述本身说'权限模型正确'，那就不应该被标记为漏洞"
    ),
    ExclusionRule(
        id="rule_48",
        name="readonly_reference_exposure",
        description="只读引用暴露不是安全问题",
        check=check_readonly_reference_exposure,
        reason="Move 的 &T 是只读引用，暴露只读引用是提供数据访问的标准方式，不是安全问题"
    ),

    # ========================================
    # 🔥 v2.5.17 新增规则 (规则 49)
    # 通用 Move 资源伪造检测
    # ========================================
    ExclusionRule(
        id="rule_49",
        name="resource_forge_impossible",
        description="Move 资源无法伪造",
        check=check_resource_forge_impossible,
        reason="Move 类型系统保证：struct 只能由定义它的模块创建，外部无法伪造任何资源类型"
    ),

    # ========================================
    # 🔥 v2.5.18 新增规则 (规则 50-53)
    # 设计选择和数学特性
    # ========================================
    ExclusionRule(
        id="rule_50",
        name="design_choice_not_vulnerability",
        description="设计选择不是漏洞",
        check=check_design_choice_not_vulnerability,
        reason="向上取整、费用分配比例等是协议的设计选择，不是安全漏洞"
    ),
    ExclusionRule(
        id="rule_51",
        name="precision_truncation_math",
        description="精度截断是数学特性",
        check=check_precision_truncation_math,
        reason="定点数/整数运算的精度损失是数学特性，没有具体攻击向量时不是安全漏洞"
    ),
    ExclusionRule(
        id="rule_52",
        name="compile_time_value",
        description="编译时确定的值",
        check=check_compile_time_value,
        reason="type_name 等值在编译时确定，用户无法操控其长度或内容"
    ),
    ExclusionRule(
        id="rule_53",
        name="invalid_finding_format",
        description="无效的漏洞格式",
        check=check_invalid_finding_format,
        reason="漏洞报告格式不完整（无位置、代码为N/A等），无法验证"
    ),

    # ========================================
    # 🔥 v2.5.19 新增规则 (规则 54-55)
    # 设计选择和猜测性漏洞
    # ========================================
    ExclusionRule(
        id="rule_54",
        name="state_field_semantics",
        description="状态字段语义是设计选择",
        check=check_state_field_semantics,
        reason="is_pause/status 等状态字段的语义由开发者定义，'语义不一致'或'容易误解'不是安全漏洞"
    ),
    ExclusionRule(
        id="rule_55",
        name="speculative_vulnerability",
        description="猜测性漏洞",
        check=check_speculative_vulnerability,
        reason="基于猜测而非实际代码分析的漏洞（如'虽未显示在此处'、'若其实现中'）缺乏依据"
    ),

    # ========================================
    # 🔥 v2.5.20 新增规则 (规则 56-57)
    # 注释代码和管理员功能
    # ========================================
    ExclusionRule(
        id="rule_56",
        name="commented_code_issue",
        description="注释掉的代码不是运行时漏洞",
        check=check_commented_code_issue,
        reason="注释掉的代码不会被执行，开发者可能有意为之，这是代码风格问题而非安全漏洞"
    ),
    ExclusionRule(
        id="rule_57",
        name="admin_function_design",
        description="管理员功能是设计选择",
        check=check_admin_function_design,
        reason="有权限检查的管理员/紧急功能（如 emergency_pause）是设计的一部分，不是漏洞"
    ),

    # ========================================
    # 🔥 v2.5.21 新增规则 (规则 58-59)
    # 命名问题和治理设计
    # ========================================
    ExclusionRule(
        id="rule_58",
        name="typo_naming_issue",
        description="拼写错误/命名问题",
        check=check_typo_naming_issue,
        reason="变量名拼写错误是代码风格问题，代码仍正确执行，不是安全漏洞"
    ),
    ExclusionRule(
        id="rule_59",
        name="governance_delay_design",
        description="治理延迟是设计选择",
        check=check_governance_delay_design,
        reason="即时更新 vs 延迟更新是治理设计选择，有权限检查的即时更新不是漏洞"
    ),

    # ========================================
    # 🔥 v2.5.22 新增规则 (规则 60-61)
    # 管理员操作相关
    # ========================================
    ExclusionRule(
        id="rule_60",
        name="admin_replay_protection",
        description="管理员操作的重放问题",
        check=check_admin_replay_protection,
        reason="有权限检查的管理员操作，重放/重复调用由管理员控制，是设计选择"
    ),
    ExclusionRule(
        id="rule_61",
        name="admin_input_validation",
        description="管理员输入验证",
        check=check_admin_input_validation,
        reason="有权限检查的函数，输入验证（如 URL 格式）是代码质量问题，管理员应知道输入什么"
    ),
    ExclusionRule(
        id="rule_62",
        name="type_name_collision_impossible",
        description="Move 类型名碰撞不可能",
        check=check_type_name_collision_impossible,
        reason="Move type_name 包含完整路径(包地址::模块::类型)，攻击者无法伪造，类型碰撞不可能"
    ),

    # ========================================
    # 🔥 v2.5.14: DeFi 通用设计模式
    # ========================================
    ExclusionRule(
        id="rule_63",
        name="flash_loan_permissionless",
        description="闪电贷无许可设计",
        check=check_flash_loan_permissionless,
        reason="闪电贷设计上是无许可的，任何人可借但必须同交易归还，安全性由原子性保证"
    ),
    ExclusionRule(
        id="rule_63b",
        name="fee_growth_wrapping",
        description="Fee/Reward Growth wrapping 设计模式",
        check=check_fee_growth_wrapping,
        reason="CLMM 协议中 fee/reward growth 使用 wrapping arithmetic 是标准设计，通过快照差值计算费用"
    ),
    ExclusionRule(
        id="rule_64",
        name="allowlist_denylist_priority",
        description="允许/拒绝列表优先级",
        check=check_allowlist_denylist_priority,
        reason="Allow/Deny 列表的优先级是架构设计选择，不是安全漏洞"
    ),
    ExclusionRule(
        id="rule_65",
        name="defensive_abort_invalid_input",
        description="无效输入的防御性 abort",
        check=check_defensive_abort_invalid_input,
        reason="无效输入导致的 abort 是正常的防御机制，不是漏洞（除非导致资金损失）"
    ),
    ExclusionRule(
        id="rule_66",
        name="readonly_function_public",
        description="只读函数公开访问",
        check=check_readonly_function_public,
        reason="只读函数（无 &mut 参数）公开访问是正常的，区块链数据本身就是公开的"
    ),
    # 🔥 v2.5.24 新增规则
    ExclusionRule(
        id="rule_67",
        name="hot_potato_protection",
        description="Hot Potato 模式保护 (Receipt 无法伪造)",
        check=check_hot_potato_protection,
        reason="Hot Potato 类型 (如 FlashLoanReceipt) 无 store/drop 能力，用户无法伪造或存储，只有定义模块能创建"
    ),
]


# ============================================================================
# 主函数
# ============================================================================

def apply_exclusion_rules(
    findings: List[Dict[str, Any]],
    enabled_rules: List[str] = None,
    verbose: bool = True
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    应用排除规则过滤明显的非安全漏洞

    Args:
        findings: 原始漏洞发现列表
        enabled_rules: 启用的规则 ID 列表，None 表示全部启用
        verbose: 是否打印过滤信息

    Returns:
        (to_verify, filtered): 需要验证的发现, 已过滤的发现
    """
    # 🔥 v2.5.9: 如果禁用所有规则，直接返回所有发现让 AI 判断
    if DISABLE_ALL_EXCLUSION_RULES:
        if verbose:
            print(f"  ⚠️ 排除规则已禁用 (DISABLE_ALL_EXCLUSION_RULES=True)，{len(findings)} 个发现全部交给 AI 验证")
        return findings, []

    to_verify = []
    filtered = []
    soft_filtered_count = 0  # 🔥 v2.5.13: 软过滤计数

    # 确定启用的规则 (排除危险规则)
    rules_to_apply = [r for r in EXCLUSION_RULES if r.id not in DANGEROUS_RULES]
    if enabled_rules is not None:
        rules_to_apply = [r for r in rules_to_apply if r.id in enabled_rules]

    for finding in findings:
        # 提取检查所需的字段
        location = finding.get("location", {})
        func_name = location.get("function", "")
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        combined = title + " " + description

        # 提取代码片段
        code_snippet = finding.get("vulnerable_code", "") or location.get("code_snippet", "")

        # 应用所有规则
        is_filtered = False
        filter_reason = ""
        matched_rule = None

        for rule in rules_to_apply:
            if rule.check(finding, func_name, combined, code_snippet):
                is_filtered = True
                filter_reason = rule.reason
                matched_rule = rule
                break

        if is_filtered:
            # 🔥 v2.5.15: 高确信度规则即使在软过滤模式下也硬过滤
            is_high_confidence = matched_rule.id in HIGH_CONFIDENCE_RULES

            if SOFT_FILTER_MODE and not is_high_confidence:
                # 软过滤：标记但不删除，给 AI 提示
                finding["soft_filter_hint"] = {
                    "rule_id": matched_rule.id,
                    "rule_name": matched_rule.name,
                    "reason": filter_reason,
                    "hint_for_ai": f"⚠️ 此漏洞可能是误报。原因: {filter_reason}。但请仔细检查代码，如果存在开发者逻辑错误（如忘记验证类型、忘记检查条件），仍应判定为真实漏洞。"
                }
                to_verify.append(finding)  # 软过滤：仍然送去验证
                soft_filtered_count += 1
            else:
                # 硬过滤：直接删除（高确信度规则或非软过滤模式）
                finding["early_filter"] = {
                    "filtered": True,
                    "rule_id": matched_rule.id,
                    "rule_name": matched_rule.name,
                    "reason": filter_reason,
                    "verification_result": "false_positive",
                    "confidence": 99 if is_high_confidence else 95
                }
                filtered.append(finding)
        else:
            to_verify.append(finding)

    if verbose:
        if SOFT_FILTER_MODE and soft_filtered_count > 0:
            print(f"  🔶 软过滤: {soft_filtered_count} 个发现被标记（仍会送给 AI 验证，但提示可能是误报）")
        if filtered:
            print(f"  ⚡ 硬过滤: {len(filtered)} 个明显误报")
            for f in filtered[:3]:
                rule_name = f.get("early_filter", {}).get("rule_name", "unknown")
                reason = f.get("early_filter", {}).get("reason", "")
                print(f"     - [{rule_name}] {f.get('title', '')[:40]}: {reason[:50]}")
            if len(filtered) > 3:
                print(f"     ... 还有 {len(filtered) - 3} 个")

    return to_verify, filtered


def get_rule_by_id(rule_id: str) -> ExclusionRule:
    """根据 ID 获取规则"""
    for rule in EXCLUSION_RULES:
        if rule.id == rule_id:
            return rule
    return None


def get_all_rule_ids() -> List[str]:
    """获取所有规则 ID"""
    return [r.id for r in EXCLUSION_RULES]


def print_rules_summary():
    """打印所有规则摘要"""
    print("\n📋 排除规则列表:")
    print("-" * 60)
    for rule in EXCLUSION_RULES:
        print(f"  [{rule.id}] {rule.name}")
        print(f"      {rule.description}")
        print(f"      原因: {rule.reason}")
        print()
