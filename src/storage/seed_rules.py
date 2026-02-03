"""
系统规则种子数据

将现有 exclusion_rules.py 中的 74 条规则转换为数据库记录
"""
from typing import List, Dict

# 系统规则定义
# category: language_protection, access_control, arithmetic, resource_safety,
#           design_pattern, code_quality, defi_specific, production_pattern, semantic, custom

SYSTEM_RULES: List[Dict] = [
    # ========================================
    # 语言级保护 (Language Protection)
    # ========================================
    {
        "name": "check_init_function_issue",
        "display_name": "init 函数保护",
        "description": "Sui init(witness, ctx) 函数由运行时保护，只能在模块发布时调用一次，外部无法调用。",
        "category": "language_protection",
        "priority": 10,
    },
    {
        "name": "check_witness_forge",
        "display_name": "Witness 类型保护",
        "description": "Witness 类型路径唯一，无法跨模块伪造。Move 类型系统确保 witness 只能由定义模块创建。",
        "category": "language_protection",
        "priority": 11,
    },
    {
        "name": "check_private_direct_call",
        "display_name": "Private 函数保护",
        "description": "Private 函数在 Move 语言层面阻止外部调用，无需额外验证。",
        "category": "language_protection",
        "priority": 12,
    },
    {
        "name": "check_txcontext_forge",
        "display_name": "TxContext 保护",
        "description": "TxContext 由 Sui 运行时注入，无法伪造或篡改。",
        "category": "language_protection",
        "priority": 13,
    },
    {
        "name": "check_overflow_bypass",
        "display_name": "算术溢出 VM 保护",
        "description": "Move VM 对 +,-,* 运算自动溢出检查，溢出时交易 abort。注意：位移运算 (<<, >>) 不受此保护！",
        "category": "language_protection",
        "priority": 14,
    },
    {
        "name": "check_cross_module_forge",
        "display_name": "跨模块伪造保护",
        "description": "Sui 类型系统阻止跨模块构造私有结构体，无法伪造其他模块的对象。",
        "category": "language_protection",
        "priority": 15,
    },
    {
        "name": "check_reentrancy_immunity",
        "display_name": "重入攻击免疫",
        "description": "Move 无动态调度和回调机制，所有函数调用在编译时确定，重入攻击不可能发生。",
        "category": "language_protection",
        "priority": 16,
    },
    {
        "name": "check_move_language_protection",
        "display_name": "Move 语言级保护 (知识库)",
        "description": "使用 Sui Move 安全知识库检测语言级误报，包括类型安全、资源线性等。",
        "category": "language_protection",
        "priority": 17,
    },
    {
        "name": "check_arithmetic_underflow",
        "display_name": "算术下溢保护",
        "description": "Move VM 对减法自动下溢检查，下溢时交易 abort，不会静默回绕。",
        "category": "language_protection",
        "priority": 18,
    },
    {
        "name": "check_vector_bounds_safety",
        "display_name": "向量边界检查保护",
        "description": "Move vector::borrow/pop_back 自动边界检查，越界时交易 abort。",
        "category": "language_protection",
        "priority": 19,
    },
    {
        "name": "check_arithmetic_overflow",
        "display_name": "算术溢出保护 (语言级)",
        "description": "Move VM 对 +,-,* 自动溢出检查，溢出时交易 abort (位移 <<,>> 不会 abort!)。",
        "category": "language_protection",
        "priority": 20,
    },

    # ========================================
    # 访问控制 (Access Control)
    # ========================================
    {
        "name": "check_capability_access_control",
        "display_name": "Capability 权限控制",
        "description": "函数使用 Capability 参数 (如 &AdminCap) 进行权限控制，这是 Sui Move 标准模式。",
        "category": "access_control",
        "priority": 30,
    },
    {
        "name": "check_package_visibility",
        "display_name": "包可见性保护",
        "description": "public(package) 函数仅同包可调用，外部无法直接访问。",
        "category": "access_control",
        "priority": 31,
    },
    {
        "name": "check_shared_object_design",
        "display_name": "共享对象设计模式",
        "description": "Sui 共享对象的标准设计模式，使用 &mut 引用进行状态修改。",
        "category": "access_control",
        "priority": 32,
    },
    {
        "name": "check_treasury_cap_proof",
        "display_name": "TreasuryCap 权限证明",
        "description": "TreasuryCap 作为铸币权限的证明，持有者才能铸造代币。",
        "category": "access_control",
        "priority": 33,
    },
    {
        "name": "check_publisher_access_control",
        "display_name": "Publisher 访问控制",
        "description": "Publisher 对象是发布者专属的证明，用于 Display 和元数据管理。",
        "category": "access_control",
        "priority": 34,
    },
    {
        "name": "check_admin_business_decision",
        "display_name": "管理员业务决策",
        "description": "有权限检查的参数范围问题属于业务决策，不是安全漏洞。",
        "category": "access_control",
        "priority": 35,
    },
    {
        "name": "check_correct_permission_model",
        "display_name": "正确的权限模型",
        "description": "函数已有正确的权限检查，不需要额外的访问控制。",
        "category": "access_control",
        "priority": 36,
    },
    {
        "name": "check_private_function_access",
        "display_name": "私有函数访问",
        "description": "私有函数只能被同模块的公开函数调用，权限由调用者保证。",
        "category": "access_control",
        "priority": 37,
    },

    # ========================================
    # 资源安全 (Resource Safety)
    # ========================================
    {
        "name": "check_move_type_safety",
        "display_name": "Move 类型安全",
        "description": "Move 的线性类型系统确保资源不会被复制或丢弃，除非显式允许。",
        "category": "resource_safety",
        "priority": 50,
    },
    {
        "name": "check_move_copy_drop_safety",
        "display_name": "Copy/Drop 能力保护",
        "description": "Move 编译器强制类型 copy/drop 能力检查，无能力的类型无法复制或丢弃。",
        "category": "resource_safety",
        "priority": 51,
    },
    {
        "name": "check_sui_object_ownership",
        "display_name": "Sui 对象所有权模型",
        "description": "&Position 等引用参数要求调用者是所有者，运行时自动验证所有权。",
        "category": "resource_safety",
        "priority": 52,
    },
    {
        "name": "check_resource_forge_impossible",
        "display_name": "资源伪造不可能",
        "description": "Move 资源无法伪造，类型系统保证 struct 只能由定义模块创建。",
        "category": "resource_safety",
        "priority": 53,
    },
    {
        "name": "check_hot_potato_protection",
        "display_name": "Hot Potato 模式保护",
        "description": "无 drop 能力的对象必须被正确处理，Hot Potato 模式确保操作完整性。",
        "category": "resource_safety",
        "priority": 54,
    },

    # ========================================
    # 设计模式 (Design Pattern)
    # ========================================
    {
        "name": "check_event_function",
        "display_name": "事件发射函数",
        "description": "emit_* 等函数只是发射事件，不需要权限控制。",
        "category": "design_pattern",
        "priority": 70,
    },
    {
        "name": "check_clock_dependency",
        "display_name": "Clock 依赖",
        "description": "使用 &Clock 获取时间是 Sui 标准模式，时间由验证者共识确定。",
        "category": "design_pattern",
        "priority": 71,
    },
    {
        "name": "check_defense_in_depth",
        "display_name": "深度防御",
        "description": "双重检查是安全最佳实践，不是代码质量问题。",
        "category": "design_pattern",
        "priority": 72,
    },
    {
        "name": "check_sui_display_pattern",
        "display_name": "Sui Display 模式",
        "description": "transfer 给用户是正常设计，Display 模式用于 NFT 元数据。",
        "category": "design_pattern",
        "priority": 73,
    },
    {
        "name": "check_publisher_init_transfer",
        "display_name": "Publisher 初始化转移",
        "description": "在 init 中 transfer Publisher 给发布者是标准模式。",
        "category": "design_pattern",
        "priority": 74,
    },
    {
        "name": "check_version_protection_feature",
        "display_name": "版本保护特性",
        "description": "version >= before_version 是安全设计，防止状态回滚攻击。",
        "category": "design_pattern",
        "priority": 75,
    },
    {
        "name": "check_wrapper_protected_function",
        "display_name": "Wrapper 保护函数",
        "description": "*_internal 函数由外层 wrapper 函数保护，权限在 wrapper 中检查。",
        "category": "design_pattern",
        "priority": 76,
    },

    # ========================================
    # 代码质量 (Code Quality) - 非安全问题
    # ========================================
    {
        "name": "check_code_style_not_vulnerability",
        "display_name": "代码风格问题",
        "description": "调用顺序/位置是代码风格问题，只要所有检查都执行了就是安全的。",
        "category": "code_quality",
        "priority": 90,
    },
    {
        "name": "check_hardcoded_constant",
        "display_name": "硬编码常量",
        "description": "硬编码的数学常量 (如 100, 1000000) 通常是设计决策，不是安全问题。",
        "category": "code_quality",
        "priority": 91,
    },
    {
        "name": "check_mock_function",
        "display_name": "Mock 函数",
        "description": "名称含 mock/test/dummy 的函数是测试代码，不需要审计。",
        "category": "code_quality",
        "priority": 92,
    },
    {
        "name": "check_pure_getter",
        "display_name": "纯 Getter 函数",
        "description": "get_*/is_*/has_* 等纯读取函数不需要权限控制。",
        "category": "code_quality",
        "priority": 93,
    },
    {
        "name": "check_debug_assertion",
        "display_name": "调试断言",
        "description": "assert! 和 abort 用于调试和验证，不是安全漏洞。",
        "category": "code_quality",
        "priority": 94,
    },
    {
        "name": "check_low_severity",
        "display_name": "低严重性过滤",
        "description": "ADVISORY 级别的问题通常是建议性质，不是安全漏洞。",
        "category": "code_quality",
        "priority": 95,
    },
    {
        "name": "check_deprecated_function",
        "display_name": "废弃函数",
        "description": "标记为 deprecated 的函数是代码维护问题，不是安全漏洞。",
        "category": "code_quality",
        "priority": 96,
    },
    {
        "name": "check_code_quality_not_security",
        "display_name": "代码质量 vs 安全",
        "description": "循环优化、命名规范等是代码质量问题，不影响安全。",
        "category": "code_quality",
        "priority": 97,
    },
    {
        "name": "check_typo_naming_issue",
        "display_name": "拼写/命名问题",
        "description": "变量命名拼写错误 (如 upper_socre) 不是安全漏洞。",
        "category": "code_quality",
        "priority": 98,
    },
    {
        "name": "check_commented_code_issue",
        "display_name": "注释代码问题",
        "description": "注释掉的代码不是运行时漏洞，可能是开发者有意为之。",
        "category": "code_quality",
        "priority": 99,
    },

    # ========================================
    # 生产合约模式 (Production Pattern)
    # ========================================
    {
        "name": "check_mock_call_site",
        "display_name": "Mock 调用点",
        "description": "调用 mock/test 模块的函数是测试代码。",
        "category": "production_pattern",
        "priority": 110,
    },
    {
        "name": "check_ctf_test_project",
        "display_name": "CTF/测试项目",
        "description": "检测 CTF 或测试项目特征，这类项目不需要严格审计。",
        "category": "production_pattern",
        "priority": 111,
    },
    {
        "name": "check_test_only_function",
        "display_name": "#[test_only] 函数",
        "description": "#[test_only] 标记的函数只在测试时编译，不影响生产环境。",
        "category": "production_pattern",
        "priority": 112,
    },
    {
        "name": "check_low_level_module_design",
        "display_name": "低层模块设计",
        "description": "acl、math 等低层模块不做权限检查，由上层调用者负责。",
        "category": "production_pattern",
        "priority": 113,
    },
    {
        "name": "check_dos_via_safe_abort",
        "display_name": "安全 Abort 的 DoS",
        "description": "通过合法 abort 造成的 DoS 不是漏洞，交易失败是正常行为。",
        "category": "production_pattern",
        "priority": 114,
    },
    {
        "name": "check_bit_shift_constant_safe",
        "display_name": "常量位移安全",
        "description": "编译时确定的常量位移是安全的，只有动态位移才需要检查。",
        "category": "production_pattern",
        "priority": 115,
    },

    # ========================================
    # DeFi 特定 (DeFi Specific)
    # ========================================
    {
        "name": "check_user_voluntary_risk",
        "display_name": "用户自愿风险",
        "description": "fix_amount 等函数的滑点风险由用户承担，不是协议漏洞。",
        "category": "defi_specific",
        "priority": 130,
    },
    {
        "name": "check_parameter_validated_at_source",
        "display_name": "参数源头验证",
        "description": "Partner fee_rate 等参数在创建时已验证，使用时无需再检查。",
        "category": "defi_specific",
        "priority": 131,
    },
    {
        "name": "check_transaction_atomicity_safety",
        "display_name": "交易原子性保护",
        "description": "Move 交易失败会回滚，不会有状态不一致问题。",
        "category": "defi_specific",
        "priority": 132,
    },
    {
        "name": "check_intentional_zero_assertion",
        "display_name": "故意的零值断言",
        "description": "ref_fee_amount == 0 等断言是设计意图，不是漏洞。",
        "category": "defi_specific",
        "priority": 133,
    },
    {
        "name": "check_precision_not_overflow",
        "display_name": "精度截断 vs 溢出",
        "description": "有范围检查的 u128->u64 转换是精度问题，不是溢出漏洞。",
        "category": "defi_specific",
        "priority": 134,
    },
    {
        "name": "check_dynamic_field_internal_state",
        "display_name": "动态字段内部状态",
        "description": "pending 等动态字段是内部状态管理，不需要外部验证。",
        "category": "defi_specific",
        "priority": 135,
    },
    {
        "name": "check_public_getter_no_acl",
        "display_name": "公开 Getter 无需权限",
        "description": "公开的 Getter 函数读取公开数据，不需要权限控制。",
        "category": "defi_specific",
        "priority": 136,
    },
    {
        "name": "check_slippage_user_parameter",
        "display_name": "滑点用户参数",
        "description": "sqrt_price_limit 等滑点参数由用户控制，用户自担风险。",
        "category": "defi_specific",
        "priority": 137,
    },
    {
        "name": "check_frequency_governance_issue",
        "display_name": "频率/速率治理问题",
        "description": "有角色检查的频率/速率限制是治理问题，不是安全漏洞。",
        "category": "defi_specific",
        "priority": 138,
    },
    {
        "name": "check_flash_loan_permissionless",
        "display_name": "闪电贷无权限设计",
        "description": "闪电贷设计为无权限访问，通过 Hot Potato 模式确保还款。",
        "category": "defi_specific",
        "priority": 139,
    },
    {
        "name": "check_fee_growth_wrapping",
        "display_name": "Fee Growth 回绕设计",
        "description": "fee_growth 使用 wrapping 算术是 CLMM 标准设计，不是溢出漏洞。",
        "category": "defi_specific",
        "priority": 140,
    },
    {
        "name": "check_allowlist_denylist_priority",
        "display_name": "允许/拒绝列表优先级",
        "description": "allowlist/denylist 的优先级是业务设计选择。",
        "category": "defi_specific",
        "priority": 141,
    },
    {
        "name": "check_precision_truncation_math",
        "display_name": "精度截断数学特性",
        "description": "定点数系统的精度损失是数学特性，无攻击向量不是漏洞。",
        "category": "defi_specific",
        "priority": 142,
    },

    # ========================================
    # 语义分析 (Semantic)
    # ========================================
    {
        "name": "check_blockchain_public_data",
        "display_name": "区块链数据公开",
        "description": "区块链数据天然公开，暴露状态不是漏洞。",
        "category": "semantic",
        "priority": 150,
    },
    {
        "name": "check_readonly_reference_exposure",
        "display_name": "只读引用暴露",
        "description": "暴露只读引用 (&T) 不会导致状态被篡改。",
        "category": "semantic",
        "priority": 151,
    },
    {
        "name": "check_design_choice_not_vulnerability",
        "display_name": "设计选择 vs 漏洞",
        "description": "向上取整保护协议、费用分配比例等是业务设计决策。",
        "category": "semantic",
        "priority": 152,
    },
    {
        "name": "check_compile_time_value",
        "display_name": "编译时确定值",
        "description": "type_name 等编译时确定的值，用户无法操控。",
        "category": "semantic",
        "priority": 153,
    },
    {
        "name": "check_invalid_finding_format",
        "display_name": "无效漏洞格式",
        "description": "Location 为空、代码为 N/A 等无效报告格式。",
        "category": "semantic",
        "priority": 154,
    },
    {
        "name": "check_state_field_semantics",
        "display_name": "状态字段语义",
        "description": "is_pause 等状态字段的语义由开发者定义，不是漏洞。",
        "category": "semantic",
        "priority": 155,
    },
    {
        "name": "check_speculative_vulnerability",
        "display_name": "猜测性漏洞",
        "description": "「虽未显示」「若其实现中」等猜测性描述不是确定的漏洞。",
        "category": "semantic",
        "priority": 156,
    },
    {
        "name": "check_admin_function_design",
        "display_name": "管理员功能设计",
        "description": "有权限检查的 emergency_pause 等是正常管理功能。",
        "category": "semantic",
        "priority": 157,
    },
    {
        "name": "check_governance_delay_design",
        "display_name": "治理延迟设计",
        "description": "即时更新 vs timelock 是设计决策，不是漏洞。",
        "category": "semantic",
        "priority": 158,
    },
    {
        "name": "check_admin_replay_protection",
        "display_name": "管理员重放保护",
        "description": "mint_cap 多次调用是设计选择，有权限检查就是安全的。",
        "category": "semantic",
        "priority": 159,
    },
    {
        "name": "check_admin_input_validation",
        "display_name": "管理员输入验证",
        "description": "URL 格式等由管理员控制的输入，信任管理员判断。",
        "category": "semantic",
        "priority": 160,
    },
    {
        "name": "check_type_name_collision_impossible",
        "display_name": "类型名碰撞不可能",
        "description": "type_name 包含完整路径，攻击者无法伪造碰撞。",
        "category": "semantic",
        "priority": 161,
    },
    {
        "name": "check_defensive_abort_invalid_input",
        "display_name": "防御性 Abort",
        "description": "对无效输入 abort 是防御性编程，不是漏洞。",
        "category": "semantic",
        "priority": 162,
    },
    {
        "name": "check_readonly_function_public",
        "display_name": "只读函数公开",
        "description": "只读函数公开访问不影响安全，区块链数据本来就公开。",
        "category": "semantic",
        "priority": 163,
    },
]


async def seed_system_rules(db):
    """将系统规则种子数据插入数据库"""
    from sqlalchemy import select
    from .database import SystemRule, RuleCategory, Blockchain

    # 检查是否已有数据
    result = await db.execute(select(SystemRule).limit(1))
    if result.scalar_one_or_none():
        print("⏭️ 系统规则已存在，跳过种子数据")
        return

    # 插入种子数据
    for rule_data in SYSTEM_RULES:
        rule = SystemRule(
            name=rule_data["name"],
            display_name=rule_data["display_name"],
            description=rule_data["description"],
            blockchain=Blockchain.SUI,  # 所有现有规则都是 Sui Move 规则
            category=RuleCategory(rule_data["category"]),
            priority=rule_data["priority"],
            is_enabled=True,
        )
        db.add(rule)

    await db.commit()
    print(f"✅ 已插入 {len(SYSTEM_RULES)} 条系统规则 (Sui Move)")
