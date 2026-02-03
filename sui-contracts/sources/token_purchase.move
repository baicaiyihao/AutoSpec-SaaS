/// AutoSpec Token 充值合约
///
/// 功能：
/// - 接收用户支付的 SUI
/// - 使用 Pyth 预言机获取实时价格
/// - 自动计算并扣除相应的 SUI
/// - 管理员提现收入
/// - 发出事件供后端监听
module autospec::token_purchase {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::event;
    use pyth::price_info::{Self, PriceInfoObject};
    use pyth::price::{Self};
    use pyth::i64::{Self};
    use pyth::pyth;
    use pyth::price_identifier;

    // ============================================================================
    // 错误码
    // ============================================================================

    const EInsufficientBalance: u64 = 1;
    const EInsufficientPayment: u64 = 2;
    const EInvalidAmount: u64 = 3;
    const EInvalidPriceFeed: u64 = 4;

    // ============================================================================
    // 结构体
    // ============================================================================

    /// 管理员权限证明
    public struct AdminCap has key, store {
        id: UID,
    }

    /// SUI 收款池（共享对象）
    public struct SuiPool has key {
        id: UID,
        balance: Balance<SUI>,  // 用户支付的 SUI 累积
    }

    /// 购买事件（后端监听）
    public struct PurchaseEvent has copy, drop {
        buyer: address,           // 买家地址
        sui_amount: u64,          // 支付的 SUI 数量（MIST 单位，1 SUI = 10^9 MIST）
        usd_amount: u64,          // 对应的 USD 金额（美分单位，1 USD = 100 cents）
        token_amount: u64,        // 应获得的 Token 数量
        timestamp: u64,           // 时间戳（毫秒）
    }

    /// 提现事件
    public struct WithdrawEvent has copy, drop {
        admin: address,
        recipient: address,
        amount: u64,              // 提现的 SUI 数量（MIST）
        timestamp: u64,
    }

    // ============================================================================
    // 初始化（仅部署时执行一次）
    // ============================================================================

    /// 模块初始化函数
    /// 自动创建 AdminCap 和 SuiPool
    fun init(ctx: &mut TxContext) {
        // 创建管理员权限，转移给部署者
        let admin_cap = AdminCap {
            id: object::new(ctx),
        };
        transfer::transfer(admin_cap, ctx.sender());

        // 创建 SUI 收款池，设为共享对象
        let pool = SuiPool {
            id: object::new(ctx),
            balance: balance::zero<SUI>(),
        };
        transfer::share_object(pool);
    }

    // ============================================================================
    // 内部辅助函数
    // ============================================================================

    /// 从 Pyth 获取 SUI/USD 价格（参考 Fate3AI）
    /// 返回: 价格（带 8 位小数，例如 112490000 表示 $1.1249）
    fun use_pyth_price(clock: &sui::clock::Clock, price_info_object: &PriceInfoObject): u64 {
        let max_age = 60;  // 最多 60 秒旧的价格

        // 获取不超过 max_age 秒的价格
        let price_struct = pyth::get_price_no_older_than(price_info_object, clock, max_age);

        // 验证是 SUI/USD price feed (Testnet)
        let price_info = price_info::get_price_info_from_price_info_object(price_info_object);
        let price_id = price_identifier::get_bytes(&price_info::get_price_identifier(&price_info));

        // Testnet SUI/USD: 0x50c67b3fd225db8912a424dd4baed60ffdde625ed2feaaf283724f9608fea266 (from Fate3AI)
        assert!(
            price_id == x"50c67b3fd225db8912a424dd4baed60ffdde625ed2feaaf283724f9608fea266",
            EInvalidPriceFeed,
        );

        // 获取价格
        let price_i64 = price::get_price(&price_struct);
        i64::get_magnitude_if_positive(&price_i64)
    }

    // ============================================================================
    // 用户购买函数
    // ============================================================================

    /// 购买 Token（自动从 Pyth 获取价格并计算扣款）
    ///
    /// # 参数
    /// - `payment`: 支付的 SUI Coin
    /// - `token_amount`: 要购买的 LLM Token 数量
    /// - `pool`: SUI 收款池
    /// - `price_info_object`: Pyth SUI/USD 价格信息对象
    /// - `clock`: 时钟对象
    /// - `ctx`: 交易上下文
    ///
    /// # 流程
    /// 1. 从 Pyth 获取实时 SUI/USD 价格
    /// 2. 根据 token_amount 计算需要支付的 SUI 数量
    /// 3. 从 payment 中扣除相应的 SUI
    /// 4. 发出购买事件供后端监听
    public entry fun purchase_tokens(
        payment: &mut Coin<SUI>,
        token_amount: u64,
        pool: &mut SuiPool,
        price_info_object: &PriceInfoObject,
        clock: &sui::clock::Clock,
        ctx: &mut TxContext,
    ) {
        // 验证 token 数量
        assert!(token_amount > 0, EInvalidAmount);

        // 从 Pyth 获取 SUI/USD 价格（带 8 位小数）
        let sui_price = use_pyth_price(clock, price_info_object);

        // 计算需要支付的美元金额
        // token_price = 0.0005 USD / 1000 tokens = 0.0000005 USD/token
        // usd_amount_usd = token_amount * 0.0000005 USD
        // 为了避免浮点运算和截断，先放大 token_amount：
        // usd_amount_cents = (token_amount * 5) / 10000 (美分 = USD * 100，所以 0.0000005 USD * 100 = 0.00005 cents)
        // 实际上：1000 tokens = $0.0005 = 0.05 cents，这会被截断
        // 改进：先计算 USD 微分（10^6 倍），再转回 cents
        // usd_micro_cents = token_amount * 50 (每个 token 0.00005 cents = 50 micro-cents)
        // usd_cents = usd_micro_cents / 1000000
        let usd_micro_cents = (token_amount as u128) * 50;
        let usd_amount_cents = (usd_micro_cents / 1000000) as u64;

        // 计算需要支付的 SUI 数量（MIST）
        // 为了避免精度损失，使用 micro_cents 直接计算
        // paysui_mist = (usd_micro_cents * 10^9) / (sui_price * 10)  (sui_price 已经是 10^8 倍了)
        let paysui_amount = ((usd_micro_cents * 1000000000) / ((sui_price as u128) * 10)) as u64;

        // 验证支付金额充足
        assert!(coin::value(payment) >= paysui_amount, EInsufficientPayment);

        // 从 payment 中分割出需要支付的部分
        let payment_coin = coin::split(payment, paysui_amount, ctx);

        // 转入收款池
        let payment_balance = coin::into_balance(payment_coin);
        balance::join(&mut pool.balance, payment_balance);

        // 发出购买事件
        event::emit(PurchaseEvent {
            buyer: ctx.sender(),
            sui_amount: paysui_amount,
            usd_amount: usd_amount_cents,
            token_amount,
            timestamp: sui::clock::timestamp_ms(clock),
        });
    }

    // ============================================================================
    // 管理员功能
    // ============================================================================

    /// 提现收入（需要管理员权限）
    ///
    /// # 参数
    /// - `_admin_cap`: 管理员权限证明（验证调用者是管理员）
    /// - `pool`: SUI 收款池
    /// - `amount`: 提现金额（MIST）
    /// - `recipient`: 接收地址
    /// - `clock`: 时钟对象
    /// - `ctx`: 交易上下文
    public entry fun withdraw_commission(
        _admin_cap: &AdminCap,
        pool: &mut SuiPool,
        amount: u64,
        recipient: address,
        clock: &sui::clock::Clock,
        ctx: &mut TxContext,
    ) {
        // 验证余额充足
        assert!(balance::value(&pool.balance) >= amount, EInsufficientBalance);

        // 从池中分割指定金额
        let withdraw_balance = balance::split(&mut pool.balance, amount);

        // 转换为 Coin 并转账
        let withdraw_coin = coin::from_balance(withdraw_balance, ctx);
        transfer::public_transfer(withdraw_coin, recipient);

        // 发出提现事件
        event::emit(WithdrawEvent {
            admin: ctx.sender(),
            recipient,
            amount,
            timestamp: sui::clock::timestamp_ms(clock),
        });
    }

    /// 查询池余额（只读）
    public fun get_pool_balance(pool: &SuiPool): u64 {
        balance::value(&pool.balance)
    }

    /// 创建新的管理员权限（需要现有管理员权限）
    public entry fun mint_admin_cap(
        _admin_cap: &AdminCap,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        let new_admin_cap = AdminCap {
            id: object::new(ctx),
        };
        transfer::transfer(new_admin_cap, recipient);
    }

    // ============================================================================
    // 测试辅助函数
    // ============================================================================

    #[test_only]
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx);
    }
}
