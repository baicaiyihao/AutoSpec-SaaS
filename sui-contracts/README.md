# AutoSpec Token Purchase 智能合约

简单的 SUI 收款合约，用于 AutoSpec Token 充值系统。

## 功能

- ✅ 接收用户支付的 SUI
- ✅ 记录 USD 金额和 Token 数量（发出事件）
- ✅ 管理员提现收入
- ✅ 事件驱动，供后端监听

## 架构设计

### 数据结构

| 结构体 | 类型 | 说明 |
|-------|------|------|
| `AdminCap` | 权限对象 | 管理员权限证明，拥有者可提现 |
| `SuiPool` | 共享对象 | SUI 收款池，存储所有用户支付的 SUI |
| `PurchaseEvent` | 事件 | 购买事件，记录买家、金额、Token 数量 |
| `WithdrawEvent` | 事件 | 提现事件，记录管理员提现操作 |

### 事件结构

**PurchaseEvent**:
```rust
{
    buyer: address,           // 买家钱包地址
    sui_amount: u64,          // 支付的 SUI（MIST，1 SUI = 10^9 MIST）
    usd_amount: u64,          // USD 金额（美分，1 USD = 100 cents）
    token_amount: u64,        // 应获得的 Token 数量
    timestamp: u64,           // 时间戳（毫秒）
}
```

**WithdrawEvent**:
```rust
{
    admin: address,           // 管理员地址
    recipient: address,       // 收款地址
    amount: u64,              // 提现金额（MIST）
    timestamp: u64,           // 时间戳（毫秒）
}
```

## 部署步骤

### 1. 安装 Sui CLI

```bash
# macOS/Linux
cargo install --locked --git https://github.com/MystenLabs/sui.git --branch testnet sui

# 验证安装
sui --version
```

### 2. 配置钱包

```bash
# 创建新钱包（如果没有）
sui client new-address ed25519

# 切换到 testnet
sui client switch --env testnet

# 获取测试币
sui client faucet
```

### 3. 构建合约

```bash
cd sui-contracts
sui move build
```

### 4. 部署合约

```bash
sui client publish --gas-budget 100000000
```

**部署后记录以下信息**：
- `PackageID`: 合约包 ID
- `SuiPool Object ID`: 收款池对象 ID
- `AdminCap Object ID`: 管理员权限对象 ID

## 使用方法

### 用户购买 Token

```bash
sui client call \
  --package <PACKAGE_ID> \
  --module token_purchase \
  --function purchase_tokens \
  --args \
    <PAYMENT_COIN_ID> \            # 支付的 SUI Coin 对象 ID
    <SUI_AMOUNT> \                  # 支付金额（MIST）
    <USD_AMOUNT> \                  # USD 金额（美分）
    <TOKEN_AMOUNT> \                # Token 数量
    <SUIPOOL_OBJECT_ID> \           # SuiPool 对象 ID
    <CLOCK_OBJECT_ID> \             # 时钟对象 ID: 0x6
  --gas-budget 10000000
```

**示例**（购买 $10 USD，支付 3.5 SUI，获得 1000 Token）：
```bash
sui client call \
  --package 0xabcd1234... \
  --module token_purchase \
  --function purchase_tokens \
  --args \
    0x5678efgh... \                 # 用户的 SUI Coin
    3500000000 \                    # 3.5 SUI = 3,500,000,000 MIST
    1000 \                          # $10.00 = 1000 美分
    1000 \                          # 1000 Token
    0x9012ijkl... \                 # SuiPool 对象 ID
    0x6 \                           # 时钟对象
  --gas-budget 10000000
```

### 管理员提现

```bash
sui client call \
  --package <PACKAGE_ID> \
  --module token_purchase \
  --function withdraw_commission \
  --args \
    <ADMINCAP_OBJECT_ID> \          # AdminCap 对象 ID
    <SUIPOOL_OBJECT_ID> \           # SuiPool 对象 ID
    <AMOUNT> \                      # 提现金额（MIST）
    <RECIPIENT_ADDRESS> \           # 收款地址
    0x6 \                           # 时钟对象 ID
  --gas-budget 10000000
```

### 查询池余额

```bash
sui client call \
  --package <PACKAGE_ID> \
  --module token_purchase \
  --function get_pool_balance \
  --args <SUIPOOL_OBJECT_ID> \
  --gas-budget 1000000
```

## 后端集成

### 监听购买事件

使用 Sui SDK 订阅 `PurchaseEvent` 事件：

```typescript
import { SuiClient } from '@mysten/sui.js/client';

const client = new SuiClient({ url: 'https://fullnode.testnet.sui.io' });

// 订阅购买事件
const unsubscribe = await client.subscribeEvent({
  filter: {
    MoveEventType: `${packageId}::token_purchase::PurchaseEvent`
  },
  onMessage: async (event) => {
    const { buyer, sui_amount, usd_amount, token_amount, timestamp } = event.parsedJson;

    // 验证交易
    // 更新数据库用户余额
    console.log(`购买事件: ${buyer} 支付 ${sui_amount} MIST，获得 ${token_amount} Token`);
  }
});
```

### 验证交易有效性

```typescript
// 获取交易详情
const txn = await client.getTransactionBlock({
  digest: event.id.txDigest,
  options: { showEffects: true, showEvents: true }
});

// 验证交易成功
if (txn.effects.status.status !== 'success') {
  throw new Error('交易失败');
}

// 验证事件数据
// 可选：验证价格合理性（对比 Pyth API 获取的价格）
```

## 单元测试

```bash
cd sui-contracts
sui move test
```

## 安全考虑

1. **管理员权限**：AdminCap 只能由部署者持有，提现需要该权限
2. **余额保护**：提现前检查池余额，防止超额提取
3. **参数验证**：purchase_tokens 验证金额 > 0
4. **事件审计**：所有关键操作都发出事件，可追溯

## 价格机制

合约本身**不验证价格**，价格由前端展示 + 后端验证：

1. **前端**：调用 Pyth Price Service HTTP API 获取实时 SUI/USD 价格
2. **用户**：看到价格后决定是否购买
3. **合约**：接收 SUI + 记录 USD/Token 数量
4. **后端**：监听事件，验证价格合理性（容差范围内），更新余额

**价格容差示例**：
```typescript
// 后端验证
const currentPrice = await getPythPrice(); // 例如 2.85 USD/SUI
const eventPrice = event.usd_amount / event.sui_amount; // 用户支付的价格

// 允许 5% 价格滑点
const tolerance = 0.05;
if (Math.abs(eventPrice - currentPrice) / currentPrice > tolerance) {
  console.warn('价格偏差过大，需要人工审核');
}
```

## Gas 费用估算

| 操作 | Gas 估算 |
|-----|---------|
| purchase_tokens | ~0.001 SUI |
| withdraw_commission | ~0.001 SUI |
| get_pool_balance | ~0.0001 SUI (读操作) |

## 后续优化

- [ ] 添加最小购买金额限制
- [ ] 添加紧急暂停功能
- [ ] 支持批量提现
- [ ] 添加价格限制（最大/最小 SUI 数量）
