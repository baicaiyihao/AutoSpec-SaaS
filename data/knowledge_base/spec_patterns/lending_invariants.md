# Lending Protocol Formal Verification Patterns

## Domain: lending, borrow, repay, collateral, vault, cdp

---

## 1. Borrow Function Verification

```move
#[spec(prove)]
fun borrow_spec<T>(vault: &mut Vault<T>, amount: u64, ...): (Coin<T>, Receipt) {
    // Collateral check
    requires(collateral_value >= amount * collateral_ratio / 100);
    requires(amount > 0);
    requires(amount <= vault_available_liquidity);

    let (coin, receipt) = borrow(vault, amount, ...);

    // Receipt records correct amount
    ensures(receipt.loan_amount == amount);

    // Vault liquidity decreased
    ensures(new_liquidity == old_liquidity - amount);

    // Interest rate bounds
    ensures(receipt.interest_rate <= MAX_INTEREST_RATE);

    (coin, receipt)
}
```

---

## 2. Repay Function Verification (Hot Potato Pattern)

```move
#[spec(prove)]
fun repay_spec<T>(vault: &mut Vault<T>, payment: Coin<T>, receipt: Receipt) {
    // Payment must cover principal + interest
    requires(coin::value(&payment) >= receipt.loan_amount + receipt.accrued_interest);

    repay(vault, payment, receipt);

    // Vault liquidity restored
    ensures(new_liquidity >= old_liquidity + receipt.loan_amount);

    // Receipt consumed (hot potato destroyed)
    // No explicit ensures needed - type system enforces
}
```

---

## 3. Flash Loan Verification

```move
#[spec(prove)]
fun flash_borrow_spec<T>(vault: &mut Vault<T>, amount: u64): (Coin<T>, FlashReceipt) {
    requires(amount > 0);
    requires(amount <= vault_balance);

    let (coin, receipt) = flash_borrow(vault, amount);

    ensures(coin::value(&coin) == amount);
    ensures(receipt.amount == amount);
    ensures(receipt.fee == amount * flash_fee_rate / FEE_DENOMINATOR);

    (coin, receipt)
}

#[spec(prove)]
fun flash_repay_spec<T>(vault: &mut Vault<T>, payment: Coin<T>, receipt: FlashReceipt) {
    // Must repay principal + fee
    requires(coin::value(&payment) >= receipt.amount + receipt.fee);

    flash_repay(vault, payment, receipt);

    // Vault balance restored with fee
    ensures(new_balance >= old_balance + receipt.fee);
}
```

---

## 4. Collateral Management

```move
#[spec(prove)]
fun deposit_collateral_spec<T>(position: &mut Position, collateral: Coin<T>) {
    let deposit_value = coin::value(&collateral);
    requires(deposit_value > 0);

    deposit_collateral(position, collateral);

    ensures(new_collateral_balance == old_collateral_balance + deposit_value);
    ensures(new_health_factor >= old_health_factor);
}

#[spec(prove)]
fun withdraw_collateral_spec<T>(position: &mut Position, amount: u64): Coin<T> {
    // Health factor must remain above threshold after withdrawal
    requires(health_factor_after_withdrawal >= MIN_HEALTH_FACTOR);
    requires(amount <= collateral_balance);

    let coin = withdraw_collateral(position, amount);

    ensures(coin::value(&coin) == amount);
    ensures(new_collateral_balance == old_collateral_balance - amount);

    coin
}
```

---

## 5. Liquidation Verification

```move
#[spec(prove)]
fun liquidate_spec<T>(position: &mut Position, ...): Coin<T> {
    // Position must be undercollateralized
    requires(health_factor < MIN_HEALTH_FACTOR);

    let bonus = liquidate(position, ...);

    // Liquidator receives bonus
    ensures(coin::value(&bonus) >= liquidation_amount * bonus_rate / 100);

    // Position health improved
    ensures(new_health_factor >= old_health_factor);

    bonus
}
```

---

## 6. Interest Accrual

```move
#[spec(prove)]
fun accrue_interest_spec(vault: &mut Vault) {
    let old_total_borrows = vault.total_borrows;

    accrue_interest(vault);

    // Interest only increases borrows
    ensures(new_total_borrows >= old_total_borrows);

    // Interest rate within bounds
    ensures(vault.borrow_rate <= MAX_BORROW_RATE);
}
```

---

## Key Invariants Summary

| Property | Verification |
|----------|-------------|
| Collateral Ratio | `collateral_value >= debt * ratio` |
| Health Factor | `health_factor >= MIN_HEALTH_FACTOR` |
| Flash Loan Atomic | `repay in same tx, amount + fee` |
| Receipt Consumed | Hot potato pattern enforcement |
| Interest Bounds | `rate <= MAX_RATE` |
| Liquidity Conservation | `deposits = borrows + available` |
