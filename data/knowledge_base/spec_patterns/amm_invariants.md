# AMM (Automated Market Maker) Formal Verification Patterns

## Domain: amm, swap, liquidity, pool, dex

---

## 1. Swap Function Verification

For swap/exchange functions, MUST verify:

```move
#[spec(prove, ignore_abort)]
fun swap_spec<A, B>(pool: &mut Pool<A, B>, ...): SwapResult {
    // Input validation
    requires(amount > 0);

    let result = swap(pool, ...);

    // 1. Fee rate consistency
    ensures(result.fee_rate == pool.fee_rate);

    // 2. Input/Output bounds
    ensures(by_amount_in ==> result.amount_in + result.fee_amount <= input_amount);
    ensures(!by_amount_in ==> result.amount_out <= input_amount);

    // 3. Price validity
    ensures(result.after_sqrt_price > 0);

    // 4. Non-negative outputs
    ensures(result.amount_out >= 0);
    ensures(result.fee_amount >= 0);

    result
}
```

---

## 2. Liquidity Addition Verification

For add_liquidity functions, MUST verify:

```move
#[spec(prove)]
fun add_liquidity_spec<A, B>(...): u64 {
    // Input validity
    requires(input_a_value > 0);
    requires(input_b_value > 0);

    // Pool state consistency (either empty or non-empty)
    requires(
        old_L.is_zero!() && old_A.is_zero!() && old_B.is_zero!() ||
        !old_L.is_zero!() && !old_A.is_zero!() && !old_B.is_zero!()
    );

    // LP token invariant: L² ≤ A × B
    requires(old_L.mul(old_L).lte(old_A.mul(old_B)));

    let minted_lp = add_liquidity(...);

    // Post-conditions
    ensures(new_L.mul(new_L).lte(new_A.mul(new_B)));  // Invariant preserved
    ensures(new_L.mul(old_A).lte(new_A.mul(old_L)));  // No dilution
    ensures(new_L.mul(old_B).lte(new_B.mul(old_L)));
    ensures(new_balance_a >= old_balance_a);
    ensures(new_balance_b >= old_balance_b);

    minted_lp
}
```

---

## 3. Liquidity Removal Verification

For remove_liquidity functions, MUST verify:

```move
#[spec(prove)]
fun remove_liquidity_spec<A, B>(...): (Coin<A>, Coin<B>) {
    requires(lp_amount > 0);
    requires(lp_amount <= total_lp_supply);

    let (coin_a, coin_b) = remove_liquidity(...);

    // Proportional withdrawal
    ensures(out_a * total_lp <= burned_lp * balance_a);
    ensures(out_b * total_lp <= burned_lp * balance_b);

    // LP invariant preserved
    ensures(new_L.mul(new_L).lte(new_A.mul(new_B)));

    (coin_a, coin_b)
}
```

---

## 4. Calculate Swap Result (Pure Calculation)

For calculation functions without state modification:

```move
#[spec(prove, ignore_abort)]  // Use ignore_abort for while loops
fun calculate_swap_result_spec<A, B>(
    pool: &Pool<A, B>,
    a2b: bool,
    by_amount_in: bool,
    amount: u64,
): CalculatedSwapResult {
    requires(amount > 0);

    let result = calculate_swap_result(pool, a2b, by_amount_in, amount);

    // Config consistency
    ensures(result.fee_rate == pool.fee_rate);

    // Bound checking
    ensures(by_amount_in ==> result.amount_in + result.fee_amount <= amount);
    ensures(!by_amount_in ==> result.amount_out <= amount);

    // Price validity
    ensures(result.after_sqrt_price > 0);

    // Non-negative
    ensures(result.amount_out >= 0);
    ensures(result.fee_amount >= 0);

    result
}
```

---

## 5. Fee Calculation Verification

```move
#[spec(prove)]
fun calc_fee_spec(amount: u64, fee_rate: u64): u64 {
    requires((amount as u128) * (fee_rate as u128) <= 18446744073709551615);
    requires(fee_rate <= MAX_FEE_RATE);

    let fee = calc_fee(amount, fee_rate);

    ensures((fee as u128) <= (amount as u128) * (fee_rate as u128) / (FEE_DENOMINATOR as u128));
    ensures(fee <= amount);

    fee
}
```

---

## 6. Price/Sqrt Price Verification

```move
// Price must be positive
ensures(sqrt_price > 0);

// Price direction for swap
ensures(a2b ==> new_sqrt_price <= old_sqrt_price);
ensures(!a2b ==> new_sqrt_price >= old_sqrt_price);
```

---

## Key Invariants Summary

| Property | Verification |
|----------|-------------|
| LP Token Invariant | `L² ≤ A × B` |
| No Dilution | `new_L * old_A ≤ new_A * old_L` |
| Fee Bounds | `fee ≤ amount * rate / denominator` |
| Price Validity | `sqrt_price > 0` |
| Input/Output Bounds | `amount_in + fee ≤ input` |
