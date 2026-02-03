# Sui/Move Security Research Collection 2024-2025

## 1. Major Security Incidents

### 1.1 Cetus Protocol Hack (May 22, 2025) - $260M
**Severity:** Critical
**Type:** Arithmetic Overflow / CLMM Tick Account Manipulation

**Description:**
Cetus Protocol, the primary DEX on Sui, suffered a $260 million exploit. The attacker found a flaw in Cetus's "tick account" system used in Concentrated Liquidity Market Makers (CLMMs).

**Root Cause:**
- Arithmetic overflow in liquidity calculation
- Miscalculated liquidity withdrawal values in addLiquidity/removeLiquidity/swap functions
- Failed to validate inputs for tokens with no economic value (spoof tokens like BULLA)

**Attack Vector:**
1. Attacker introduced spoof tokens with no liquidity
2. Exploited tick account overflow to manipulate price calculations
3. Used minimal initial investment to drain real tokens

**Impact:**
- $223M stolen, $162M frozen
- SUI token dropped 15%
- CETUS dropped 40%+

**Lessons:**
- Audit math libraries thoroughly
- Validate all token inputs regardless of perceived value
- Multiple audits may still miss critical bugs

**Source:** https://cointelegraph.com/explained/how-220m-was-stolen-in-minutes-understanding-the-cetus-dex-exploit-on-sui

---

### 1.2 Nemo Protocol Exploit (September 2025) - $2.4M
**Severity:** High
**Type:** Yield Protocol Exploit

**Description:**
Nemo, a yield protocol on Sui, was exploited for $2.4M USDC.

**Impact:**
- TVL dropped from $6M to $1.53M
- Funds bridged to Ethereum via Arbitrum

---

### 1.3 Infinite Recursion Vulnerability (June 2023)
**Severity:** Critical
**Type:** Denial-of-Service (DoS)

**Description:**
A flaw in the Move VM allowed infinite recursive function calls causing stack overflows.

**Impact:**
- Could cause complete blockchain collapse
- Could force a hard fork on Sui/Aptos

**Resolution:** Fixed after 1+ month of development

---

### 1.4 Memory Pool DoS Vulnerability (September 2024)
**Severity:** High
**Type:** Denial-of-Service (DoS)

**Description:**
Inadequate transaction eviction mechanism in the memory pool could reject up to 90% of valid transactions.

**Resolution:** Fixed in Aptos v1.19.1, MoveBit credited

---

## 2. Common Vulnerability Patterns (SlowMist Audit Primer)

### 2.1 Overflow & Bitwise Operations
- Bitwise operations lack overflow checks unlike arithmetic
- Custom overflow detection may have flawed thresholds
- **Detection:** Check all bitwise ops, validate thresholds

### 2.2 Arithmetic Precision Errors
- Move lacks floating-point types
- Division operations cause precision loss
- **Detection:** Review all divisions, check for rounding issues

### 2.3 Race Conditions & Transaction Ordering
- Validators can reorder transactions for profit (MEV)
- **Detection:** Check if function outcomes depend on execution order

### 2.4 Access Control Bypass
- Internal functions accidentally exposed externally
- Missing permission checks
- **Detection:** Verify all public functions have proper auth

### 2.5 Object Permission Mismanagement
- Private objects incorrectly made shared
- All objects need clear classification
- **Detection:** Audit object visibility (address-owned, immutable, shared, wrapped)

### 2.6 Token Consumption Errors
- Sui's token nesting/splitting creates risks
- Mishandled transfers, amounts, object bindings
- **Detection:** Track all Coin/Balance flows

### 2.7 Flashloan Attacks
- Hot Potato pattern enables large borrows
- Price manipulation via oracle dependency
- **Detection:** Check oracle reliability, price validation

### 2.8 Unchecked Return Values
- Ignored return values prevent critical logic
- **Detection:** Verify all external call returns are handled

### 2.9 Denial of Service
- Logic errors cause contract unavailability
- **Detection:** Test error handling, edge cases

### 2.10 Contract Upgrade Issues
- Init functions only run on first deployment
- External package upgrades don't update dependents
- **Detection:** Review upgrade migration logic

### 2.11 Design Logic Flaws
- Implementation doesn't match business logic
- **Detection:** Map business flows against code paths

---

## 3. CTF Security Challenges (lets-ctf.vercel.app)

### Chapter 3: Generic Type Safety
**Vulnerability:** Improper generic type constraints
**Attack:** Forge voting credentials by exploiting type system
**Lesson:** Always validate generic type parameters

### Chapter 4: Resource Management
**Vulnerability:** Improper handling of Move resources
**Attack:** Resource leak or double-spend
**Lesson:** Ensure all resources are properly consumed/transferred

### Chapter 5: Access Control
**Vulnerability:** TxContext validation bypass
**Attack:** Authorization bypass
**Lesson:** Validate sender identity properly

### Chapter 6: State Logic
**Vulnerability:** Inconsistent state transitions
**Attack:** Exploit state machine flaws
**Lesson:** Test all state transition paths

### Chapter 7: Cross-Contract Interaction
**Vulnerability:** Insecure contract interactions
**Attack:** Callback manipulation, reentrancy-like issues
**Lesson:** Validate all cross-contract calls

---

## 4. Audit Report Sources

### Cetus Protocol
- MoveBit: https://github.com/CetusProtocol/Audit/blob/main/Cetus%20Sui%20Audit%20Report%20by%20MoveBit.pdf
- OtterSec: https://github.com/CetusProtocol/Audit/blob/main/Cetus%20Sui%20Audit%20Report%20by%20OtterSec.pdf
- Zellic: https://github.com/CetusProtocol/Audit

### Scallop
- Zellic, OtterSec, MoveBit audits: https://docs.scallop.io/protocol/auditing

### MoveBit Sample Reports
- Repository: https://github.com/movebit/Sampled-Audit-Reports/tree/main/reports

### OmniBTC AMM
- Report: https://movebit.xyz/file/Sui-AMM-swap-Contracts-Audit-Report.pdf

### Streamflow Finance
- Report: http://movebit.xyz/reports/Streamflow-Final-Audit-Report.pdf

---

## 5. Security Best Practices

### Arithmetic Safety
```move
// BAD: Direct multiplication
let result = amount * price;

// GOOD: Use u128 for intermediate calculations
let result = ((amount as u128) * (price as u128)) as u64;
```

### Access Control
```move
// BAD: No permission check
public fun withdraw_all(vault: &mut Vault) { ... }

// GOOD: Require admin capability
public fun withdraw_all(vault: &mut Vault, _admin: &AdminCap) { ... }
```

### Resource Safety
```move
// BAD: Resource may leak
public fun process(coin: Coin<SUI>) {
    if (condition) { return } // coin leaked!
    transfer::public_transfer(coin, recipient);
}

// GOOD: All paths handle resource
public fun process(coin: Coin<SUI>) {
    if (condition) {
        transfer::public_transfer(coin, sender);
        return
    }
    transfer::public_transfer(coin, recipient);
}
```

### Slippage Protection
```move
// BAD: No slippage check
public fun swap(pool: &mut Pool, coin_in: Coin<SUI>): Coin<USDC> { ... }

// GOOD: With min_amount_out
public fun swap(
    pool: &mut Pool,
    coin_in: Coin<SUI>,
    min_amount_out: u64
): Coin<USDC> {
    let out = calculate_output(...);
    assert!(coin::value(&out) >= min_amount_out, E_SLIPPAGE);
    out
}
```

---

## References

- SlowMist Audit Primer: https://github.com/slowmist/Sui-MOVE-Smart-Contract-Auditing-Primer
- MoveBit 2024 Review: https://www.movebit.xyz/blog/post/A-Deep-Dive-Analysis-A-2024-Comprehensive-Review-of-Technological-Innovations-and-Security-Events-in-the-Move-Ecosystem-20241204.html
- Sui Security: https://www.sui.io/security
- CTF Course: https://lets-ctf.vercel.app/
