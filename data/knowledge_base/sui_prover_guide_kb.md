# Sui Prover Knowledge Base

## [Module: Overview] Tool Description
The **Sui Prover** is a formal verification tool designed to verify the correctness of Move smart contracts on the Sui blockchain.
- **Core Engine:** It is built upon the **Boogie** verification engine and the **Z3 SMT solver**.
- **Purpose:** It mathematically proves that a smart contract satisfies its written specifications (specs).

---

## [Module: Installation] Setup & Configuration

### Installation Command
To install the Sui Prover via Homebrew:
```bash
brew install asymptotic-code/sui-prover/sui-prover
```

### Dependency Configuration (`Move.toml`)
The Sui Prover requires using **implicit dependencies** in `Move.toml`. You must remove direct dependency definitions for `Sui` and `MoveStdlib`.

**Action Required:**
Delete lines similar to this from your `Move.toml`:
```toml
Sui = { git = "[https://github.com/MystenLabs/sui.git](https://github.com/MystenLabs/sui.git)", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet", override = true }
```
*Note: If you must reference Sui directly, place your specifications in a separate package.*

---

## [Module: Concepts] Specification Structure
To verify a function, you must write a corresponding specification function annotated with `#[spec(prove)]`.

### Anatomy of a Spec Function
```move
#[spec(prove)]
fun target_function_spec<T>(arg1: Type, arg2: Type): ReturnType {
    // 1. Pre-conditions (Assumptions)
    requires(arg1 > 0);

    // 2. State snapshot (optional)
    let old_state = old!(global_resource);

    // 3. Call the target function
    let result = target_function(arg1, arg2);

    // 4. Post-conditions (Assertions)
    ensures(result == old_state + 1);

    result
}
```

### Key Keywords & Operators
| Keyword | Description | Context |
| :--- | :--- | :--- |
| `#[spec(prove)]` | Marks a function as a verification target for Sui Prover. | Function Attribute |
| `requires(condition)` | Defines a **pre-condition** that is assumed to be true before execution. | Function Body |
| `ensures(condition)` | Defines a **post-condition** that must be true after execution. | Function Body |
| `old!(variable)` | Captures the state of a variable **before** the function execution. | Function Body |
| `.to_int()` | Converts a number to an **unbounded integer** (spec-only type) to avoid overflow during verification math. | Spec Logic |

---

## [Module: Code Example] Liquidity Pool (LP) Withdraw
**Context:** Verifying that withdrawing from a pool does not decrease the share price.

### 1. Target Function (Move Source)
```move
module amm::simple_lp;
use sui::balance::{Balance, Supply, zero};

public struct LP<phantom T> has drop {}

public struct Pool<phantom T> has store {
    balance: Balance<T>,
    shares: Supply<LP<T>>,
}

public fun withdraw<T>(pool: &mut Pool<T>, shares_in: Balance<LP<T>>): Balance<T> {
    if (shares_in.value() == 0) {
        shares_in.destroy_zero();
        return zero()
    };
    let balance = pool.balance.value();
    let shares = pool.shares.supply_value();
    
    // Logic to calculate withdrawal amount
    let balance_to_withdraw = (((shares_in.value() as u128) * (balance as u128)) / (shares as u128)) as u64;

    pool.shares.decrease_supply(shares_in);
    pool.balance.split(balance_to_withdraw)
}
```

### 2. Verification Spec (Formal Proof)
```move
#[spec(prove)]
fun withdraw_spec<T>(pool: &mut Pool<T>, shares_in: Balance<LP<T>>): Balance<T> {
    // Assumption: Cannot withdraw more shares than exist
    requires(shares_in.value() <= pool.shares.supply_value());

    // Snapshot old state
    let old_pool = old!(pool);

    // Execute function
    let result = withdraw(pool, shares_in);

    // Convert to unbounded integers for safe math
    let old_balance = old_pool.balance.value().to_int();
    let new_balance = pool.balance.value().to_int();
    let old_shares = old_pool.shares.supply_value().to_int();
    let new_shares = pool.shares.supply_value().to_int();

    // Assertion: Share price logic (new_shares * old_balance <= old_shares * new_balance)
    ensures(new_shares.mul(old_balance).lte(old_shares.mul(new_balance)));

    result
}
```

---

## [Module: Advanced] Ghost Variables
**Ghost Variables** are global variables used *only* in specifications to track state or pass information (e.g., verifying event emissions).

### Syntax
- **Import:** `use prover::ghost::{declare_global, global};`
- **Declaration:** `declare_global<TypeTag, ValueType>();`
- **Access:** `*global<TypeTag, ValueType>()`

### Example Usage: Verifying Event Emission
**Scenario:** Verify that `LargeWithdrawEvent` is emitted when withdrawal amount > 10,000.

1.  **In Source Code:**
    ```move
    fun emit_large_withdraw_event() {
        event::emit(LargeWithdrawEvent { });
        // Update ghost variable state implicitly via requires (or explicit update in spec context)
        requires(*global<LargeWithdrawEvent, bool>()); 
    }
    ```

2.  **In Spec Code:**
    ```move
    #[spec(prove)]
    fun withdraw_spec(...) {
        // Declare the ghost variable
        declare_global<LargeWithdrawEvent, bool>();
        
        // ... logic ...

        // Verification: If amount > threshold, assert the ghost variable is true
        if (shares_in_value >= LARGE_WITHDRAW_AMOUNT) {
            ensures(*global<LargeWithdrawEvent, bool>());
        };
    }
    ```