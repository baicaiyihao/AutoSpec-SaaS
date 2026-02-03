# Sui Prover Reference Knowledge Base

## [Module: Overview] Core Components
The **Sui Move Prover** is a tool for verifying the correctness of Move smart contracts on the Sui blockchain.
- **Core Engine:** It is based on the **Boogie** verification engine and the **Z3 SMT solver**.
- **The `prover` module:** A spec-only module that provides the building blocks for writing specifications.

---

## [Module: Spec Functions] Conditions & Assertions

### `requires` (Pre-conditions)
The `requires` function specifies conditions assumed to be true regarding the function arguments **before** execution.
```move
// Example: Input shares must not exceed total supply
requires(shares_in.value() <= pool.shares.supply_value());
```

### `ensures` (Post-conditions)
The `ensures` function specifies conditions that must hold true **after** the function execution completes (as an effect of the call).
```move
// Example: New shares * old balance <= Old shares * new balance
ensures(new_shares.mul(old_balance).lte(old_shares.mul(new_balance)));
```

### `asserts` (In-line Assertions)
The `asserts` function specifies conditions that must **always** hold at a specific point in the execution flow.
```move
asserts(shares_in.value() <= pool.shares.supply_value());
```

---

## [Module: State & Types] Macros and Conversions

### `old!` Macro
Refers to the state of an object or resource **before** the function call began.
```move
let old_pool = old!(pool);
```

### `to_int` (Unbounded Integer)
Converts a fixed-precision unsigned integer (e.g., `u64`) to an **unbounded integer**.
- **Usage:** Unbounded integers are only available while executing a specification.
```move
let x = 10u64.to_int();
```

### `to_real` (Arbitrary Precision Real)
Converts a fixed-precision integer to an **arbitrary-precision real number**.
- **Usage:** Useful for checking rounding direction. Real numbers are only available while executing a specification.
```move
let x = 10u64.to_real();
```

---

## [Module: Advanced State] Ghost Variables
**Ghost variables** are global variables used exclusively in specifications.

### Declaration
Use `ghost::declare_global` or `ghost::declare_global_mut`.
- **Arguments:** The declaration takes two type-level arguments: the **name** (often a spec-only struct) and the **type**.
```move
// Define a struct to serve as the name
public struct MyGhostVariableName {}

// Declare the ghost variable
ghost::declare_global_mut<MyGhostVariableName, bool>();
```

### Usage
Can be accessed in `requires`, `ensures`, and `asserts` functions.
```move
requires(ghost::global<MyGhostVariableName, _>() == true);
```

---

## [Module: Invariants] Loops & Objects

### Loop Invariants
Conditions that must hold for **all iterations** of a loop.
- **Requirement:** If a spec contains conditions over variables modified inside a loop, the invariant must be specified.
- **Syntax:** Call the `invariant!` macro **before** the loop.
```move
invariant!(|| {
    ensures(i <= n);
});
while (i < n) {
    i = i + 1;
}
```

### Object Invariants
Conditions that must hold for **all objects** of a given type.
- **Syntax:** Create a new function named `<type_name>_inv` annotated with `#[spec_only]`.
- **Signature:** Must take a single argument (reference to the object) and return `bool`.
```move
#[spec_only]
public fun MyType_inv(self: &MyType): bool {
    // Return true if invariant holds
    ...
}
```

---

## [Module: Attributes] Configuration & Visibility

### `#[spec]` (Function Specification)
Specifies that a function is a verification logic.
- **Context:** When placed on a function named `<function_name>_spec`.
- **Behavior:** The Prover uses this spec instead of the original function when verifying **callers** of `<function_name>`.
- **Requirements:**
    1. Name must be `<original>_spec` (otherwise it's treated as a scenario).
    2. Must have the same signature as the original.
    3. Usually calls the original function.

### `#[spec]` (Scenario)
Used to specify a scenario that can be checked by the Prover. There are no restrictions on the name/signature.

### `#[spec(prove)]`
Specifies that a function should be **verified** by the Move Prover.
- **Note:** A spec without `prove` will not be checked directly, but is used when proving other functions that call it.

### `#[spec(prove, focus)]`
Instructs the Prover to **only** attempt to prove this particular spec/scenario.
- **Usage:** Focus can be used on several specs simultaneously for targeted verification.

### `#[spec_only]`
Makes any annotated code (module, function, struct) visible **only to the Prover**.
- **Effect:** The code will not appear under regular compilation nor in test mode.