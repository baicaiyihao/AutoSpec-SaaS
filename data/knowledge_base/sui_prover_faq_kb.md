# Sui Prover FAQ Knowledge Base

## [Module: Troubleshooting] Composition & Verification Logic

### Spec Composition
**Question:** How do specs compose when verifying multiple functions?
**Answer:** The Move Prover uses a modular verification approach.
- If function `foo` calls `bar`, and `bar` has a spec `bar_spec`, the Prover uses `bar_spec` (not the implementation of `bar`) to verify `foo`.
- **`#[spec(prove)]`**: Instructs the Prover to verify this spec itself.
- **Without `prove`**: The spec is used only to verify *other* functions that call it, but is not verified itself.

### Spec Focus
**Question:** How do I focus the prover on a particular spec?
**Answer:** Use the `focus` attribute: `#[spec(prove, focus)]`.
- **Effect:** The Prover will *only* attempt to prove specs marked with `focus`, ignoring others.
- **Warning:** Do not commit this to the repository, as it disables full-project verification.

### Avoiding Spec Dependency (Opaque Specs)
**Question:** How do I force the prover to use the implementation instead of the spec when verifying callers?
**Answer:** By default, the Prover uses a called function's spec (opaque behavior). To include the *implementation* in the proof, annotate the spec with `no_opaque`.
```move
#[spec(prove, no_opaque)]
fun foo_spec(...) { ... }
```

---

## [Module: Syntax & Structure] Scenarios & Targets

### Defining Scenarios
**Question:** How do I specify a verification scenario instead of a function spec?
**Answer:** Use the `#[spec]` attribute on a function that:
1. Does **not** end in `_spec`.
2. Does **not** have a `target` attribute.
- **Note:** Scenarios do not need to call a specific target function.

### Cross-Module Specs (Target Attribute)
**Question:** How do I write a spec for a function in a different module?
**Answer:** Use the `target` attribute to explicitly link the spec to a function.
- **Convention:** `<name>_spec` automatically targets `<name>` in the same module.
- **Cross-module syntax:**
```move
module 0x43::my_spec_module {
    #[spec(prove, target = 0x42::target_module::target_func)]
    fun my_custom_spec_name(...) { ... }
}
```

### Accessing Private Members
**Question:** How do I access private members/functions in specs (especially for cross-module specs)?
**Answer:** Specs cannot access private members directly.
- **Solution:** Use `#[spec_only]` to define public getter/accessor functions.
- **Benefit:** These helpers are visible only to the Prover and do not affect the compiled bytecode.

---

## [Module: Aborts & Errors] Assertions & Overflows

### Specifying Abort Conditions
**Question:** How do I specify when a transaction should abort?
**Answer:** A spec must comprehensively list all conditions that cause an abort (e.g., `assert!` failures, overflows).
- **Tool:** Use the `asserts` function.
```move
// Specifying that foo aborts if x >= y
asserts(x < y); 
```

### Specifying Overflow Aborts
**Question:** How do I handle arithmetic overflows in specs?
**Answer:** You must explicitly assert that operations do not exceed type limits.
```move
// Specifying abort on u64 overflow
asserts((x as u128) + (y as u128) <= u64::max_value!() as u128);
```

### Ignoring Aborts
**Question:** How do I verify logic without specifying every abort condition?
**Answer:** Use the `ignore_abort` annotation.
- **Syntax:** `#[spec(prove, ignore_abort)]`
- **Effect:** The Prover will verify the `ensures` properties assuming the transaction succeeds, ignoring abort scenarios.

---

## [Module: Common Errors] Compilation Issues

### Compilation Errors with Specs
**Question:** Why do I get compile errors when adding specs?
**Answer:** Current Move Prover integration may conflict with standard compilation pipelines.
- **Workaround:** Create a **separate package** specifically for proofs and use the `target` mechanism (see Cross-Module Specs) to verify your main code.