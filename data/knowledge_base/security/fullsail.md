
A-8
Optimization in Tick Math Price Calculation
New
advisory
The get_tick_at_sqrt_price function in the tick_math module performs multiple bit operations to calculate tick indices, with each step introducing new local variables instead of reusing existing ones. It uses decimal values for bit manipulation constants with poor readability.
Reuse mutable msb_bits and msb_shifted variables to reduce allocations.

Replace decimal constants with hexadecimal bit masks for better readability (e.g., replace 4294967296 with 0x100_000_000)
remediated
github.com/LFB…157211

L-3
Total Volume Overflow Risk in Volume Tracking
New
low
The stats module uses u64 type for total_volume tracking, which presents a potential overflow risk for active pools. While the add_total_volume_internal function is not currently used during swaps, its future implementation could lead to transaction reverts due to overflow, effectively blocking swap operations in high-volume pools.
Use u256 type for volume tracking to significantly increase the maximum trackable volume. Also consider implementing a denominator system (e.g., track volume in larger units) to further increase the maximum value.

Add an overflow strategy, for example one of the following:
• Emit an event and reset volume to zero when overflow is detected
• Implement periodic resets (e.g., daily/weekly volume tracking)
• Store historical periods in a separate accumulator
remediated
github.com/LFB…157211

M-8
Type Order Validation Bypass in Pool Key Generation
New
medium
The new_pool_key function in the factory module contains a critical flaw in its type order validation logic. The issue occurs because the function modifies the comparison buffer (bytes_a) during processing but uses the modified length for validation checks, rather than the original length.

The function appends bytes_b from the second type name to bytes_a during comparison in the while loop. When the second type name extends the first one (like "A" vs "A0"), the comparison flag swapped remains false as all common bytes match. The subsequent length validation check becomes meaningless because it compares lengths after bytes_b were already appended to bytes_a. This allows creating pools with the same types using different type orderings, breaking the fundamental protocol invariant that each unique type pair should have a unique pool key and pool.

// Example 
public struct A {}    // type_name = "0x123::module::A"
public struct A0 {}   // type_name = "0x123::module::A0"
// Both calls succeed when one should fail
let key1 = new_pool_key<A, A0>(tick_spacing);
let key2 = new_pool_key<A0, A>(tick_spacing);
Use a separate result variable for types concatenation, or perform concatenation after all validation checks are completed, which separates the type ordering validation logic from the key generation logic. This ensures that the original type names remain unmodified during comparison.
remediated
github.com/LFB…f3c372

M-3
Missing Validation for tick_spacing in add_fee_tier
New
medium
The add_fee_tier function in config module does not validate the tick_spacing parameter, allowing callers to set arbitrarily large values.

A very large tick_spacing significantly reduces tick density across the price range. In concentrated liquidity models like CLMM, this results in extremely coarse or even absent liquidity across wide price intervals, leading to inefficient pricing and degraded trading performance.
Enforce a reasonable upper bound for tick_spacing in add_fee_tier to prevent accidents and ensure efficient tick layout.
remediated
github.com/LFB…157211
L-7
Version Validation in update_package_version
New
low
The update_package_version function in the config module allows setting any value, including older or identical versions. This can lead to unintended downgrades or redundant updates, potentially causing compatibility or versioning issues.

Additionally, the lack of a public getter for package_version makes it difficult to verify the current version for external callers or before performing updates.
Modify update_package_version to allow only strictly increasing values (i.e., new_version > current_version) to prevent accidental or malicious downgrades.

Provide a public read-only function to access the current package_version, enabling safe pre-checks by external callers.

Consider using constants instead of literals during initialization and checks.
remediated
github.com/LFB…157211
L-5
Overlapping Error Codes
New
low
Multiple modules define error codes with overlapping numeric values, leading to potential ambiguity. Error codes are typically defined sequentially, starting from 0 or 1. 

This can lead to ambiguous error reporting and make debugging or on-chain analysis more difficult, as the origin of the error may be unclear.
Refactor the codebase so that all used error codes have unique numeric values. A common practice is to centralize error code management in a single module or shared file to prevent duplication across modules.
remediated
github.com/LFB…157211
L-1
Missing checked_package_version Enforcement in Multiple Functions
New
low
Several functions across the factory and pool modules are missing calls to checked_package_version, which is used to ensure compatibility and enforce upgrade safety in systems with upgradeable packages.

Omitting this check allows these functions to be called even when the package version is outdated or mismatched, potentially leading to unintended behavior, security vulnerabilities, or inconsistent state if the logic is changed in newer versions.

Affected Functions:
• factory module
    ◦ receive_ref_fee
• pool module
    ◦ mark_position_staked
    ◦ mark_position_unstaked
    ◦ collect_fullsail_distribution_gauger_fees
    ◦ update_fullsail_distribution_growth_global
    ◦ init_fullsail_distribution_gauge
    ◦ stake_in_fullsail_distribution
    ◦ unstake_from_fullsail_distribution
    ◦ sync_fullsail_distribution_reward
Include a call to checked_package_version at the start of each affected function to ensure they only execute when the package version is verified to be current.
acknowledged
L-4
Incorrect Old Values Emitted in Update Events
New
low
Several configuration and pool update functions emit events that include both the old and new values of updated parameters. However, the old values emitted are incorrect because the new values are written to storage before the event is emitted. As a result, both old and new values in the event payload reflect the new state, misleading off-chain consumers and compromising auditability.

Affected functions:
• config module:
    ◦ update_package_version
    ◦ update_protocol_fee_rate
    ◦ update_fee_tier
    ◦ update_unstaked_liquidity_fee_rate
• pool module:
    ◦ update_fee_rate
    ◦ update_unstaked_liquidity_fee_rate

Additionally, some of these functions include an assertion new ≠ old to prevent redundant updates, while others do not.
Store the current value in a temporary variable before updating storage. Use this saved value as the old field in the emitted event. Alternatively, emit the event before updating the value in storage.

Consider applying a consistent pattern across all update functions by asserting that new_value ≠ old_value before proceeding with the update.
remediated
github.com/LFB…157211
A-1
Tick Cleanup in update_by_liquidity When Liquidity Reaches Zero
1
New
advisory
The update_by_liquidity function in tick module skips updating the tick’s state entirely if (updated_liquidity_gross == 0), under the assumption that an external function will subsequently remove the tick from the list. This approach breaks encapsulation by requiring external logic.

Relying on external cleanup introduces a risk: if future changes to code paths forget to remove the tick or defer its removal, stale ticks may remain in the list with outdated or incorrect state.
To maintain encapsulation and reduce the chance of misuse, update_by_liquidity should itself handle tick cleanup when liquidity drops to zero.
acknowledged
L-12
fetch_ticks Behavior Deviates from Other Fetch Functions
New
low
The fetch_ticks function in the tick module behaves inconsistently compared to other fetch_* functions.

It skips the tick at tick_indexes[0] itself, starting from the next tick(include parameter in find_next function is set to false). This differs from other fetch functions, which typically include the starting element, and can lead to unexpected omissions or developer confusion.

Additionally, fetch_ticks function does not check the limit in the while loop condition, only inside the loop body. As a result, if the limit is set to zero, the loop still runs and continues fetching until the end of the list, since the break condition if (new_count == limit) is never satisfied. While a limit of zero could be interpreted as "fetch all", this behavior is not aligned with the comments or how limits are handled in similar functions.
Consider modifying fetch_ticks to include the tick at tick_indexes[0] for consistency with other fetch_* functions, which typically include the starting element. To handle sentinel ticks appropriately, you can extract the relevant logic from first_score_for_swap into a shared helper function.

Also move the count limit check into the while loop condition to prevent any iterations when limit == 0, aligning with how other fetch_* functions handle limits. Remove the redundant new_count variable and increment count directly to streamline the logic.
remediated
github.com/LFB…157211
H-1
Incorrect Tick Initialization Logic for Upper Tick (invalid)
1
New
The update_by_liquidity function in the tick module uses a single is_lower_initialized flag and applies the same initialization logic for both lower and upper ticks. This behavior is likely a consequence of an initial naming issue. As a result, the function does not correctly distinguish the conditions under which global growth values should be applied for each tick boundary.

Specifically, for lower ticks, global growth values should be used when current_tick >= tick.index, whereas for upper ticks, they should be used when current_tick < tick.index. Applying the same logic to both cases results in incorrect initialization of growth values for upper ticks.

This flaw may lead to inconsistencies in fee accounting, reward distribution, and other state updates dependent on accurate tick growth tracking.
To align with the correct tick initialization logic, the is_lower_initialized flag should be renamed to a more general is_tick_initialized, and the logic should be explicitly split using the existing is_upper flag to distinguish between upper and lower ticks:
• for lower ticks use global values if current_tick >= tick.index, otherwise use zero.
• for upper ticks use global values if current_tick < tick.index, otherwise use zero.
invalid
