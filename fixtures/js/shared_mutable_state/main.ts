/**
 * Positive fixture for TEST006-shared-mutable-state.
 *
 * Module-level `cache` and `requestCount` are mutated inside test functions
 * with no beforeEach/afterEach cleanup — flagged.
 */

let cache: Record<string, number> = {};
let requestCount = 0;

function test_mutates_cache(): void {
    cache["foo"] = 1;
    expect(cache["foo"]).toBe(1);
}

function test_increments_request_count(): void {
    requestCount += 1;
    expect(requestCount).toBeGreaterThan(0);
}
