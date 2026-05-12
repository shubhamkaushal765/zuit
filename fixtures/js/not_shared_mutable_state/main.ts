/**
 * Negative fixture for TEST006-shared-mutable-state.
 *
 * Module-level `cache` exists but beforeEach resets it before every test —
 * the analyzer suppresses all findings because a lifecycle hook is present.
 */

let cache: Record<string, number> = {};

beforeEach(() => {
    cache = {};
});

afterEach(() => {
    cache = {};
});

function test_cache_mutation_safe(): void {
    cache["key"] = 42;
    expect(cache["key"]).toBe(42);
}
