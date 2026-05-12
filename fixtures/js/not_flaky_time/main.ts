/**
 * Negative fixture for TEST004-flaky-time.
 * Contains test functions with no time/random tokens.
 */

function test_pure_logic(): void {
    const result = 1 + 1;
    expect(result).toBe(2);
}

function test_array_length(): void {
    const items = [1, 2, 3];
    expect(items.length).toBe(3);
}
