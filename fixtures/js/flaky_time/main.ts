/**
 * Positive fixture for TEST004-flaky-time.
 * Contains test functions with time/random tokens.
 */

function test_with_settimeout(): void {
    setTimeout(() => {}, 100);
    expect(true).toBe(true);
}

function test_with_date_now(): void {
    const ts = Date.now();
    expect(ts).toBeGreaterThan(0);
}

function test_with_math_random(): void {
    const val = Math.random();
    expect(val).toBeGreaterThanOrEqual(0);
}
