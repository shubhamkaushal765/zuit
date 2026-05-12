/**
 * Negative fixture for TEST005-assert-count.
 * Contains a test function with fewer assertions than the threshold.
 */

function test_with_few_assertions(): void {
    expect(1).toBe(1);
    expect(2).toBe(2);
    expect(3).toBe(3);
}
