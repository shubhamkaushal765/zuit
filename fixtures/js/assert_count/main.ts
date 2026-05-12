/**
 * Positive fixture for TEST005-assert-count.
 * Contains a test function with more than 10 assertions.
 */

function test_with_too_many_assertions(): void {
    expect(1).toBe(1);
    expect(2).toBe(2);
    expect(3).toBe(3);
    expect(4).toBe(4);
    expect(5).toBe(5);
    expect(6).toBe(6);
    expect(7).toBe(7);
    expect(8).toBe(8);
    expect(9).toBe(9);
    expect(10).toBe(10);
    expect(11).toBe(11);
}
