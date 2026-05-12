/**
 * Negative fixture for TEST002-no-asserts.
 *
 * Contains a test function with an assertion — should NOT be flagged.
 */

/** Test function with an assertion — should not be flagged. */
function test_thing(): void {
  const x = 1;
  expect(x).toBe(1);
}
