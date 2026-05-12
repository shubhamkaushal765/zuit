/**
 * Positive fixture for TEST002-no-asserts.
 *
 * Contains a test function but no assertion of any kind.
 */

/** Test function with no assertion — will be flagged. */
function test_thing(): void {
  const x = 1;
  const _y = x + 1;
}
