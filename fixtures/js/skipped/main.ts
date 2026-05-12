/**
 * Positive fixture for TEST003-skipped.
 *
 * Contains two different skip markers — both should produce findings.
 */

/** Skipped test via it.skip. */
it.skip("should do something", () => {
  expect(true).toBe(true);
});

/** Skipped test via xit. */
xit("should do something else", () => {
  expect(true).toBe(true);
});
