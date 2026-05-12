/**
 * Cognitive-complexity fixture for JavaScript/TypeScript.
 *
 * Contains a function with cognitive complexity > 15 to exercise the
 * MAINT002-cognitive analyzer positive case.
 */

/**
 * A deeply-nested function designed to exceed cognitive complexity 15.
 *
 * Cognitive complexity (Sonar variant):
 * - if (a < 0) at depth 0: +1; consequent at depth 1
 *   - if (b < 0) at depth 1: +2; consequent at depth 2
 *     - if (c < 0) at depth 2: +3; consequent at depth 3
 *       - if (d < 0) at depth 3: +4; consequent at depth 4
 *         - if (e < 0) at depth 4: +5
 *         - else if (e > 10) at depth 4: +5
 *       - else if (d > 10) at depth 3: +4
 *     - else if (c > 10) at depth 2: +3
 *   - else if (b > 10) at depth 1: +2
 * - else if (a > 10) at depth 0: +1
 * Total: 1+2+3+4+5+5+4+3+2+1 = 30
 */
export function highCognitive(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number,
): string {
  if (a < 0) {
    if (b < 0) {
      if (c < 0) {
        if (d < 0) {
          if (e < 0) {
            return "all-negative";
          } else if (e > 10) {
            return "e-large";
          } else {
            return "e-mid";
          }
        } else if (d > 10) {
          return "d-large";
        } else {
          return "d-mid";
        }
      } else if (c > 10) {
        return "c-large";
      } else {
        return "c-mid";
      }
    } else if (b > 10) {
      return "b-large";
    } else {
      return "b-mid";
    }
  } else if (a > 10) {
    return "a-large";
  } else {
    return "a-mid";
  }
}
