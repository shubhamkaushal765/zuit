/**
 * Unhealthy module — contains security issues and high complexity.
 */

// Hardcoded AWS access key — triggers SEC001-hardcoded-secret.
export const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

export function complexLogic(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number,
): string {
  if (a > 0) {
    if (b > 0) {
      if (c > 0) {
        if (d > 0) {
          if (e > 0) {
            return "all positive";
          } else if (e < -10) {
            return "e very negative";
          } else {
            return "e small negative";
          }
        } else if (d < 0) {
          return "d negative c positive";
        }
      } else if (c < 0) {
        return "c negative b positive";
      }
    } else if (b < 0) {
      return "b negative a positive";
    }
  } else if (a < 0) {
    return "a negative";
  }
  return "default";
}

export function undocumentedPublicFunction(x: number, y: number): number {
  return x + y;
}
