/** Deep nesting fixture for MAINT005. */

export function deeplyNested(x: number): number {
  if (x > 0) {
    if (x > 10) {
      if (x > 100) {
        if (x > 1000) {
          if (x > 10000) {
            return x * 2;
          }
        }
      }
    }
  }
  return x;
}
