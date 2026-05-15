// Module with commented-out code that should trigger MAINT014.

export function calculate(x: number): number {
  // function oldCalculate(x: number, y: number) {
  //   const result = x * y;
  //   if (result > 100) {
  //     return result - 100;
  //   }
  //   return result;
  // }
  return x * x;
}
