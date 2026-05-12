// SEC002-eval-sink positive fixture (TypeScript)
// Every expression here should trigger at least one finding.

// 1. eval with TypeScript type annotation on the binding
let x: number = eval("1");

// 2. new Function in a typed context
const compute: () => number = new Function("return 42") as () => number;

// 3. setTimeout with a string arg
function scheduleUnsafe(code: string): void {
    setTimeout(code, 0);
}
