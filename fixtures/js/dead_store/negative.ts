// MAINT012-dead-store negative fixture

function readAfterWrite() {
    let x = 1;
    return x;   // x is read — not dead
}

function underscorePrefix() {
    let _x = 1;
    return null;   // skipped — leading underscore
}

function loopVar(arr: number[]) {
    for (let x of arr) {
        // loop var — skipped
    }
}

function destructure(obj: { a: number; b: number }) {
    const { a, b } = obj;
    return a + b;   // both a and b are used
}
