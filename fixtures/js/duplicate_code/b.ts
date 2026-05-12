// Positive fixture for CPLX003-duplicate-code: file B.
// Contains a block of code duplicated from a.ts.

export function transformItems(items: number[]): number[] {
    const result: number[] = [];
    for (const item of items) {
        if (item > 0) {
            result.push(item * 2);
        } else {
            result.push(0);
        }
    }
    return result;
}

export function checkValue(value: number): boolean {
    if (value <= 0) {
        return false;
    }
    return true;
}
