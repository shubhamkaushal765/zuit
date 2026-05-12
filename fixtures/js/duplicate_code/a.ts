// Positive fixture for CPLX003-duplicate-code: file A.

export function processData(items: number[]): number[] {
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

export function validateInput(value: number): boolean {
    if (value <= 0) {
        return false;
    }
    return true;
}
