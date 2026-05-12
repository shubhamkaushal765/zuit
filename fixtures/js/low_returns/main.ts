/**
 * Negative fixture for MAINT007-return-complexity.
 * Contains functions with fewer return statements than the threshold.
 */

function simpleFunction(x: number): string {
    if (x < 0) {
        return "negative";
    }
    return "non-negative";
}

function anotherSimple(value: boolean): number {
    return value ? 1 : 0;
}
