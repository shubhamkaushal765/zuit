/**
 * Positive fixture for MAINT007-return-complexity.
 * Contains a function with many return statements exceeding the threshold.
 */

function complexReturns(x: number, y: number, z: number): string {
    if (x < 0) {
        return "negative x";
    }
    if (y < 0) {
        return "negative y";
    }
    if (z < 0) {
        return "negative z";
    }
    if (x === y) {
        return "x equals y";
    }
    if (y === z) {
        return "y equals z";
    }
    return "default";
}
