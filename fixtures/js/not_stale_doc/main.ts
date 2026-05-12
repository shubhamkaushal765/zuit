/**
 * Negative fixture for DOC004-stale-doc.
 * Contains a function whose JSDoc param names match the actual parameters.
 */

/**
 * Adds two numbers.
 * @param a - the first operand
 * @param b - the second operand
 * @returns the sum
 */
export function add(a: number, b: number): number {
    return a + b;
}
