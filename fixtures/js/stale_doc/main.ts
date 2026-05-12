/**
 * Positive fixture for DOC004-stale-doc.
 * Contains a function whose JSDoc references a parameter name that does not
 * match the actual parameter in the signature.
 */

/**
 * Adds two numbers.
 * @param foo - the first operand (WRONG name: actual param is `a`)
 * @param bar - the second operand (WRONG name: actual param is `b`)
 * @returns the sum
 */
export function add(a: number, b: number): number {
    return a + b;
}
