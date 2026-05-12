/**
 * Negative fixture for DOC003-empty-doc.
 * Contains functions with proper doc comments.
 */

/**
 * Adds two numbers together and returns their sum.
 */
export function add(a: number, b: number): number {
    return a + b;
}

/**
 * Returns whether the given number is even.
 */
export function isEven(n: number): boolean {
    return n % 2 === 0;
}
