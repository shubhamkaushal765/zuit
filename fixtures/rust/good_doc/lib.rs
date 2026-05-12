//! Negative fixture for DOC003-empty-doc.
//! Contains functions with proper doc comments.

/// Adds two integers together and returns their sum.
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

/// Returns whether the given number is even.
pub fn is_even(n: i32) -> bool {
    n % 2 == 0
}
