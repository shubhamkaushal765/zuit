//! Positive fixture for DOC004-stale-doc.
//! Contains a function with rustdoc that references wrong parameter names.

/// Computes a result from two integers.
///
/// # Arguments
///
/// * `a` - the first input (WRONG: actual param is `x`)
/// * `b` - the second input (WRONG: actual param is `y`)
pub fn compute(x: i32, y: i32) -> i32 {
    x + y
}
