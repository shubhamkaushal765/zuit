//! Negative fixture for DOC004-stale-doc.
//! Contains a function with rustdoc that references correct parameter names.

/// Computes a result from two integers.
///
/// # Arguments
///
/// * `x` - the first input
/// * `y` - the second input
pub fn compute(x: i32, y: i32) -> i32 {
    x + y
}
