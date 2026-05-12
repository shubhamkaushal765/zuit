//! Negative fixture for MAINT007-return-complexity.
//! Contains functions with fewer return statements than the threshold.

/// A simple function with few returns.
pub fn simple_function(x: i32) -> &'static str {
    if x < 0 {
        return "negative";
    }
    "non-negative"
}

/// Another simple function.
pub fn another_simple(value: bool) -> i32 {
    if value { 1 } else { 0 }
}
