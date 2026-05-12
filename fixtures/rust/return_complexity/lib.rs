//! Positive fixture for MAINT007-return-complexity.
//! Contains a function with many return statements exceeding the threshold.

/// A function with too many return paths.
pub fn complex_returns(x: i32, y: i32, z: i32) -> &'static str {
    if x < 0 {
        return "negative x";
    }
    if y < 0 {
        return "negative y";
    }
    if z < 0 {
        return "negative z";
    }
    if x == y {
        return "x equals y";
    }
    if y == z {
        return "y equals z";
    }
    "default"
}
