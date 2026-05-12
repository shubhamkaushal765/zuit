//! Deep nesting fixture for MAINT005.

/// A function with nesting depth 5.
pub fn deeply_nested(x: i32) -> i32 {
    if x > 0 {
        if x > 10 {
            if x > 100 {
                if x > 1000 {
                    if x > 10000 {
                        return x * 2;
                    }
                }
            }
        }
    }
    x
}
