//! Cognitive-complexity fixture for Rust.
//!
//! Contains a function with cognitive complexity > 15 to exercise the
//! `MAINT002-cognitive` analyzer positive case.

/// A deeply-nested function designed to exceed cognitive complexity 15.
///
/// Cognitive complexity (Sonar variant):
/// - `if a < 0` at depth 0: +1
///   - `if b < 0` at depth 1: +2
///     - `if c < 0` at depth 2: +3
///       - `if d < 0` at depth 3: +4
///         - `if e < 0` at depth 4: +5
///       - `else if d > 10` continues at depth 3: +4
///     - `else if c > 10` at depth 2: +3
///   - `else if b > 10` at depth 1: +2
/// - `else if a > 10` at depth 0: +1
/// Total: 1+2+3+4+5+4+3+2+1 = 25 (well above threshold 15)
pub fn high_cognitive(a: i32, b: i32, c: i32, d: i32, e: i32) -> &'static str {
    if a < 0 {
        if b < 0 {
            if c < 0 {
                if d < 0 {
                    if e < 0 {
                        "all-negative"
                    } else {
                        "e-non-negative"
                    }
                } else if d > 10 {
                    "d-large"
                } else {
                    "d-mid"
                }
            } else if c > 10 {
                "c-large"
            } else {
                "c-mid"
            }
        } else if b > 10 {
            "b-large"
        } else {
            "b-mid"
        }
    } else if a > 10 {
        "a-large"
    } else {
        "a-mid"
    }
}
