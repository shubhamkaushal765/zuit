//! Negative fixture for TEST002-no-asserts.
//!
//! Contains a test function with an assertion — should NOT be flagged.

/// Test function with an assertion — should not be flagged.
#[cfg(test)]
mod tests {
    #[test]
    fn test_thing() {
        let x = 1;
        assert_eq!(x, 1);
    }
}
