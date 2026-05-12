//! Positive fixture for TEST002-no-asserts.
//!
//! Contains a test function but no assertion of any kind.

/// Test function with no assertion — will be flagged.
#[cfg(test)]
mod tests {
    #[test]
    fn test_thing() {
        let _ = 1;
    }
}
