//! Positive fixture for TEST003-skipped.
//!
//! Contains two different skip markers — both should produce findings.

#[cfg(test)]
mod tests {
    /// Test skipped with plain `#[ignore]`.
    #[test]
    #[ignore]
    fn test_plain_ignore() {
        assert_eq!(1, 1);
    }

    /// Test skipped with `#[ignore = "reason"]`.
    #[test]
    #[ignore = "not yet implemented"]
    fn test_ignore_with_reason() {
        assert_eq!(2, 2);
    }
}
