//! Negative fixture for TEST004-flaky-time.
//! Contains test functions with no time/random tokens.

#[cfg(test)]
mod tests {
    #[test]
    fn test_pure_logic() {
        let result = 1 + 1;
        assert_eq!(result, 2);
    }

    #[test]
    fn test_another_pure() {
        let items = vec![1, 2, 3];
        assert_eq!(items.len(), 3);
    }
}
