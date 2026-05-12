//! Negative fixture for TEST005-assert-count.
//! Contains a test function with fewer assertions than the threshold.

#[cfg(test)]
mod tests {
    #[test]
    fn test_with_few_assertions() {
        assert_eq!(1, 1);
        assert_eq!(2, 2);
        assert_eq!(3, 3);
    }
}
