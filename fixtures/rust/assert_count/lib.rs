//! Positive fixture for TEST005-assert-count.
//! Contains a test function with more than 10 assertions.

#[cfg(test)]
mod tests {
    #[test]
    fn test_with_too_many_assertions() {
        assert_eq!(1, 1);
        assert_eq!(2, 2);
        assert_eq!(3, 3);
        assert_eq!(4, 4);
        assert_eq!(5, 5);
        assert_eq!(6, 6);
        assert_eq!(7, 7);
        assert_eq!(8, 8);
        assert_eq!(9, 9);
        assert_eq!(10, 10);
        assert_eq!(11, 11);
    }
}
