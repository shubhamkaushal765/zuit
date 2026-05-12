//! Negative fixture for TEST006-shared-mutable-state.
//!
//! Test function uses only local variables — no `static mut` or unsafe
//! mutation of shared state. No finding should be emitted.

#[cfg(test)]
mod tests {
    #[test]
    fn test_pure_local() {
        let local = 0;
        assert_eq!(local + 1, 1);
    }

    #[test]
    fn test_another_local() {
        let mut v = vec![1, 2, 3];
        v.push(4);
        assert_eq!(v.len(), 4);
    }
}
