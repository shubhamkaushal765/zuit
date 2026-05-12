//! Positive fixture for TEST004-flaky-time.
//! Contains test functions referencing time/random tokens.

#[cfg(test)]
mod tests {
    use std::time::{Instant, SystemTime};

    #[test]
    fn test_with_instant() {
        let start = Instant::now();
        let _ = start;
        assert!(true);
    }

    #[test]
    fn test_with_system_time() {
        let now = SystemTime::now();
        let _ = now;
        assert!(true);
    }
}
