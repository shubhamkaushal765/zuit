//! Positive fixture for TEST006-shared-mutable-state.
//!
//! Contains a `static mut` variable that is mutated inside a `#[test]`
//! function without any Drop-based fixture or setup teardown.

#![allow(unsafe_code)]

static mut TOTAL: i32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutates_static() {
        // Mutates module-level static mut — flagged.
        unsafe {
            TOTAL += 1;
        }
        unsafe {
            assert!(TOTAL > 0);
        }
    }
}
