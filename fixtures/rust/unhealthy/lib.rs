//! An unhealthy Rust library used as a positive fixture.
//!
//! Problems intentionally included:
//! - At least one `unsafe` block (triggers `SEC101-rust-unsafe`).
//! - A function with cyclomatic complexity ≥ 8 (triggers `MAINT001-cyclomatic`).
//! - A public function without a doc comment (triggers `DOC001-public-api-undoc`).
//! - A hardcoded AWS access key (triggers `SEC001-hardcoded-secret`).

use std::ptr;

/// Copies bytes from `src` to `dst` using a raw pointer dereference.
///
/// # Safety
///
/// Both `src` and `dst` must be valid, aligned, non-null pointers to at least
/// `n` bytes.  The regions must not overlap.
pub unsafe fn raw_copy(dst: *mut u8, src: *const u8, n: usize) {
    // SAFETY: caller guarantees validity and non-overlap.
    unsafe {
        ptr::copy_nonoverlapping(src, dst, n);
    }
}

/// A function with high cyclomatic complexity (≥ 8) to exercise the
/// `MAINT001-cyclomatic` analyzer.
pub fn complex_classify(x: i32, flag: bool, mode: u8) -> &'static str {
    if x < 0 {
        if flag {
            "negative-flagged"
        } else {
            "negative"
        }
    } else if x == 0 {
        "zero"
    } else if mode == 1 {
        if x > 100 {
            "large-mode1"
        } else {
            "small-mode1"
        }
    } else if mode == 2 {
        match x % 3 {
            0 => "div3-mode2",
            1 => "rem1-mode2",
            _ => "rem2-mode2",
        }
    } else if flag && x > 50 {
        "flagged-large"
    } else {
        "other"
    }
}

// Public function intentionally missing a doc comment (Phase 4 fixture reuse).
pub fn undocumented(input: &str) -> usize {
    input.len()
}

// Hardcoded AWS access key — triggers SEC001-hardcoded-secret (Phase 4 fixture).
pub fn aws_key() -> &'static str {
    "AKIAIOSFODNN7EXAMPLE"
}
