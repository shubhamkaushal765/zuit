//! A small, healthy Rust library.
//!
//! - No `unsafe` constructs.
//! - All public items are documented.
//! - Maximum cyclomatic complexity is 3 (well under the threshold of 10).

/// Returns the sum of two integers.
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

/// Returns the absolute value of an integer.
pub fn abs_val(x: i32) -> i32 {
    if x < 0 { -x } else { x }
}

/// Classifies a number as negative, zero, or positive.
pub fn classify(x: i32) -> &'static str {
    if x < 0 {
        "negative"
    } else if x == 0 {
        "zero"
    } else {
        "positive"
    }
}

/// A simple named counter.
pub struct Counter {
    /// The current count value.
    pub value: u32,
}

impl Counter {
    /// Creates a new counter starting at zero.
    pub fn new() -> Self {
        Self { value: 0 }
    }

    /// Increments the counter by one.
    pub fn increment(&mut self) {
        self.value += 1;
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}
