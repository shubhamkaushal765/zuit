// Negative fixture for SEC014-redos-regex — safe regex patterns.
use regex::Regex;

fn safe_patterns() {
    // Simple character class repetition.
    let _r1 = Regex::new("[a-z]+").unwrap();

    // Bounded repetition.
    let _r2 = Regex::new(r"\d{1,5}").unwrap();

    // Anchored literal.
    let _r3 = Regex::new("^abc$").unwrap();
}
