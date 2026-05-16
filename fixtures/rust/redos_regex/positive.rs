// Positive fixture for SEC014-redos-regex — patterns that cause catastrophic backtracking.
use regex::Regex;

fn catastrophic_patterns() {
    // Nested repetition: (a+)+ is the canonical ReDoS pattern.
    let _r1 = Regex::new("(a+)+").unwrap();

    // Nested repetition: (.*)*
    let _r2 = Regex::new("(.*)*").unwrap();
}
