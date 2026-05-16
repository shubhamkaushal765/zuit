// MAINT009-missing-default-case — positive fixture
// These match expressions should produce findings.

fn check_literal() {
    // Literal scrutinee, no wildcard arm — should fire.
    match 1 {
        1 => {}
        2 => {}
    }
}

fn check_local_var(status: i32) {
    // Lowercase path scrutinee, no wildcard arm — should fire.
    match status {
        0 => {}
        1 => {}
    }
}
