// Fixture: positive cases for MAINT013-empty-block (Rust)
// Each of the following should produce a finding.

fn check_empty_if(x: bool) {
    if x {}
}

fn check_empty_for() {
    for _i in 0..10 {}
}

fn check_empty_while(mut x: i32) {
    while x > 0 {}
}
