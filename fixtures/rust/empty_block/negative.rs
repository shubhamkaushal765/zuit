// Fixture: negative cases for MAINT013-empty-block (Rust)
// None of the following should produce a finding.

fn check_nonempty_if(x: bool) {
    if x {
        let _ = 1;
    }
}

fn check_nonempty_for() {
    for i in 0..10 {
        let _ = i;
    }
}

fn check_nonempty_while(mut x: i32) {
    while x > 0 {
        x -= 1;
    }
}

// Empty loop is NOT flagged by MAINT013 (covered by MAINT010).
fn empty_loop_not_flagged() {
    loop {}
}

// Empty function body is NOT flagged (intentional stub).
fn stub() {}
