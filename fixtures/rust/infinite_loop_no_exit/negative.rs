// MAINT010-infinite-loop-no-exit: negative fixture
// These loops should NOT be flagged.

fn loop_with_break(x: bool) {
    loop {
        if x {
            break;
        }
    }
}

fn loop_with_return() {
    loop {
        return;
    }
}

fn loop_with_panic() {
    loop {
        panic!("unexpected");
    }
}
