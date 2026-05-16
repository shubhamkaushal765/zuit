// MAINT010-infinite-loop-no-exit: positive fixture
// These loops should be flagged — they have no break, return, or panic.

fn spin() {
    let mut x = 0i32;
    loop {
        x += 1;
        let _ = x;
    }
}

fn call_in_loop() {
    loop {
        let _ = do_work();
    }
}

fn do_work() -> i32 {
    42
}
