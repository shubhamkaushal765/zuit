// MAINT012-dead-store positive fixture

fn dead_store_never_read() {
    let unused = 42;  // dead: never read, no _prefix
}

fn dead_store_overwritten() {
    let result = compute();  // dead: never read before function ends
}

fn compute() -> i32 {
    42
}
