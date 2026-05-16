// MAINT012-dead-store negative fixture

fn read_after_write() {
    let x = 1;
    let _ = x + 1;  // x is read — not dead
}

fn underscore_prefix() {
    let _x = 1;   // leading underscore — skipped
}

fn mut_binding() {
    let mut x = 1;
    x = 2;
    let _ = x;  // mut skipped
}

fn destructure() {
    let pair = (1, 2);
    let _ = pair;
}
