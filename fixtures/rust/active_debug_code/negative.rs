// Fixture: MAINT011-active-debug-code — Rust negative cases
// No dbg! calls — should produce zero findings for MAINT011.

fn compute(x: i32) -> i32 {
    x * 2
}

fn format_output(value: i32) {
    // println! is not flagged by default (flag_println = false)
    println!("Result: {value}");
}

fn log_error(msg: &str) {
    eprintln!("Error: {msg}");
}
