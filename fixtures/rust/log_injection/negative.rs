// Negative fixtures for SEC015-log-injection (CWE-117)
// None of these should trigger a finding.

use log;

// No placeholder
fn startup() {
    log::info!("startup complete");
}

// Placeholder but non-request, non-param arg
fn report() {
    let total = 42;
    log::info!("count: {}", total);
}

// Not a logging macro
fn debug_out() {
    println!("debug: {}", "safe");
}
