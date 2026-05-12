//! Positive fixture for SEC003-shell-injection.
//!
//! Both signals are present:
//!   1. Import of `std::process::Command` (a shell-exec module).
//!   2. A string literal that matches the shell-prefix command pattern.

use std::process::Command;

/// Run a shell command with user-supplied input — injection risk.
pub fn run_user_command(payload: &str) {
    // The string literal below matches the shell-prefix pattern: "sh -c".
    let _cmd = Command::new("sh").arg("-c").arg(payload);
    let _shell_prefix = "sh -c";
}
