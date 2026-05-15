//! Development task runner for the zuit workspace.
//!
//! Usage: `cargo xtask <subcommand>`. Subcommands: ci, lint, fmt, test, bench,
//! doc, sync, sync-check, verify-tag.
//!
//! `ci` runs fmt-check, clippy with `-D warnings`, and the test suite. It is
//! the single command CI should call.
#![warn(missing_docs)]

pub mod sync;

use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let result = match cmd.as_str() {
        "ci" => ci(),
        "lint" => clippy(),
        "fmt" => fmt(),
        "test" => test(),
        "bench" => bench(),
        "doc" => doc(),
        "sync" => do_sync(),
        "sync-check" => do_sync_check(),
        "verify-tag" => {
            let tag = args.next().unwrap_or_default();
            do_verify_tag(&tag)
        }
        "" => {
            print_help();
            return ExitCode::from(2);
        }
        other => {
            eprintln!("xtask: unknown subcommand `{other}`");
            print_help();
            return ExitCode::from(2);
        }
    };
    if result {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Run fmt-check, clippy, and tests (the full CI suite).
fn ci() -> bool {
    fmt_check() && clippy() && test()
}

/// Format all code.
fn fmt() -> bool {
    run("cargo", &["fmt", "--all"])
}

/// Check code formatting without changes.
fn fmt_check() -> bool {
    run("cargo", &["fmt", "--all", "--check"])
}

/// Lint with clippy denying warnings.
fn clippy() -> bool {
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
}

/// Run the test suite.
fn test() -> bool {
    run("cargo", &["test", "--workspace"])
}

/// Run benchmarks.
fn bench() -> bool {
    run("cargo", &["bench", "--workspace"])
}

/// Generate documentation.
fn doc() -> bool {
    run("cargo", &["doc", "--workspace", "--no-deps"])
}

/// Sync managed files from `meta/project.toml`.
fn do_sync() -> bool {
    let root = workspace_root();
    match sync::run_sync(&root) {
        Ok(()) => {
            eprintln!("xtask sync: managed files updated successfully");
            true
        }
        Err(e) => {
            eprintln!("xtask sync: {e}");
            false
        }
    }
}

/// Check that managed files are in sync; exit non-zero if not.
fn do_sync_check() -> bool {
    let root = workspace_root();
    match sync::run_sync_check(&root) {
        Ok(true) => {
            eprintln!("xtask sync-check: all managed files are in sync");
            true
        }
        Ok(false) => {
            eprintln!("xtask sync-check: managed files are out of sync — run `cargo xtask sync`");
            false
        }
        Err(e) => {
            eprintln!("xtask sync-check: {e}");
            false
        }
    }
}

/// Verify that the provided git tag matches the SSOT version.
fn do_verify_tag(tag: &str) -> bool {
    if tag.is_empty() {
        eprintln!("xtask verify-tag: TAG argument is required");
        return false;
    }
    let root = workspace_root();
    match sync::verify_tag(&root, tag) {
        Ok(true) => {
            eprintln!("xtask verify-tag: tag `{tag}` matches SSOT version");
            true
        }
        Ok(false) => {
            eprintln!("xtask verify-tag: tag `{tag}` does NOT match SSOT version");
            false
        }
        Err(e) => {
            eprintln!("xtask verify-tag: {e}");
            false
        }
    }
}

/// Resolve the workspace root from `CARGO_MANIFEST_DIR` at run time.
///
/// `xtask` lives at `crates/xtask/`; the workspace root is two levels up.
fn workspace_root() -> std::path::PathBuf {
    // `CARGO_MANIFEST_DIR` is set by Cargo when building; at *run time* we
    // instead use the current working directory which, for `cargo xtask`, is
    // the workspace root.
    std::env::current_dir().expect("invariant: current directory is accessible")
}

/// Run a command and return whether it succeeded.
fn run(program: &str, args: &[&str]) -> bool {
    eprintln!("$ {program} {}", args.join(" "));
    Command::new(program)
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

/// Print usage information.
fn print_help() {
    eprintln!("usage: cargo xtask <ci|lint|fmt|test|bench|doc|sync|sync-check|verify-tag <TAG>>");
}
