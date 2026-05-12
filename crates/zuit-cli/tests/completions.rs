//! Integration tests for the `zuit completions <shell>` subcommand.
//!
//! These tests must FAIL before the `Completions` command is implemented.

use assert_cmd::Command;

fn zuit() -> Command {
    Command::cargo_bin("zuit").expect("zuit binary must be buildable")
}

/// Bash completion script must emit the `_zuit()` function.
#[test]
fn bash_completion_emits_function() {
    zuit()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicates::str::contains("_zuit"));
}

/// Zsh completion script must start with `#compdef zuit`.
#[test]
fn zsh_completion_emits_compdef() {
    let output = zuit()
        .args(["completions", "zsh"])
        .output()
        .expect("failed to run zuit completions zsh");

    assert!(output.status.success(), "exit code was not 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("#compdef zuit"),
        "zsh completion should start with '#compdef zuit', got:\n{stdout}"
    );
}
