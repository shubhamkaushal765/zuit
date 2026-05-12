//! Smoke tests for the plugin-management CLI subcommands.
//!
//! Uses `assert_cmd` to run the compiled binary against a temp `ZUIT_HOME`.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

#[test]
#[cfg(unix)]
fn add_list_remove_round_trip() {
    let tempdir = TempDir::new().unwrap();
    let zuit_home = tempdir.path();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../zuit-plugins/tests/fixtures/echo-plugin");

    // add
    Command::cargo_bin("zuit")
        .unwrap()
        .env("ZUIT_HOME", zuit_home)
        .args(["add-analyzer", fixture.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("Installed plugin 'echo'"));

    // list (plugins)
    Command::cargo_bin("zuit")
        .unwrap()
        .env("ZUIT_HOME", zuit_home)
        .args(["list", "plugins"])
        .assert()
        .success()
        .stdout(contains("echo"));

    // remove
    Command::cargo_bin("zuit")
        .unwrap()
        .env("ZUIT_HOME", zuit_home)
        .args(["remove-analyzer", "echo"])
        .assert()
        .success()
        .stdout(contains("Removed plugin 'echo'"));

    // list again — should show no plugins
    Command::cargo_bin("zuit")
        .unwrap()
        .env("ZUIT_HOME", zuit_home)
        .args(["list", "plugins"])
        .assert()
        .success()
        .stdout(contains("No plugins installed"));
}
