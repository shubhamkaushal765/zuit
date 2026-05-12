//! Smoke tests for `zuit show`, `zuit stop`, and `zuit status`,
//! plus the `--no-save` flag on `zuit analyze`.

use assert_cmd::Command;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn analyze_no_save_does_not_write_history() {
    let home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    Command::cargo_bin("zuit")
        .unwrap()
        .env("HOME", home.path())
        .timeout(Duration::from_secs(30))
        .args([
            "analyze",
            &work.path().display().to_string(),
            "--no-save",
            "--format",
            "json",
        ])
        .assert()
        .success();
    let zuit_home = home.path().join(".zuit");
    let n = std::fs::read_dir(zuit_home.join("projects"))
        .map(std::iter::Iterator::count)
        .unwrap_or(0);
    assert_eq!(n, 0, "no projects should be recorded with --no-save");
}

#[test]
fn status_when_no_daemon_says_not_running() {
    let home = TempDir::new().unwrap();
    Command::cargo_bin("zuit")
        .unwrap()
        .env("HOME", home.path())
        .timeout(Duration::from_secs(10))
        .arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("not running"));
}

/// End-to-end daemon round trip. Marked `#[ignore]` because it spawns a
/// detached background process whose lifetime crosses test-process bounds;
/// run explicitly with `cargo test -- --ignored show_then_stop`.
#[test]
#[ignore = "spawns a detached daemon process; run explicitly with --ignored"]
fn show_then_stop_round_trip() {
    let home = TempDir::new().unwrap();
    // `show` blocks until the parent CLI exits — which it does after the
    // grandchild has redirected its stdio to /dev/null. The 10-second
    // timeout is a fallback if the grandchild fails to dup2 in time.
    Command::cargo_bin("zuit")
        .unwrap()
        .env("HOME", home.path())
        .timeout(Duration::from_secs(10))
        .arg("show")
        .assert()
        .success();

    // Give the daemon a beat to be ready for healthz.
    std::thread::sleep(Duration::from_millis(200));

    Command::cargo_bin("zuit")
        .unwrap()
        .env("HOME", home.path())
        .timeout(Duration::from_secs(5))
        .arg("status")
        .assert()
        .stdout(predicates::str::contains("running"));

    Command::cargo_bin("zuit")
        .unwrap()
        .env("HOME", home.path())
        .timeout(Duration::from_secs(5))
        .arg("stop")
        .assert()
        .success();

    Command::cargo_bin("zuit")
        .unwrap()
        .env("HOME", home.path())
        .timeout(Duration::from_secs(5))
        .arg("status")
        .assert()
        .stdout(predicates::str::contains("not running"));
}
