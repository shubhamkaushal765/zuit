//! Integration tests for `zuit install-hook`.

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

fn zuit() -> Command {
    Command::cargo_bin("zuit").expect("zuit binary must be built")
}

fn make_fake_repo() -> TempDir {
    let tmp = TempDir::new().expect("tempdir");
    fs::create_dir_all(tmp.path().join(".git")).expect("create .git dir");
    tmp
}

#[test]
fn install_hook_creates_pre_commit_file() {
    let tmp = make_fake_repo();
    zuit()
        .args(["install-hook"])
        .current_dir(tmp.path())
        .assert()
        .success();

    let hook = tmp.path().join(".git/hooks/pre-commit");
    assert!(hook.exists(), "pre-commit hook file must exist");
}

#[cfg(unix)]
#[test]
fn install_hook_sets_executable_bit() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = make_fake_repo();
    zuit()
        .args(["install-hook"])
        .current_dir(tmp.path())
        .assert()
        .success();

    let hook = tmp.path().join(".git/hooks/pre-commit");
    let mode = fs::metadata(&hook).expect("metadata").permissions().mode();
    assert!(mode & 0o111 != 0, "hook must be executable (mode={mode:o})");
}

#[test]
fn install_hook_errors_when_hook_exists_without_force() {
    let tmp = make_fake_repo();

    // Install once.
    zuit()
        .args(["install-hook"])
        .current_dir(tmp.path())
        .assert()
        .success();

    // Second install without --force must fail.
    zuit()
        .args(["install-hook"])
        .current_dir(tmp.path())
        .assert()
        .failure();
}

#[test]
fn install_hook_overwrites_with_force() {
    let tmp = make_fake_repo();
    zuit()
        .args(["install-hook"])
        .current_dir(tmp.path())
        .assert()
        .success();
    zuit()
        .args(["install-hook", "--force"])
        .current_dir(tmp.path())
        .assert()
        .success();
}

#[test]
fn install_hook_content_contains_fail_on_medium() {
    let tmp = make_fake_repo();
    zuit()
        .args(["install-hook"])
        .current_dir(tmp.path())
        .assert()
        .success();

    let hook = tmp.path().join(".git/hooks/pre-commit");
    let content = fs::read_to_string(&hook).expect("read hook");
    assert!(
        content.contains("zuit analyze --fail-on medium"),
        "hook content must contain 'zuit analyze --fail-on medium'"
    );
}

#[test]
fn install_hook_fails_outside_git_repo() {
    let tmp = TempDir::new().expect("tempdir");
    // No .git directory.
    zuit()
        .args(["install-hook"])
        .current_dir(tmp.path())
        .assert()
        .failure();
}

#[test]
fn install_hook_prints_path_on_success() {
    let tmp = make_fake_repo();
    let output = zuit()
        .args(["install-hook"])
        .current_dir(tmp.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("stdout utf8");
    assert!(
        text.contains("pre-commit"),
        "stdout must mention the hook path, got: {text}"
    );
}
