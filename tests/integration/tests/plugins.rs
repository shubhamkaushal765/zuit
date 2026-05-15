//! End-to-end test for the zuit plugin feature.
//!
//! Verifies the full lifecycle:
//!   add-analyzer → list plugins → analyze (sees plugin finding) → remove-analyzer → analyze (no plugin finding)

use std::path::PathBuf;

use assert_cmd::Command;
use tempfile::TempDir;

/// Returns a `Command` that will invoke the `zuit` binary.
fn zuit() -> Command {
    Command::cargo_bin("zuit").expect("zuit binary must be buildable")
}

/// Resolves a path relative to the workspace root.
///
/// `CARGO_MANIFEST_DIR` for this crate is `tests/integration`; the workspace
/// root is two directories up.
fn workspace_path(rel: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent() // tests/
        .expect("parent of integration/")
        .parent() // workspace root
        .expect("workspace root")
        .join(rel)
}

#[test]
#[cfg(unix)]
fn plugin_round_trip_through_analyze() {
    let zuit_home = TempDir::new().unwrap();
    let target = TempDir::new().unwrap();
    // Write a single .py file so analyze has at least one file to walk.
    std::fs::write(target.path().join("hello.py"), "print('hi')\n").unwrap();

    let fixture = workspace_path("crates/zuit-plugins/tests/fixtures/echo-plugin");
    assert!(fixture.exists(), "fixture missing at {}", fixture.display());

    // 1. add-analyzer — installs the echo plugin.
    let add_stdout = String::from_utf8(
        zuit()
            .env("ZUIT_HOME", zuit_home.path())
            .args(["add-analyzer", fixture.to_str().unwrap()])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        add_stdout.contains("Installed plugin 'echo'"),
        "expected 'Installed plugin \\'echo\\''; got: {add_stdout}"
    );

    // 2. list plugins — 'echo' must appear.
    let list_stdout = String::from_utf8(
        zuit()
            .env("ZUIT_HOME", zuit_home.path())
            .args(["list", "plugins"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        list_stdout.contains("echo"),
        "expected 'echo' in plugin list; got: {list_stdout}"
    );

    // 3. analyze — the echo plugin must contribute a finding with rule_id starting with "echo/".
    let analyze_stdout = String::from_utf8(
        zuit()
            .env("ZUIT_HOME", zuit_home.path())
            .args([
                "analyze",
                "--no-save",
                "--format",
                "json",
                target.path().to_str().unwrap(),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        analyze_stdout.contains("\"rule_id\": \"echo/"),
        "expected an echo/ finding in JSON output; got: {analyze_stdout}"
    );

    // 4. remove-analyzer — uninstalls the echo plugin.
    let remove_stdout = String::from_utf8(
        zuit()
            .env("ZUIT_HOME", zuit_home.path())
            .args(["remove-analyzer", "echo"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        remove_stdout.contains("Removed plugin 'echo'"),
        "expected 'Removed plugin \\'echo\\''; got: {remove_stdout}"
    );

    // 5. analyze again — no echo/ finding should appear.
    let analyze_stdout2 = String::from_utf8(
        zuit()
            .env("ZUIT_HOME", zuit_home.path())
            .args([
                "analyze",
                "--no-save",
                "--format",
                "json",
                target.path().to_str().unwrap(),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        !analyze_stdout2.contains("\"rule_id\": \"echo/"),
        "echo finding should be absent after remove-analyzer; got: {analyze_stdout2}"
    );
}
