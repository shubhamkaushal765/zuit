//! Integration tests for the `zuit` binary.
//!
//! Uses `assert_cmd` to run the compiled binary and `assert_fs` for temp dirs.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use assert_fs::TempDir;

/// Returns a `Command` that invokes the `zuit` binary.
fn zuit() -> Command {
    Command::cargo_bin("zuit").expect("zuit binary must be built")
}

/// Returns the workspace root directory (two levels up from this crate).
fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the directory of this crate's Cargo.toml:
    // crates/zuit-cli. The workspace root is two directories up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent() // crates/
        .expect("crates dir")
        .parent() // workspace root
        .expect("workspace root")
        .to_path_buf()
}

/// Absolute path to the Rust healthy fixtures.
fn rust_healthy() -> PathBuf {
    workspace_root().join("fixtures/rust/healthy")
}

/// Absolute path to the Rust unhealthy fixtures.
fn rust_unhealthy() -> PathBuf {
    workspace_root().join("fixtures/rust/unhealthy")
}

/// Absolute path to the Python unhealthy fixtures.
fn python_unhealthy() -> PathBuf {
    workspace_root().join("fixtures/python/unhealthy")
}

// ── Test 1: analyze healthy Rust fixture, JSON output, exit 0 ────────────────

#[test]
fn analyze_rust_healthy_json_exit_zero() {
    let path = rust_healthy();
    let output = zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("stdout must be valid JSON");

    // schema_version must be 1
    assert_eq!(json["schema_version"], 1, "expected schema_version == 1");

    // The findings array must exist (may be empty for healthy fixture).
    assert!(
        json["findings"].is_array(),
        "expected findings to be an array"
    );
}

// ── Test 2: analyze unhealthy Rust, fail-on high → exit 1 ────────────────────

#[test]
fn analyze_rust_unhealthy_fail_on_high_exits_one() {
    let path = rust_unhealthy();
    zuit()
        .args([
            "analyze",
            path.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on",
            "high",
        ])
        .assert()
        .failure(); // exit code 1
}

// ── Test 3: analyze unhealthy Python, fail-on high → exit 1 ──────────────────

#[test]
fn analyze_python_unhealthy_fail_on_high_exits_one() {
    let path = python_unhealthy();
    zuit()
        .args([
            "analyze",
            path.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on",
            "high",
        ])
        .assert()
        .failure(); // exit code 1
}

// ── Test 4: terminal output contains expected rule IDs ────────────────────────

#[test]
fn analyze_rust_unhealthy_terminal_contains_rule_ids() {
    let path = rust_unhealthy();
    let output = zuit()
        .args([
            "analyze",
            path.to_str().unwrap(),
            "--format",
            "terminal",
            "--no-color",
        ])
        .assert()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("stdout must be valid UTF-8");

    // The unhealthy Rust fixture must trigger at least SEC001 (hardcoded secret)
    // and SEC101 (unsafe block); check that at least one rule ID appears.
    let has_any_rule = text.contains("SEC001")
        || text.contains("SEC101")
        || text.contains("MAINT001")
        || text.contains("DOC001");

    assert!(
        has_any_rule,
        "expected at least one rule ID in terminal output, got:\n{text}"
    );
}

// ── Test 5: list analyzers contains expected rule IDs ────────────────────────

#[test]
fn list_analyzers_contains_expected_rules() {
    let output = zuit()
        .args(["list", "analyzers"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("stdout must be valid UTF-8");

    assert!(
        text.contains("MAINT001-cyclomatic"),
        "list analyzers must include MAINT001-cyclomatic, got:\n{text}"
    );
    assert!(
        text.contains("SEC001-hardcoded-secret"),
        "list analyzers must include SEC001-hardcoded-secret, got:\n{text}"
    );
    assert!(
        text.contains("SEC101-rust-unsafe"),
        "list analyzers must include SEC101-rust-unsafe, got:\n{text}"
    );
}

// ── Test 6: init creates zuit.toml; second run errors ────────────────────

#[test]
fn init_creates_toml_second_run_errors() {
    let tmp = TempDir::new().expect("temp dir creation");

    // First run: should succeed and create zuit.toml.
    zuit()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();

    let toml_path = tmp.path().join("zuit.toml");
    assert!(toml_path.exists(), "zuit.toml must have been created");

    let content = fs::read_to_string(&toml_path).expect("reading zuit.toml");
    assert!(
        content.contains("[general]"),
        "zuit.toml must contain [general] section"
    );

    // Second run: should fail because the file already exists.
    zuit()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .failure();

    tmp.close().expect("temp dir cleanup");
}

// ── Test 7: JSON output parses and findings array exists (unhealthy) ──────────

#[test]
fn analyze_rust_unhealthy_json_has_findings() {
    let path = rust_unhealthy();
    let output = zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("stdout must be valid JSON");

    let findings = json["findings"].as_array().expect("findings must be array");
    assert!(
        !findings.is_empty(),
        "unhealthy Rust fixture must produce at least one finding"
    );

    // Each finding must have a rule_id field.
    for f in findings {
        assert!(
            f["rule_id"].is_string(),
            "every finding must have a string rule_id"
        );
    }
}

// ── Test 8: --fail-on not set always exits 0 even with findings ───────────────

#[test]
fn analyze_unhealthy_without_fail_on_exits_zero() {
    let path = rust_unhealthy();
    zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success(); // exit code 0 (no --fail-on)
}

// ── Test 9: list languages includes rust and python ───────────────────────────

#[test]
fn list_languages_shows_rust_and_python() {
    let output = zuit()
        .args(["list", "languages"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("stdout must be valid UTF-8");
    assert!(
        text.contains("rust"),
        "list languages must include rust, got:\n{text}"
    );
    assert!(
        text.contains("python"),
        "list languages must include python, got:\n{text}"
    );
}

// ── Test 10: analyze Python unhealthy JSON contains SEC002 ───────────────────

#[test]
fn analyze_python_unhealthy_json_contains_sec002() {
    let path = python_unhealthy();
    let output = zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("stdout must be valid JSON");

    let findings = json["findings"].as_array().expect("findings must be array");
    let has_sec002 = findings
        .iter()
        .any(|f| f["rule_id"].as_str() == Some("SEC002-eval-sink"));

    assert!(
        has_sec002,
        "Python unhealthy fixture must produce SEC002-eval-sink finding"
    );
}

// ── Test 11: JUnit XML output (healthy fixture) ───────────────────────────────

/// Runs `zuit analyze --format junit` against the healthy Rust fixture and
/// asserts that the output is valid `JUnit` XML with the expected root element.
#[test]
fn analyze_rust_healthy_junit_output() {
    let path = rust_healthy();
    let output = zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "junit"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("stdout must be valid UTF-8");

    assert!(
        text.starts_with("<?xml"),
        "JUnit output must start with <?xml declaration, got:\n{text}"
    );
    assert!(
        text.contains("<testsuites"),
        "JUnit output must contain <testsuites root element, got:\n{text}"
    );
}

// ── Test 12: --format junit produces well-formed JUnit XML (unhealthy) ────────

#[test]
fn analyze_rust_unhealthy_junit_output_is_valid_xml() {
    let path = rust_unhealthy();
    let output = zuit()
        .args([
            "analyze",
            path.to_str().unwrap(),
            "--format",
            "junit",
            "--no-save",
        ])
        .assert()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("stdout must be valid UTF-8");

    assert!(
        text.starts_with("<?xml"),
        "JUnit output must start with XML declaration; got:\n{text}"
    );
    assert!(
        text.contains("<testsuites"),
        "JUnit output must contain <testsuites> root element; got:\n{text}"
    );
    assert!(
        text.contains("<testsuite"),
        "JUnit output must contain at least one <testsuite> element; got:\n{text}"
    );
    assert!(
        text.contains("<testcase"),
        "JUnit output must contain at least one <testcase> element for unhealthy fixture; \
         got:\n{text}"
    );
    assert!(
        text.contains("</testsuites>"),
        "JUnit output must close the root <testsuites> element; got:\n{text}"
    );
}

// ── Test 13: `zuit report --format junit` re-renders JSON as JUnit ────────

#[test]
fn report_subcommand_junit_format_produces_xml() {
    let path = rust_unhealthy();

    // First capture the JSON report.
    let json_output = zuit()
        .args([
            "analyze",
            path.to_str().unwrap(),
            "--format",
            "json",
            "--no-save",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // Write JSON to a temp file so `report` can read it.
    let tmp = TempDir::new().expect("temp dir");
    let json_path = tmp.path().join("report.json");
    fs::write(&json_path, &json_output).expect("write json report");

    let junit_output = zuit()
        .args(["report", json_path.to_str().unwrap(), "--format", "junit"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(junit_output).expect("stdout must be valid UTF-8");
    assert!(
        text.starts_with("<?xml"),
        "re-rendered JUnit output must start with XML declaration; got:\n{text}"
    );
    assert!(
        text.contains("<testsuites"),
        "re-rendered JUnit output must have <testsuites>; got:\n{text}"
    );

    tmp.close().expect("temp dir cleanup");
}
