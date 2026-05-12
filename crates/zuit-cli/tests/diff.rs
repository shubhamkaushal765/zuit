//! Integration tests for `zuit diff`.

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

fn zuit() -> Command {
    Command::cargo_bin("zuit").expect("zuit binary must be built")
}

fn make_finding(file: &str, line: u64, rule_id: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "rule_id": rule_id,
        "message": message,
        "location": {
            "file": file,
            "start": { "line": line, "col": 1 }
        }
    })
}

fn make_envelope(findings: &[serde_json::Value]) -> serde_json::Value {
    serde_json::json!({
        "scan_id": "test-scan",
        "report": {
            "findings": findings,
            "scores": {}
        }
    })
}

fn write_json(dir: &TempDir, name: &str, value: &serde_json::Value) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    path
}

// Test 1: identical reports → exit 0, empty `new` array.
#[test]
fn diff_identical_reports_exit_zero() {
    let tmp = TempDir::new().unwrap();
    let finding = make_finding("src/main.rs", 10, "SEC001", "hardcoded secret");
    let envelope = make_envelope(&[finding]);
    let from = write_json(&tmp, "from.json", &envelope);
    let to = write_json(&tmp, "to.json", &envelope);

    let output = zuit()
        .args(["diff", from.to_str().unwrap(), to.to_str().unwrap()])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON output");
    let new_arr = json["new"].as_array().expect("new must be array");
    assert!(
        new_arr.is_empty(),
        "new must be empty for identical reports"
    );
}

// Test 2: TO has one extra finding → exit 1, `new` array length 1.
#[test]
fn diff_extra_finding_in_to_exits_one() {
    let tmp = TempDir::new().unwrap();
    let shared = make_finding("src/main.rs", 10, "SEC001", "hardcoded secret");
    let extra = make_finding("src/lib.rs", 5, "MAINT001", "complexity too high");

    let from_env = make_envelope(std::slice::from_ref(&shared));
    let to_env = make_envelope(&[shared, extra]);

    let from = write_json(&tmp, "from.json", &from_env);
    let to = write_json(&tmp, "to.json", &to_env);

    let output = zuit()
        .args(["diff", from.to_str().unwrap(), to.to_str().unwrap()])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON output");
    let new_arr = json["new"].as_array().expect("new must be array");
    assert_eq!(new_arr.len(), 1, "expected exactly one new finding");
}

// Test 3: TO is missing one finding from FROM → `resolved` array length 1.
#[test]
fn diff_resolved_finding_shows_in_resolved() {
    let tmp = TempDir::new().unwrap();
    let shared = make_finding("src/main.rs", 10, "SEC001", "hardcoded secret");
    let old_finding = make_finding("src/lib.rs", 5, "MAINT001", "complexity too high");

    let from_env = make_envelope(&[shared.clone(), old_finding]);
    let to_env = make_envelope(std::slice::from_ref(&shared));

    let from = write_json(&tmp, "from.json", &from_env);
    let to = write_json(&tmp, "to.json", &to_env);

    let output = zuit()
        .args(["diff", from.to_str().unwrap(), to.to_str().unwrap()])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON output");
    let resolved = json["resolved"].as_array().expect("resolved must be array");
    assert_eq!(resolved.len(), 1, "expected exactly one resolved finding");
}

// Test 4: malformed JSON in either file → exit 2.
#[test]
fn diff_malformed_json_exits_two() {
    let tmp = TempDir::new().unwrap();
    let bad = tmp.path().join("bad.json");
    fs::write(&bad, b"this is not json").unwrap();

    let good_env = make_envelope(&[]);
    let good = write_json(&tmp, "good.json", &good_env);

    zuit()
        .args(["diff", bad.to_str().unwrap(), good.to_str().unwrap()])
        .assert()
        .code(2);

    zuit()
        .args(["diff", good.to_str().unwrap(), bad.to_str().unwrap()])
        .assert()
        .code(2);
}
