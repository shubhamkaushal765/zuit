//! Workspace-level integration tests for the `zuit` CLI binary.
//!
//! Design notes
//! ─────────────
//! - Tests live in `tests/integration/` (a dedicated workspace member) rather
//!   than inside `crates/zuit-cli/tests/` so they are visible at the
//!   workspace layout level described by `ARCH_SPEC` §4.
//! - `crates/zuit-cli/tests/cli_integration.rs` already covers several
//!   scenarios; this suite adds the `ARCH_SPEC` §12 requirements that were
//!   NOT STARTED: structured JSON assertions against fixtures, `list languages`,
//!   `list analyzers`, non-existent path, JS fixture smoke-test, and the
//!   `--fail-on` exit-code contract.
//! - Finding *counts* are intentionally NOT pinned — a parallel agent is adding
//!   JS-specific rules that will perturb counts.  We pin on structural invariants
//!   (`schema_version`, field presence) and on a small number of stable
//!   rule IDs that already exist in the chosen fixture.

use std::path::PathBuf;

use assert_cmd::Command;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Returns a `Command` that will invoke the `zuit` binary.
///
/// `assert_cmd` compiles the binary automatically on first use via Cargo.
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

// ── Test 1: rust/healthy — exit 0, schema_version 1, findings field present ──

#[test]
fn rust_healthy_json_exit_zero_schema_version() {
    let path = workspace_path("fixtures/rust/healthy");
    let raw = zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout must be valid JSON");

    assert_eq!(
        json["schema_version"], 1,
        "schema_version must be 1, got: {}",
        json["schema_version"]
    );
    assert!(
        json["findings"].is_array(),
        "findings field must be an array"
    );
    assert!(json["scores"].is_object(), "scores field must be an object");
    assert!(json["stats"].is_object(), "stats field must be an object");
}

// ── Test 2: rust/unhealthy — exit 0, non-empty findings, SEC001 present ───────

#[test]
fn rust_unhealthy_json_has_sec001_finding() {
    let path = workspace_path("fixtures/rust/unhealthy");
    let raw = zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout must be valid JSON");

    assert_eq!(json["schema_version"], 1);

    let findings = json["findings"].as_array().expect("findings must be array");
    assert!(
        !findings.is_empty(),
        "rust/unhealthy must produce at least one finding"
    );

    // Every finding must have a string rule_id field.
    for f in findings {
        assert!(
            f["rule_id"].is_string(),
            "every finding must carry a string rule_id; got: {f:?}"
        );
    }

    // The fixture contains a hardcoded AWS key — SEC001 must fire.
    let has_sec001 = findings
        .iter()
        .any(|f| f["rule_id"].as_str() == Some("SEC001-hardcoded-secret"));
    assert!(
        has_sec001,
        "rust/unhealthy must produce SEC001-hardcoded-secret; rule_ids present: {:?}",
        findings
            .iter()
            .filter_map(|f| f["rule_id"].as_str())
            .collect::<Vec<_>>()
    );
}

// ── Test 3: python/unhealthy — exit 0, SEC002-eval-sink present ───────────────

#[test]
fn python_unhealthy_json_has_sec002_finding() {
    let path = workspace_path("fixtures/python/unhealthy");
    let raw = zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout must be valid JSON");

    assert_eq!(json["schema_version"], 1);

    let findings = json["findings"].as_array().expect("findings must be array");

    let has_sec002 = findings
        .iter()
        .any(|f| f["rule_id"].as_str() == Some("SEC002-eval-sink"));
    assert!(
        has_sec002,
        "python/unhealthy must produce SEC002-eval-sink; rule_ids present: {:?}",
        findings
            .iter()
            .filter_map(|f| f["rule_id"].as_str())
            .collect::<Vec<_>>()
    );
}

// ── Test 4: js/unhealthy — exit 0, schema_version 1, structural fields present

#[test]
fn js_unhealthy_json_structural_fields_present() {
    let path = workspace_path("fixtures/js/unhealthy");
    let raw = zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout must be valid JSON");

    // Structural invariants — do NOT pin rule_ids (parallel JS-rule agent).
    assert_eq!(
        json["schema_version"], 1,
        "schema_version must be 1 for JS fixture"
    );
    assert!(
        json["findings"].is_array(),
        "findings must be an array for JS fixture"
    );
    assert!(
        json["scores"].is_object(),
        "scores must be an object for JS fixture"
    );
    assert!(
        json["stats"]["files_scanned"].is_number(),
        "stats.files_scanned must be a number for JS fixture"
    );
}

// ── Test 5: --fail-on high exits non-zero when high findings present ──────────

#[test]
fn rust_unhealthy_fail_on_high_exits_nonzero() {
    let path = workspace_path("fixtures/rust/unhealthy");
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
        .failure(); // exit code must be non-zero
}

// ── Test 6: list languages — rust / python / javascript all present ───────────

#[test]
fn list_languages_contains_rust_python_javascript() {
    let raw = zuit()
        .args(["list", "languages"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(raw).expect("stdout must be UTF-8");
    assert!(
        text.contains("rust"),
        "list languages must include 'rust'; got:\n{text}"
    );
    assert!(
        text.contains("python"),
        "list languages must include 'python'; got:\n{text}"
    );
    assert!(
        text.contains("javascript") || text.contains("js"),
        "list languages must include 'javascript' or 'js'; got:\n{text}"
    );
}

// ── Test 7: list analyzers — non-empty, contains known stable rule id ─────────

#[test]
fn list_analyzers_nonempty_contains_maint001() {
    let raw = zuit()
        .args(["list", "analyzers"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(raw).expect("stdout must be UTF-8");
    assert!(
        !text.trim().is_empty(),
        "list analyzers must produce non-empty output"
    );
    assert!(
        text.contains("MAINT001-cyclomatic"),
        "list analyzers must contain 'MAINT001-cyclomatic'; got:\n{text}"
    );
}

// ── Test 8: nonexistent path — exit non-zero, stderr mentions error ───────────

#[test]
fn analyze_nonexistent_path_exits_nonzero_with_error_message() {
    let bad_path = "/tmp/zuit_test_nonexistent_path_xyz_should_not_exist_12345";
    let out = zuit()
        .args(["analyze", bad_path])
        .assert()
        .failure()
        .get_output()
        .clone();

    // Either stderr or stdout should contain a useful diagnostic string.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stderr}{stdout}");

    assert!(
        combined.contains("error")
            || combined.contains("Error")
            || combined.contains("not found")
            || combined.contains("No such file")
            || combined.contains("does not exist")
            || combined.contains("cannot"),
        "expected an error message for nonexistent path; combined output:\n{combined}"
    );
}

// ── Test 9: no --fail-on exits 0 even when findings present ──────────────────

#[test]
fn rust_unhealthy_without_fail_on_exits_zero() {
    let path = workspace_path("fixtures/rust/unhealthy");
    zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success(); // findings present but no --fail-on → exit 0
}

// ── scan: alias of analyze produces equivalent finding count ──────────────────

#[test]
fn scan_alias_matches_analyze_finding_count() {
    let path = workspace_path("fixtures/python/sql_injection");
    let analyze_raw = zuit()
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
    let scan_raw = zuit()
        .args([
            "scan",
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
    let analyze_json: serde_json::Value =
        serde_json::from_slice(&analyze_raw).expect("analyze stdout JSON");
    let scan_json: serde_json::Value = serde_json::from_slice(&scan_raw).expect("scan stdout JSON");
    assert_eq!(
        analyze_json["findings"].as_array().map(Vec::len),
        scan_json["findings"].as_array().map(Vec::len),
        "scan and analyze must yield the same number of findings"
    );
}

// ── --owasp keeps only matching findings ─────────────────────────────────────

#[test]
fn analyze_owasp_filter_keeps_only_matching_findings() {
    // The python/sql_injection fixture exercises SEC006 (OWASP A03:2021).
    let path = workspace_path("fixtures/python/sql_injection");
    let raw = zuit()
        .args([
            "analyze",
            path.to_str().unwrap(),
            "--format",
            "json",
            "--no-save",
            "--owasp",
            "A03:2021",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout JSON");
    let findings = json["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "expected ≥1 finding for A03:2021 on the sql_injection fixture"
    );
    for f in findings {
        let owasp = f["owasp"].as_array().cloned().unwrap_or_default();
        assert!(
            owasp.iter().any(|o| o.as_str() == Some("A03:2021")),
            "every finding must carry A03:2021; got owasp={owasp:?}"
        );
    }
}

#[test]
fn analyze_owasp_filter_with_no_match_returns_empty_findings() {
    let path = workspace_path("fixtures/python/sql_injection");
    let raw = zuit()
        .args([
            "analyze",
            path.to_str().unwrap(),
            "--format",
            "json",
            "--no-save",
            "--owasp",
            "A99:1999",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout JSON");
    let findings = json["findings"].as_array().expect("findings array");
    assert!(
        findings.is_empty(),
        "no finding has OWASP A99:1999 — filter should drop everything"
    );
}

// ── --cwe filter keeps only matching findings ────────────────────────────────

#[test]
fn analyze_cwe_filter_keeps_only_matching_findings() {
    // fixtures/python/path_traversal exercises SEC007 (CWE-22).
    let path = workspace_path("fixtures/python/path_traversal");
    let raw = zuit()
        .args([
            "analyze",
            path.to_str().unwrap(),
            "--format",
            "json",
            "--no-save",
            "--cwe",
            "CWE-22",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout JSON");
    let findings = json["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "expected ≥1 finding for CWE-22 on the path_traversal fixture"
    );
    for f in findings {
        let cwe = f["cwe"].as_array().cloned().unwrap_or_default();
        assert!(
            cwe.iter().any(|c| c.as_str() == Some("CWE-22")),
            "every finding must carry CWE-22; got cwe={cwe:?}"
        );
    }
}

// ── report: re-renders JSON in another format ────────────────────────────────

#[test]
fn report_subcommand_re_renders_json_to_markdown() {
    let path = workspace_path("fixtures/rust/healthy");
    let json_dir = tempfile::tempdir().expect("tempdir");
    let json_path = json_dir.path().join("report.json");

    // Step 1: produce a JSON report.
    zuit()
        .args([
            "analyze",
            path.to_str().unwrap(),
            "--format",
            "json",
            "--no-save",
            "--output",
            json_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(json_path.exists(), "analyze must write the JSON file");

    // Step 2: feed it to `zuit report` in markdown form.
    let md = zuit()
        .args([
            "report",
            json_path.to_str().unwrap(),
            "--format",
            "markdown",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let md_text = std::str::from_utf8(&md).expect("markdown must be utf8");
    assert!(
        !md_text.is_empty(),
        "markdown output must be non-empty for any input report"
    );
    assert!(
        md_text.contains('#'),
        "markdown output must contain a heading marker"
    );
}

// ── Test 10: JSON tool field present with name and version ────────────────────

#[test]
fn json_output_contains_tool_field() {
    let path = workspace_path("fixtures/rust/healthy");
    let raw = zuit()
        .args(["analyze", path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout must be valid JSON");

    assert!(
        json["tool"].is_object(),
        "JSON output must contain a 'tool' object"
    );
    assert!(
        json["tool"]["name"].is_string(),
        "tool.name must be a string"
    );
    assert!(
        json["tool"]["version"].is_string(),
        "tool.version must be a string"
    );
}

// ── MAINT011-active-debug-code: Python fixture produces at least one finding ──

#[test]
fn python_active_debug_code_positive_fixture_has_maint011_finding() {
    let path = workspace_path("fixtures/python/active_debug_code/positive.py");
    let raw = zuit()
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

    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout must be valid JSON");
    let findings = json["findings"].as_array().expect("findings must be array");

    let has_maint011 = findings
        .iter()
        .any(|f| f["rule_id"].as_str() == Some("MAINT011-active-debug-code"));

    assert!(
        has_maint011,
        "python/active_debug_code/positive.py must produce at least one MAINT011-active-debug-code \
         finding; rule_ids present: {:?}",
        findings
            .iter()
            .filter_map(|f| f["rule_id"].as_str())
            .collect::<Vec<_>>()
    );
}

// ── MAINT013-empty-block: Python fixture produces at least one finding ────────

#[test]
fn python_empty_block_positive_fixture_has_maint013_finding() {
    let path = workspace_path("fixtures/python/empty_block/positive.py");
    let raw = zuit()
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

    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout must be valid JSON");
    let findings = json["findings"].as_array().expect("findings must be array");

    let has_maint013 = findings
        .iter()
        .any(|f| f["rule_id"].as_str() == Some("MAINT013-empty-block"));

    assert!(
        has_maint013,
        "python/empty_block/positive.py must produce at least one MAINT013-empty-block finding; \
         rule_ids present: {:?}",
        findings
            .iter()
            .filter_map(|f| f["rule_id"].as_str())
            .collect::<Vec<_>>()
    );
}

// ── SEC013-bind-all-interfaces: Python positive fixture produces at least one finding ──

#[test]
fn python_bind_all_interfaces_positive_fixture_has_sec013_finding() {
    let path = workspace_path("fixtures/python/bind_all_interfaces/positive.py");
    let raw = zuit()
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

    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout must be valid JSON");
    let findings = json["findings"].as_array().expect("findings must be array");

    let has_sec013 = findings
        .iter()
        .any(|f| f["rule_id"].as_str() == Some("SEC013-bind-all-interfaces"));

    assert!(
        has_sec013,
        "python/bind_all_interfaces/positive.py must produce at least one \
         SEC013-bind-all-interfaces finding; rule_ids present: {:?}",
        findings
            .iter()
            .filter_map(|f| f["rule_id"].as_str())
            .collect::<Vec<_>>()
    );
}

// ── MAINT014-commented-out-code: Python fixture produces at least one finding ─

#[test]
fn python_commented_code_positive_fixture_has_maint014_finding() {
    let path = workspace_path("fixtures/python/commented_code/positive.py");
    let raw = zuit()
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

    let json: serde_json::Value = serde_json::from_slice(&raw).expect("stdout must be valid JSON");
    let findings = json["findings"].as_array().expect("findings must be array");

    let has_maint014 = findings
        .iter()
        .any(|f| f["rule_id"].as_str() == Some("MAINT014-commented-out-code"));

    assert!(
        has_maint014,
        "python/commented_code/positive.py must produce at least one \
         MAINT014-commented-out-code finding; rule_ids present: {:?}",
        findings
            .iter()
            .filter_map(|f| f["rule_id"].as_str())
            .collect::<Vec<_>>()
    );
}
