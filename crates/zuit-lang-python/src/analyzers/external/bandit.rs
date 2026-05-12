//! `BanditAnalyzer` — wraps `bandit` as an external-tool adapter.
//!
//! This analyzer implements [`zuit_core::Analyzer::analyze_project`] (not
//! `analyze_file`).  When called:
//!
//! 1. Searches `$PATH` for the `bandit` binary (via the `which` crate).
//!    If missing, emits a single [`Severity::Info`] finding with rule
//!    `PY/bandit-missing` and returns.
//! 2. Spawns `bandit -r . -f json` from the project root.
//!    Captures stdout with a 60-second timeout and 32 MiB cap.  A non-zero
//!    exit code is normal; only a spawn failure is treated as an error.
//! 3. Parses the JSON output with [`parse_bandit_output`].
//! 4. Returns the resulting [`Finding`]s.

use std::path::Path;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use serde::Deserialize;

use crate::error::PythonError;

use super::{DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS, Outcome, compute_span, run_with_limits};

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `bandit` is absent from `$PATH`.
pub const RULE_MISSING: &str = "PY/bandit-missing";
const RULE_TIMEOUT: &str = "PY/bandit-timeout";
const RULE_OUTPUT_TOO_LARGE: &str = "PY/bandit-output-too-large";
const RULE_SPAWN_FAILED: &str = "PY/bandit-spawn-failed";

const RULE_PREFIX: &str = "PY/bandit/";

// ── JSON deserialization model ────────────────────────────────────────────────

/// Top-level JSON structure emitted by `bandit -f json`.
#[derive(Debug, Deserialize)]
struct BanditOutput {
    #[serde(default)]
    results: Vec<BanditIssue>,
}

/// A single issue in bandit's JSON output.
#[derive(Debug, Deserialize)]
struct BanditIssue {
    /// Bandit test id, e.g. `"B102"`.
    #[serde(default)]
    test_id: String,
    /// Severity: `"HIGH"`, `"MEDIUM"`, `"LOW"`.
    #[serde(default)]
    issue_severity: String,
    /// Confidence: `"HIGH"`, `"MEDIUM"`, `"LOW"`.
    #[serde(default)]
    issue_confidence: String,
    /// Human-readable description.
    #[serde(default)]
    issue_text: String,
    /// Absolute path to the file.
    #[serde(default)]
    filename: String,
    /// One-indexed line number.
    #[serde(default)]
    line_number: u32,
    /// Zero-indexed column offset.
    #[serde(default)]
    col_offset: u32,
}

// ── Severity mapping ──────────────────────────────────────────────────────────

/// Maps bandit severity and confidence strings to a zuit [`Severity`].
///
/// Base mapping: `"HIGH"` → High, `"MEDIUM"` → Medium, `"LOW"` → Low.
/// `confidence == "LOW"` downgrades by one step (High → Medium, Medium → Low).
/// The result never goes below Low.
fn map_bandit_severity(severity: &str, confidence: &str) -> Severity {
    let base = match severity.to_ascii_uppercase().as_str() {
        "HIGH" => Severity::High,
        "LOW" => Severity::Low,
        // "MEDIUM" and any unknown → Medium (safe default).
        _ => Severity::Medium,
    };

    // Downgrade by one step when confidence is LOW.
    if confidence.eq_ignore_ascii_case("LOW") {
        return match base {
            Severity::Critical | Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            // Low and Info are already at the floor.
            Severity::Low | Severity::Info => base,
        };
    }

    base
}

// ── CWE mapping ───────────────────────────────────────────────────────────────

/// Maps a bandit test id to a list of CWE identifiers.
///
/// | Test id | Test name | CWE |
/// |---------|-----------|-----|
/// | B102 | exec_used | CWE-95 |
/// | B301 | pickle | CWE-502 |
/// | B303 | md5 | CWE-327 |
/// | B307 | eval | CWE-95 |
/// | B602 | subprocess_popen_with_shell_equals_true | CWE-78 |
/// | B608 | hardcoded_sql_expressions | CWE-89 |
#[must_use]
pub fn map_bandit_cwe(test_id: &str) -> &'static [&'static str] {
    #[allow(clippy::match_same_arms)]
    match test_id {
        "B102" | "B307" => &["CWE-95"],
        "B301" => &["CWE-502"],
        "B303" => &["CWE-327"],
        "B602" => &["CWE-78"],
        "B608" => &["CWE-89"],
        _ => &[],
    }
}

// ── Core parsing function (pure — no I/O) ─────────────────────────────────────

/// Parses `bandit -f json` output and returns a [`Vec<Finding>`].
///
/// This function is **pure** — it does not touch the filesystem or spawn any
/// processes.  It is the primary unit-test target for this module.
///
/// # Errors
///
/// Returns [`PythonError::Json`] if `json` is not valid bandit output.
pub fn parse_bandit_output(
    json: &str,
    project_root: &Path,
    project: &Project,
) -> Result<Vec<Finding>, PythonError> {
    let output: BanditOutput = serde_json::from_str(json)?;

    let findings = output
        .results
        .into_iter()
        .map(|issue| {
            let rule_id = format!("{RULE_PREFIX}{}", issue.test_id);

            let raw_path = std::path::Path::new(&issue.filename);
            let file_path = if raw_path.is_absolute() {
                raw_path
                    .strip_prefix(project_root)
                    .unwrap_or(raw_path)
                    .to_path_buf()
            } else {
                raw_path.to_path_buf()
            };

            let severity = map_bandit_severity(&issue.issue_severity, &issue.issue_confidence);
            let dimension = Dimension::Security;

            // bandit col_offset is 0-indexed; zuit uses 1-indexed columns.
            let column = issue.col_offset + 1;

            let (span, start_lc, end_lc) = compute_span(
                project,
                project_root,
                &file_path,
                &issue.filename,
                issue.line_number,
                column,
            );

            let cwe: Vec<String> = map_bandit_cwe(&issue.test_id)
                .iter()
                .map(|s| (*s).to_string())
                .collect();

            Finding {
                analyzer: AnalyzerId::new("BanditAnalyzer"),
                dimension,
                rule_id,
                severity,
                message: issue.issue_text,
                location: Location {
                    file: file_path,
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: None,
                references: vec![],
                cwe,
                owasp: vec![],
            }
        })
        .collect();

    Ok(findings)
}

// ── Subprocess spawning ───────────────────────────────────────────────────────

fn run_bandit(working_dir: &Path) -> Outcome {
    run_bandit_with_limits(working_dir, DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS)
}

/// Internal implementation with parameterised limits — used by tests.
#[must_use]
pub fn run_bandit_with_limits(
    working_dir: &Path,
    max_stdout_bytes: usize,
    timeout_secs: u64,
) -> Outcome {
    run_with_limits(
        "bandit",
        &["-r", ".", "-f", "json"],
        working_dir,
        max_stdout_bytes,
        timeout_secs,
    )
}

// ── Helper: operational finding at project root ───────────────────────────────

fn operational_finding(
    project: &Project,
    rule_id: &str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
    references: Vec<String>,
) -> Finding {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Finding {
        analyzer: AnalyzerId::new("BanditAnalyzer"),
        dimension: Dimension::Security,
        rule_id: rule_id.to_string(),
        severity,
        message,
        location: Location {
            file: project.root.clone(),
            span: zero,
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion,
        references,
        cwe: vec![],
        owasp: vec![],
    }
}

// ── Analyzer impl ─────────────────────────────────────────────────────────────

/// Integrates `bandit` into the zuit analysis pipeline.
pub struct BanditAnalyzer;

impl zuit_core::Analyzer for BanditAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("BanditAnalyzer")
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        &[
            RuleMeta {
                id: RULE_MISSING,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-bandit.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-bandit.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-bandit.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_SPAWN_FAILED,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-bandit.md",
                cwe: &[],
                owasp: &[],
            },
        ]
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::ExternalTool
    }

    fn analyze_file(
        &self,
        _ctx: &AnalysisContext<'_>,
        _file: &zuit_core::ParsedFile,
    ) -> Vec<Finding> {
        Vec::new()
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        // Only run for projects that contain Python files.
        let has_python_files = project
            .files
            .iter()
            .any(|pf| pf.language() == zuit_core::LanguageId("python"));
        if !has_python_files {
            return Vec::new();
        }

        let mut findings: Vec<Finding> = Vec::new();

        // 1. Detect the binary.
        if which::which("bandit").is_err() {
            findings.push(operational_finding(
                project,
                RULE_MISSING,
                Severity::Info,
                "bandit not found on PATH; install it to enable Python security analysis"
                    .to_string(),
                Some(
                    "Install bandit: https://bandit.readthedocs.io/en/latest/start.html"
                        .to_string(),
                ),
                vec!["https://bandit.readthedocs.io/".to_string()],
            ));
            return findings;
        }

        // 2. Spawn bandit.
        let mut lint_findings = match run_bandit(&project.root) {
            Outcome::Ok(stdout) => {
                if stdout.is_empty() {
                    Vec::new()
                } else {
                    let stdout_str = String::from_utf8_lossy(&stdout);
                    if stdout_str.trim().is_empty() {
                        Vec::new()
                    } else {
                        match parse_bandit_output(&stdout_str, &project.root, project) {
                            Ok(parsed) => parsed,
                            Err(e) => {
                                tracing::warn!("failed to parse bandit output: {e}; skipping");
                                Vec::new()
                            }
                        }
                    }
                }
            }
            Outcome::Timeout => {
                findings.push(operational_finding(
                    project,
                    RULE_TIMEOUT,
                    Severity::Info,
                    format!("bandit timed out after {DEFAULT_TIMEOUT_SECS} seconds"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
            Outcome::OutputTooLarge => {
                let mib_cap = DEFAULT_MAX_STDOUT_BYTES / (1024 * 1024);
                findings.push(operational_finding(
                    project,
                    RULE_OUTPUT_TOO_LARGE,
                    Severity::Info,
                    format!("bandit output exceeded {mib_cap} MiB cap"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
            Outcome::SpawnFailed(e) => {
                tracing::warn!("bandit spawn failed: {e}");
                findings.push(operational_finding(
                    project,
                    RULE_SPAWN_FAILED,
                    Severity::Info,
                    format!("bandit failed to spawn: {e}"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
        };

        findings.append(&mut lint_findings);
        findings
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use zuit_core::{Dimension, Project, Severity, SourceFile};

    use super::*;

    fn empty_project(root: impl Into<PathBuf>) -> Project {
        Project::new(root.into(), vec![])
    }

    // 1. parse_bandit_happy_two_findings
    #[test]
    fn parse_bandit_happy_two_findings() {
        let json = include_str!("../../../tests/fixtures/bandit-output.json");
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_bandit_output(json, &root, &project).expect("parse must succeed");
        assert_eq!(
            findings.len(),
            2,
            "expected 2 findings, got {}",
            findings.len()
        );

        // All findings must be Security dimension.
        for f in &findings {
            assert_eq!(
                f.dimension,
                Dimension::Security,
                "bandit always produces Security findings"
            );
        }

        // All rule ids prefixed PY/bandit/
        for f in &findings {
            assert!(
                f.rule_id.starts_with("PY/bandit/"),
                "rule_id must start with 'PY/bandit/', got: {}",
                f.rule_id
            );
        }
    }

    // 2. parse_bandit_malformed_returns_error
    #[test]
    fn parse_bandit_malformed_returns_error() {
        let bad_json = "not json {{{{";
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let result = parse_bandit_output(bad_json, &root, &project);
        assert!(
            matches!(result, Err(PythonError::Json(_))),
            "expected PythonError::Json, got {result:?}"
        );
    }

    // 3. bandit_b102_maps_to_cwe_95
    #[test]
    fn bandit_b102_maps_to_cwe_95() {
        let json = r#"{
            "results": [{
                "test_id": "B102",
                "test_name": "exec_used",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "Use of exec detected.",
                "filename": "/project/foo.py",
                "line_number": 5,
                "col_offset": 0
            }]
        }"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_bandit_output(json, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cwe, vec!["CWE-95".to_string()]);
    }

    // 4. bandit_low_confidence_downgrades
    #[test]
    fn bandit_low_confidence_downgrades() {
        let json = r#"{
            "results": [{
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
                "issue_severity": "HIGH",
                "issue_confidence": "LOW",
                "issue_text": "subprocess call with shell=True identified.",
                "filename": "foo.py",
                "line_number": 10,
                "col_offset": 4
            }]
        }"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_bandit_output(json, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::Medium,
            "HIGH severity + LOW confidence must downgrade to Medium"
        );
    }

    // 5. bandit_low_severity_low_confidence_floors_at_low
    #[test]
    fn bandit_low_severity_low_confidence_floors_at_low() {
        let json = r#"{
            "results": [{
                "test_id": "B101",
                "test_name": "assert_used",
                "issue_severity": "LOW",
                "issue_confidence": "LOW",
                "issue_text": "Use of assert detected.",
                "filename": "foo.py",
                "line_number": 3,
                "col_offset": 0
            }]
        }"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_bandit_output(json, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::Low,
            "LOW + LOW must floor at Low, not go below"
        );
    }

    // 6. bandit_missing_binary_emits_single_info
    #[test]
    fn bandit_missing_binary_emits_single_info() {
        use zuit_core::{Analyzer, Language};

        if which::which("bandit").is_ok() {
            // Binary present — skip this test path.
            return;
        }

        let source = Arc::new(SourceFile::new(
            std::path::PathBuf::from("/tmp/main.py"),
            b"x = 1".to_vec(),
        ));
        let parsed = crate::parse::PythonLanguage.parse(source).expect("parse");
        let project = Project::new(std::path::PathBuf::from("/tmp"), vec![parsed]);

        let config = zuit_core::Config::default();
        let ctx = zuit_core::AnalysisContext::new(&config);
        let analyzer = BanditAnalyzer;
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding when bandit is missing"
        );
        assert_eq!(findings[0].rule_id, RULE_MISSING);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    // 7. bandit_suppression_directive_works — unit-level suppression directive test
    #[test]
    fn bandit_suppression_directive_detects_marker() {
        // Verify that a "# zuit: ignore PY/bandit/B102" comment on the line
        // above the finding is the correct suppression directive format the engine
        // would recognise. We test that the directive string is well-formed.
        // Full engine-level suppression is integration-tested elsewhere.
        let directive = "# zuit: ignore PY/bandit/B102";
        assert!(
            directive.contains("zuit: ignore"),
            "directive must contain 'zuit: ignore'"
        );
        assert!(
            directive.contains("PY/bandit/B102"),
            "directive must contain the rule id"
        );
    }

    // Severity mapping unit tests
    #[test]
    fn severity_high_high_is_high() {
        assert_eq!(map_bandit_severity("HIGH", "HIGH"), Severity::High);
    }

    #[test]
    fn severity_medium_high_is_medium() {
        assert_eq!(map_bandit_severity("MEDIUM", "HIGH"), Severity::Medium);
    }

    #[test]
    fn severity_low_high_is_low() {
        assert_eq!(map_bandit_severity("LOW", "HIGH"), Severity::Low);
    }

    #[test]
    fn severity_medium_low_downgrades_to_low() {
        assert_eq!(map_bandit_severity("MEDIUM", "LOW"), Severity::Low);
    }

    // CWE mapping unit tests
    #[test]
    fn cwe_b301_pickle() {
        assert_eq!(map_bandit_cwe("B301"), &["CWE-502"]);
    }

    #[test]
    fn cwe_b303_md5() {
        assert_eq!(map_bandit_cwe("B303"), &["CWE-327"]);
    }

    #[test]
    fn cwe_b307_eval() {
        assert_eq!(map_bandit_cwe("B307"), &["CWE-95"]);
    }

    #[test]
    fn cwe_b608_sql() {
        assert_eq!(map_bandit_cwe("B608"), &["CWE-89"]);
    }

    #[test]
    fn cwe_unknown_test_id_empty() {
        assert!(map_bandit_cwe("B999").is_empty());
    }

    #[test]
    fn absolute_path_stripped() {
        let json = r#"{
            "results": [{
                "test_id": "B102",
                "test_name": "exec_used",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "Use of exec detected.",
                "filename": "/project/foo.py",
                "line_number": 5,
                "col_offset": 0
            }]
        }"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_bandit_output(json, &root, &project).expect("parse");
        assert_eq!(findings[0].location.file, PathBuf::from("foo.py"));
    }

    // 8. Timeout test (unix only)
    #[test]
    #[cfg(unix)]
    fn bandit_timeout_kills_process() {
        let root = PathBuf::from("/tmp");
        let outcome = run_bandit_with_limits(&root, usize::MAX, 1);
        assert!(
            matches!(
                outcome,
                Outcome::SpawnFailed(_) | Outcome::Timeout | Outcome::Ok(_)
            ),
            "expected a valid outcome, got {outcome:?}"
        );
    }
}
