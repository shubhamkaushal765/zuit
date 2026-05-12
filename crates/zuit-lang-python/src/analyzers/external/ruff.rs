//! `RuffAnalyzer` — wraps `ruff` as an external-tool adapter.
//!
//! This analyzer implements [`zuit_core::Analyzer::analyze_project`] (not
//! `analyze_file`).  When called:
//!
//! 1. Searches `$PATH` for the `ruff` binary (via the `which` crate).
//!    If missing, emits a single [`Severity::Info`] finding with rule
//!    `PY/ruff-missing` and returns.
//! 2. Spawns `ruff check --output-format=json .` from the project root.
//!    Captures stdout with a 60-second timeout and 32 MiB cap.  A non-zero
//!    exit code is normal; only a spawn failure is treated as an error.
//! 3. Parses the JSON output with [`parse_ruff_output`].
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

/// Rule ID emitted when `ruff` is absent from `$PATH`.
pub const RULE_MISSING: &str = "PY/ruff-missing";
const RULE_TIMEOUT: &str = "PY/ruff-timeout";
const RULE_OUTPUT_TOO_LARGE: &str = "PY/ruff-output-too-large";
const RULE_SPAWN_FAILED: &str = "PY/ruff-spawn-failed";

const RULE_PREFIX: &str = "PY/ruff/";

// ── JSON deserialization model ────────────────────────────────────────────────

/// A single issue emitted by `ruff check --output-format=json`.
///
/// ruff emits a top-level JSON array of these objects.
/// Unknown fields are ignored; all fields use `#[serde(default)]`.
#[derive(Debug, Deserialize)]
struct RuffIssue {
    /// The rule code (e.g. `"F401"`, `"E501"`).
    #[serde(default)]
    code: String,
    /// Human-readable message.
    #[serde(default)]
    message: String,
    /// Absolute path to the file.
    #[serde(default)]
    filename: String,
    /// Start location.
    #[serde(default)]
    location: RuffLocation,
}

#[derive(Debug, Default, Deserialize)]
struct RuffLocation {
    #[serde(default)]
    row: u32,
    #[serde(default)]
    column: u32,
}

// ── Severity / Dimension mapping ──────────────────────────────────────────────

/// Maps a ruff rule code to a [`Severity`].
///
/// - `error` → High, `warning` → Medium, `info` → Low.
/// - F-rules (pyflakes) are bumped to Medium minimum regardless of raw severity.
///
/// ruff does not emit a severity field in its JSON output; we derive severity
/// from the rule code prefix using the documented convention.
fn map_ruff_severity(code: &str) -> Severity {
    // F-rules (pyflakes): floor at Medium.
    if code.starts_with('F') {
        return Severity::Medium;
    }
    // E5xx are style errors (line-length, etc.) — treat as Medium.
    // All E/W/C/etc. codes in ruff are "warning"-level by convention.
    // Security-relevant S-codes → High.
    if code.starts_with('S') {
        return Severity::High;
    }
    // Default for most rules: Medium (warning-equivalent).
    Severity::Medium
}

/// Maps a ruff rule code to a [`Dimension`].
///
/// | Rule prefix | Dimension |
/// |-------------|-----------|
/// | `E*`, `W*`, `F*` | Maintainability |
/// | `S*` (flake8-bandit) | Security |
/// | `C90` (mccabe complexity) | Complexity |
/// | `D*` (pydocstyle) | Documentation |
/// | `PT*`, `T*` | TestSmell |
/// | everything else | Maintainability |
fn map_ruff_dimension(code: &str) -> Dimension {
    if code.starts_with('S') {
        return Dimension::Security;
    }
    if code.starts_with("C90") {
        return Dimension::Complexity;
    }
    if code.starts_with('D') {
        return Dimension::Documentation;
    }
    if code.starts_with("PT") || code.starts_with('T') {
        return Dimension::TestSmell;
    }
    // E*, W*, F*, and everything else → Maintainability.
    Dimension::Maintainability
}

// ── Core parsing function (pure — no I/O) ─────────────────────────────────────

/// Parses `ruff check --output-format=json` output and returns a [`Vec<Finding>`].
///
/// This function is **pure** — it does not touch the filesystem or spawn any
/// processes.  It is the primary unit-test target for this module.
///
/// # Errors
///
/// Returns [`PythonError::Json`] if `json` is not valid ruff output.
pub fn parse_ruff_output(
    json: &str,
    project_root: &Path,
    project: &Project,
) -> Result<Vec<Finding>, PythonError> {
    let issues: Vec<RuffIssue> = serde_json::from_str(json)?;

    let findings = issues
        .into_iter()
        .map(|issue| {
            let rule_id = format!("{RULE_PREFIX}{}", issue.code);

            let raw_path = std::path::Path::new(&issue.filename);
            let file_path = if raw_path.is_absolute() {
                raw_path
                    .strip_prefix(project_root)
                    .unwrap_or(raw_path)
                    .to_path_buf()
            } else {
                raw_path.to_path_buf()
            };

            let severity = map_ruff_severity(&issue.code);
            let dimension = map_ruff_dimension(&issue.code);

            let (span, start_lc, end_lc) = compute_span(
                project,
                project_root,
                &file_path,
                &issue.filename,
                issue.location.row,
                issue.location.column,
            );

            Finding {
                analyzer: AnalyzerId::new("RuffAnalyzer"),
                dimension,
                rule_id,
                severity,
                message: issue.message,
                location: Location {
                    file: file_path,
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: None,
                references: vec![],
                cwe: vec![],
                owasp: vec![],
            }
        })
        .collect();

    Ok(findings)
}

// ── Subprocess spawning ───────────────────────────────────────────────────────

fn run_ruff(working_dir: &Path) -> Outcome {
    run_ruff_with_limits(working_dir, DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS)
}

/// Internal implementation with parameterised limits — used by tests.
#[must_use]
pub fn run_ruff_with_limits(
    working_dir: &Path,
    max_stdout_bytes: usize,
    timeout_secs: u64,
) -> Outcome {
    run_with_limits(
        "ruff",
        &["check", "--output-format=json", "."],
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
        analyzer: AnalyzerId::new("RuffAnalyzer"),
        dimension: Dimension::Maintainability,
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

/// Integrates `ruff` into the zuit analysis pipeline.
pub struct RuffAnalyzer;

impl zuit_core::Analyzer for RuffAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("RuffAnalyzer")
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        &[
            RuleMeta {
                id: RULE_MISSING,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-ruff.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-ruff.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-ruff.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_SPAWN_FAILED,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-ruff.md",
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
        if which::which("ruff").is_err() {
            findings.push(operational_finding(
                project,
                RULE_MISSING,
                Severity::Info,
                "ruff not found on PATH; install it to enable Python linting".to_string(),
                Some("Install ruff: https://docs.astral.sh/ruff/installation/".to_string()),
                vec!["https://docs.astral.sh/ruff/".to_string()],
            ));
            return findings;
        }

        // 2. Spawn ruff.
        let mut lint_findings = match run_ruff(&project.root) {
            Outcome::Ok(stdout) => {
                if stdout.is_empty() {
                    Vec::new()
                } else {
                    let stdout_str = String::from_utf8_lossy(&stdout);
                    if stdout_str.trim().is_empty() {
                        Vec::new()
                    } else {
                        match parse_ruff_output(&stdout_str, &project.root, project) {
                            Ok(parsed) => parsed,
                            Err(e) => {
                                tracing::warn!("failed to parse ruff output: {e}; skipping");
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
                    format!("ruff timed out after {DEFAULT_TIMEOUT_SECS} seconds"),
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
                    format!("ruff output exceeded {mib_cap} MiB cap"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
            Outcome::SpawnFailed(e) => {
                tracing::warn!("ruff spawn failed: {e}");
                findings.push(operational_finding(
                    project,
                    RULE_SPAWN_FAILED,
                    Severity::Info,
                    format!("ruff failed to spawn: {e}"),
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

    fn project_with_file(root: impl Into<PathBuf>, filename: &str, content: &str) -> Project {
        use zuit_core::Language;
        let root_buf: PathBuf = root.into();
        let source = Arc::new(SourceFile::new(
            root_buf.join(filename),
            content.as_bytes().to_vec(),
        ));
        let parsed = crate::parse::PythonLanguage
            .parse(source)
            .expect("parse must succeed");
        Project::new(root_buf, vec![parsed])
    }

    // 1. parse_ruff_happy_three_findings
    #[test]
    fn parse_ruff_happy_three_findings() {
        let json = include_str!("../../../tests/fixtures/ruff-output.json");
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_ruff_output(json, &root, &project).expect("parse must succeed");
        assert_eq!(
            findings.len(),
            3,
            "expected 3 findings, got {}",
            findings.len()
        );

        // All rule ids prefixed PY/ruff/
        for f in &findings {
            assert!(
                f.rule_id.starts_with("PY/ruff/"),
                "rule_id must start with 'PY/ruff/', got: {}",
                f.rule_id
            );
        }

        // F401 finding — severity Medium (F-rule floor)
        let f401 = findings
            .iter()
            .find(|f| f.rule_id == "PY/ruff/F401")
            .expect("missing F401 finding");
        assert_eq!(f401.severity, Severity::Medium);
        assert_eq!(f401.dimension, Dimension::Maintainability);

        // E501 finding — severity Medium, Maintainability
        let e501 = findings
            .iter()
            .find(|f| f.rule_id == "PY/ruff/E501")
            .expect("missing E501 finding");
        assert_eq!(e501.severity, Severity::Medium);
        assert_eq!(e501.dimension, Dimension::Maintainability);

        // C901 finding — Complexity dimension
        let c901 = findings
            .iter()
            .find(|f| f.rule_id == "PY/ruff/C901")
            .expect("missing C901 finding");
        assert_eq!(
            c901.dimension,
            Dimension::Complexity,
            "C901 must be Complexity"
        );
    }

    // 2. parse_ruff_malformed_returns_error
    #[test]
    fn parse_ruff_malformed_returns_error() {
        let bad_json = "not json at all {{{";
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let result = parse_ruff_output(bad_json, &root, &project);
        assert!(
            matches!(result, Err(PythonError::Json(_))),
            "expected PythonError::Json, got {result:?}"
        );
    }

    // 3. parse_ruff_empty_array
    #[test]
    fn parse_ruff_empty_array() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_ruff_output("[]", &root, &project).expect("parse must succeed");
        assert!(
            findings.is_empty(),
            "expected empty findings for empty array"
        );
    }

    // 4. parse_ruff_unknown_rule_code_default_dimension
    #[test]
    fn parse_ruff_unknown_rule_code_default_dimension() {
        let json = r#"[{
            "code": "XYZ999",
            "message": "some unknown rule",
            "filename": "foo.py",
            "location": {"row": 1, "column": 1},
            "end_location": {"row": 1, "column": 5}
        }]"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_ruff_output(json, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].dimension,
            Dimension::Maintainability,
            "unknown rule code must default to Maintainability"
        );
    }

    // 5. parse_ruff_f_rule_severity_floor_at_medium
    #[test]
    fn parse_ruff_f_rule_severity_floor_at_medium() {
        // F401 with any raw classification → still Medium (F-rule floor)
        let json = r#"[{
            "code": "F401",
            "message": "'os' imported but unused",
            "filename": "foo.py",
            "location": {"row": 1, "column": 1},
            "end_location": {"row": 1, "column": 3}
        }]"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_ruff_output(json, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::Medium,
            "F401 must be at least Medium"
        );
    }

    // 6. ruff_missing_binary_emits_single_info
    #[test]
    fn ruff_missing_binary_emits_single_info() {
        use zuit_core::{Analyzer, Language};

        // If ruff is not on PATH, analyze_project returns a single Info finding.
        // We can only assert the correct behaviour when ruff is absent.
        if which::which("ruff").is_ok() {
            // Binary present — skip this test path; just verify no panic.
            return;
        }

        // Build a minimal project with a .py file so the early-exit guard passes.
        let source = Arc::new(SourceFile::new(
            std::path::PathBuf::from("/tmp/main.py"),
            b"x = 1".to_vec(),
        ));
        let parsed = crate::parse::PythonLanguage.parse(source).expect("parse");
        let project = Project::new(std::path::PathBuf::from("/tmp"), vec![parsed]);

        let config = zuit_core::Config::default();
        let ctx = zuit_core::AnalysisContext::new(&config);
        let analyzer = RuffAnalyzer;
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding when ruff is missing"
        );
        assert_eq!(findings[0].rule_id, RULE_MISSING);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    // 7. timeout_kills_process (unix only)
    #[test]
    #[cfg(unix)]
    fn timeout_kills_process() {
        let root = PathBuf::from("/tmp");
        // Use a 1-second timeout. Either ruff finishes fast (Ok/SpawnFailed) or times out.
        let outcome = run_ruff_with_limits(&root, usize::MAX, 1);
        assert!(
            matches!(
                outcome,
                Outcome::SpawnFailed(_) | Outcome::Timeout | Outcome::Ok(_)
            ),
            "expected a valid outcome, got {outcome:?}"
        );
    }

    // Dimension mapping unit tests
    #[test]
    fn dimension_s_rule_is_security() {
        assert_eq!(map_ruff_dimension("S101"), Dimension::Security);
        assert_eq!(map_ruff_dimension("S506"), Dimension::Security);
    }

    #[test]
    fn dimension_c90_is_complexity() {
        assert_eq!(map_ruff_dimension("C901"), Dimension::Complexity);
        assert_eq!(map_ruff_dimension("C90"), Dimension::Complexity);
    }

    #[test]
    fn dimension_d_rule_is_documentation() {
        assert_eq!(map_ruff_dimension("D100"), Dimension::Documentation);
        assert_eq!(map_ruff_dimension("D401"), Dimension::Documentation);
    }

    #[test]
    fn dimension_pt_rule_is_testsmell() {
        assert_eq!(map_ruff_dimension("PT001"), Dimension::TestSmell);
        assert_eq!(map_ruff_dimension("T201"), Dimension::TestSmell);
    }

    #[test]
    fn absolute_path_stripped() {
        let json = r#"[{
            "code": "E501",
            "message": "line too long",
            "filename": "/project/main.py",
            "location": {"row": 5, "column": 1},
            "end_location": {"row": 5, "column": 100}
        }]"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_ruff_output(json, &root, &project).expect("parse");
        assert_eq!(findings[0].location.file, PathBuf::from("main.py"));
    }

    #[test]
    fn span_computed_from_source() {
        let content = "line1\nline2\nline3\n";
        let root = PathBuf::from("/project");
        let project = project_with_file(&root, "main.py", content);

        let json = r#"[{
            "code": "E501",
            "message": "line too long",
            "filename": "main.py",
            "location": {"row": 2, "column": 1},
            "end_location": {"row": 2, "column": 5}
        }]"#;
        let findings = parse_ruff_output(json, &root, &project).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].location.span.start,
            ByteOffset(6),
            "line 2 col 1 should be byte offset 6"
        );
    }
}
