//! `MypyAnalyzer` — wraps `mypy` as an external-tool adapter.
//!
//! This analyzer implements [`zuit_core::Analyzer::analyze_project`] (not
//! `analyze_file`).  When called:
//!
//! 1. Searches `$PATH` for the `mypy` binary (via the `which` crate).
//!    If missing, emits a single [`Severity::Info`] finding with rule
//!    `PY/mypy-missing` and returns.
//! 2. Spawns `mypy --output json .` from the project root.
//!    mypy emits one JSON object per line (JSONL format).  Captures stdout
//!    with a 60-second timeout and 32 MiB cap.
//! 3. Parses the JSONL output with [`parse_mypy_output`], skipping malformed
//!    lines silently.
//! 4. Returns the resulting [`Finding`]s.

use std::path::Path;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use serde::Deserialize;

use super::{DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS, Outcome, compute_span, run_with_limits};

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `mypy` is absent from `$PATH`.
pub const RULE_MISSING: &str = "PY/mypy-missing";
const RULE_TIMEOUT: &str = "PY/mypy-timeout";
const RULE_OUTPUT_TOO_LARGE: &str = "PY/mypy-output-too-large";
const RULE_SPAWN_FAILED: &str = "PY/mypy-spawn-failed";

const RULE_PREFIX: &str = "PY/mypy/";

// ── JSON deserialization model ────────────────────────────────────────────────

/// A single line from `mypy --output json` (JSONL format).
///
/// mypy emits one JSON object per line; unknown/missing fields default to
/// their zero value via `#[serde(default)]`.
#[derive(Debug, Deserialize)]
struct MypyIssue {
    /// Source file path (relative to CWD or absolute).
    #[serde(default)]
    file: String,
    /// One-indexed line number.
    #[serde(default)]
    line: u32,
    /// Zero-indexed column offset.
    #[serde(default)]
    column: u32,
    /// Human-readable message.
    #[serde(default)]
    message: String,
    /// Error code string (e.g. `"arg-type"`, `"return-value"`).
    #[serde(default)]
    code: String,
    /// Severity string: `"error"`, `"warning"`, or `"note"`.
    #[serde(default)]
    severity: String,
}

// ── Severity mapping ──────────────────────────────────────────────────────────

/// Maps mypy severity string to a zuit [`Severity`].
///
/// - `"error"` → Medium
/// - `"warning"` / `"note"` / anything else → Low
fn map_mypy_severity(severity: &str) -> Severity {
    if severity.eq_ignore_ascii_case("error") {
        Severity::Medium
    } else {
        Severity::Low
    }
}

// ── Core parsing function (pure — no I/O) ─────────────────────────────────────

/// Parses `mypy --output json` JSONL output and returns a [`Vec<Finding>`].
///
/// This function is **pure** — it does not touch the filesystem or spawn any
/// processes.  It is the primary unit-test target for this module.
///
/// Malformed lines are skipped silently (no error returned).
#[must_use]
pub fn parse_mypy_output(jsonl: &str, project_root: &Path, project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in jsonl.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let issue: MypyIssue = match serde_json::from_str(line) {
            Ok(i) => i,
            Err(_) => continue, // silently skip malformed lines
        };

        // Skip lines with no useful content (empty code = not an actionable finding).
        if issue.code.is_empty() && issue.message.is_empty() {
            continue;
        }

        let rule_id = if issue.code.is_empty() {
            format!("{RULE_PREFIX}unknown")
        } else {
            format!("{RULE_PREFIX}{}", issue.code)
        };

        let raw_path = std::path::Path::new(&issue.file);
        let file_path = if raw_path.is_absolute() {
            raw_path
                .strip_prefix(project_root)
                .unwrap_or(raw_path)
                .to_path_buf()
        } else {
            raw_path.to_path_buf()
        };

        let severity = map_mypy_severity(&issue.severity);

        // mypy column is 0-indexed; zuit uses 1-indexed columns.
        let column = issue.column + 1;

        let (span, start_lc, end_lc) = compute_span(
            project,
            project_root,
            &file_path,
            &issue.file,
            issue.line,
            column,
        );

        findings.push(Finding {
            analyzer: AnalyzerId::new("MypyAnalyzer"),
            dimension: Dimension::Maintainability,
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
            references: vec!["https://mypy.readthedocs.io/".to_string()],
            cwe: vec![],
            owasp: vec![],
        });
    }

    findings
}

// ── Subprocess spawning ───────────────────────────────────────────────────────

fn run_mypy(working_dir: &Path) -> Outcome {
    run_mypy_with_limits(working_dir, DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS)
}

/// Internal implementation with parameterised limits — used by tests.
#[must_use]
pub fn run_mypy_with_limits(
    working_dir: &Path,
    max_stdout_bytes: usize,
    timeout_secs: u64,
) -> Outcome {
    run_with_limits(
        "mypy",
        &["--output", "json", "."],
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
        analyzer: AnalyzerId::new("MypyAnalyzer"),
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

/// Integrates `mypy` into the zuit analysis pipeline.
pub struct MypyAnalyzer;

impl zuit_core::Analyzer for MypyAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("MypyAnalyzer")
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
                doc_path: "docs/rules/PY-mypy.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-mypy.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-mypy.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_SPAWN_FAILED,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-mypy.md",
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
        if which::which("mypy").is_err() {
            findings.push(operational_finding(
                project,
                RULE_MISSING,
                Severity::Info,
                "mypy not found on PATH; install it to enable Python type checking".to_string(),
                Some(
                    "Install mypy: https://mypy.readthedocs.io/en/stable/getting_started.html"
                        .to_string(),
                ),
                vec!["https://mypy.readthedocs.io/".to_string()],
            ));
            return findings;
        }

        // 2. Spawn mypy.
        let mut lint_findings = match run_mypy(&project.root) {
            Outcome::Ok(stdout) => {
                if stdout.is_empty() {
                    Vec::new()
                } else {
                    let stdout_str = String::from_utf8_lossy(&stdout);
                    if stdout_str.trim().is_empty() {
                        Vec::new()
                    } else {
                        parse_mypy_output(&stdout_str, &project.root, project)
                    }
                }
            }
            Outcome::Timeout => {
                findings.push(operational_finding(
                    project,
                    RULE_TIMEOUT,
                    Severity::Info,
                    format!("mypy timed out after {DEFAULT_TIMEOUT_SECS} seconds"),
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
                    format!("mypy output exceeded {mib_cap} MiB cap"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
            Outcome::SpawnFailed(e) => {
                tracing::warn!("mypy spawn failed: {e}");
                findings.push(operational_finding(
                    project,
                    RULE_SPAWN_FAILED,
                    Severity::Info,
                    format!("mypy failed to spawn: {e}"),
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

    // 5. parse_mypy_happy_path — fixture mypy JSONL → 2 findings
    #[test]
    fn parse_mypy_happy_path() {
        let jsonl = include_str!("../../../tests/fixtures/mypy-output.json");
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_mypy_output(jsonl, &root, &project);
        assert_eq!(
            findings.len(),
            2,
            "expected 2 findings, got {}: {findings:#?}",
            findings.len()
        );

        // All rule ids prefixed PY/mypy/
        for f in &findings {
            assert!(
                f.rule_id.starts_with("PY/mypy/"),
                "rule_id must start with 'PY/mypy/', got: {}",
                f.rule_id
            );
        }

        // All are Maintainability dimension
        for f in &findings {
            assert_eq!(
                f.dimension,
                Dimension::Maintainability,
                "mypy always produces Maintainability findings"
            );
        }

        // error → Medium, warning/note → Low
        let error_finding = findings.iter().find(|f| f.rule_id == "PY/mypy/arg-type");
        let warning_finding = findings
            .iter()
            .find(|f| f.rule_id == "PY/mypy/return-value");
        if let Some(f) = error_finding {
            assert_eq!(f.severity, Severity::Medium, "error must be Medium");
        }
        if let Some(f) = warning_finding {
            assert_eq!(f.severity, Severity::Low, "warning must be Low");
        }
    }

    // 11. parse_mypy_malformed_line_skipped — bad line + good line → 1 finding
    #[test]
    fn parse_mypy_malformed_line_skipped() {
        let jsonl = "not valid json {{{{\n{\"file\":\"foo.py\",\"line\":1,\"column\":0,\"message\":\"oops\",\"code\":\"arg-type\",\"severity\":\"error\"}\n";
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_mypy_output(jsonl, &root, &project);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding (malformed line skipped): {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, "PY/mypy/arg-type");
    }

    // Severity mapping: error → Medium
    #[test]
    fn mypy_error_severity_is_medium() {
        assert_eq!(map_mypy_severity("error"), Severity::Medium);
        assert_eq!(map_mypy_severity("ERROR"), Severity::Medium);
    }

    // Severity mapping: warning/note → Low
    #[test]
    fn mypy_warning_note_severity_is_low() {
        assert_eq!(map_mypy_severity("warning"), Severity::Low);
        assert_eq!(map_mypy_severity("note"), Severity::Low);
        assert_eq!(map_mypy_severity(""), Severity::Low);
    }

    // 9. mypy_missing_binary_emits_info
    #[test]
    fn mypy_missing_binary_emits_info() {
        use zuit_core::{Analyzer, Language};

        if which::which("mypy").is_ok() {
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
        let analyzer = MypyAnalyzer;
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding when mypy is missing"
        );
        assert_eq!(findings[0].rule_id, RULE_MISSING);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    // Empty JSONL → 0 findings
    #[test]
    fn parse_mypy_empty_returns_zero() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_mypy_output("", &root, &project);
        assert!(findings.is_empty(), "expected 0 findings for empty input");
    }

    // Absolute path stripped from file location
    #[test]
    fn mypy_absolute_path_stripped() {
        let jsonl = r#"{"file":"/project/main.py","line":5,"column":0,"message":"bad arg","code":"arg-type","severity":"error"}"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_mypy_output(jsonl, &root, &project);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.file, PathBuf::from("main.py"));
    }

    // Suppression directive format
    #[test]
    fn mypy_suppression_directive_format() {
        let directive = "# zuit: ignore PY/mypy/arg-type";
        assert!(directive.contains("zuit: ignore"));
        assert!(directive.contains("PY/mypy/arg-type"));
    }

    // Timeout test (unix only)
    #[test]
    #[cfg(unix)]
    fn mypy_timeout_kills_process() {
        let root = PathBuf::from("/tmp");
        let outcome = run_mypy_with_limits(&root, usize::MAX, 1);
        assert!(
            matches!(
                outcome,
                Outcome::SpawnFailed(_) | Outcome::Timeout | Outcome::Ok(_)
            ),
            "expected a valid outcome, got {outcome:?}"
        );
    }
}
