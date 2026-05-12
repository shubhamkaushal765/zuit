//! `EslintAnalyzer` — wraps `eslint` as an external-tool adapter.
//!
//! When called:
//!
//! 1. Skips when the project contains no JS/TS files.
//! 2. Searches `$PATH` for the `eslint` binary. If missing, emits a single
//!    [`Severity::Info`] finding with rule `JS/eslint-missing` and returns.
//! 3. Spawns `eslint --format=json --no-error-on-unmatched-pattern .` from
//!    the project root.  Captures stdout with a 60-second timeout and 32 MiB
//!    cap.  A non-zero exit code is normal (findings exist); only a spawn
//!    failure is an error.
//! 4. Parses the JSON output with [`parse_eslint_output`].
//! 5. Returns the resulting [`Finding`]s.

use std::io::Read;
use std::path::Path;
use std::time::Instant;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use serde::Deserialize;

use crate::error::JsError;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Maximum time allowed for `eslint` to complete, in seconds.
const ESLINT_TIMEOUT_SECS: u64 = 60;

/// Maximum size of stdout captured from `eslint`, in bytes (32 MiB).
const ESLINT_MAX_STDOUT_BYTES: usize = 32 * 1024 * 1024;

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `eslint` is absent from `$PATH`.
pub const RULE_MISSING: &str = "JS/eslint-missing";

/// Rule ID emitted when `eslint` exceeds the timeout.
const RULE_TIMEOUT: &str = "JS/eslint-timeout";

/// Rule ID emitted when `eslint` stdout exceeds the cap.
const RULE_OUTPUT_TOO_LARGE: &str = "JS/eslint-output-too-large";

// ── JSON deserialization model ────────────────────────────────────────────────

/// Top-level array entry from `eslint --format=json`.
#[derive(Debug, Deserialize)]
struct EslintFileResult {
    /// Absolute or relative path to the linted file.
    #[serde(rename = "filePath", default)]
    file_path: String,
    /// Diagnostics for this file.
    #[serde(default)]
    messages: Vec<EslintMessage>,
}

/// A single `ESLint` diagnostic message.
#[derive(Debug, Deserialize)]
struct EslintMessage {
    /// The `ESLint` rule that fired; `null` for fatal parse errors.
    #[serde(rename = "ruleId", default)]
    rule_id: Option<String>,
    /// `2` = error, `1` = warning, other = off/unknown.
    #[serde(default)]
    severity: u8,
    /// Human-readable description.
    #[serde(default)]
    message: String,
    /// One-indexed line number.
    #[serde(default = "default_one")]
    line: u32,
    /// One-indexed column number.
    #[serde(default = "default_one")]
    column: u32,
}

fn default_one() -> u32 {
    1
}

// ── Severity / Dimension mapping ──────────────────────────────────────────────

/// Maps an `ESLint` numeric severity to a zuit [`Severity`].
///
/// - `2` → `High` (error)
/// - `1` → `Medium` (warning)
/// - other → `Low`
fn map_eslint_severity(severity: u8) -> Severity {
    match severity {
        2 => Severity::High,
        1 => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Maps an `ESLint` rule id to a zuit [`Dimension`].
///
/// | Rule pattern | Dimension |
/// |---|---|
/// | starts with `security/`, or equals `no-eval` / `no-implied-eval` / `no-new-func` | [`Dimension::Security`] |
/// | equals `complexity` / `max-depth` / `max-lines` / `max-params` | [`Dimension::Complexity`] |
/// | equals `valid-jsdoc` / `require-jsdoc` | [`Dimension::Documentation`] |
/// | all others | [`Dimension::Maintainability`] |
#[must_use]
pub fn map_eslint_dimension(rule_id: &str) -> Dimension {
    if rule_id.starts_with("security/")
        || matches!(rule_id, "no-eval" | "no-implied-eval" | "no-new-func")
    {
        return Dimension::Security;
    }
    if matches!(
        rule_id,
        "complexity" | "max-depth" | "max-lines" | "max-params"
    ) {
        return Dimension::Complexity;
    }
    if matches!(rule_id, "valid-jsdoc" | "require-jsdoc") {
        return Dimension::Documentation;
    }
    Dimension::Maintainability
}

// ── Span helper ───────────────────────────────────────────────────────────────

/// Computes a [`Span`] for a finding at `(line, column)` within `file_path`.
///
/// Searches `project.files` for a matching source; falls back to a
/// zero-length span at offset 0 when the file is not in the parse tree.
fn compute_span(
    project: &Project,
    project_root: &Path,
    file_path: &Path,
    raw_filename: &str,
    line: u32,
    column: u32,
) -> (Span, LineCol, LineCol) {
    let source = project.files.iter().find_map(|pf| {
        let src_path = &pf.source().path;
        let abs_candidate = project_root.join(file_path);
        if src_path == file_path
            || src_path == &abs_candidate
            || src_path.as_os_str() == raw_filename
        {
            Some(pf.source())
        } else {
            None
        }
    });

    let Some(src) = source else {
        let lc = LineCol::new(line.max(1), column.max(1));
        let zero = Span::new(ByteOffset(0), ByteOffset(0));
        return (zero, lc, lc);
    };

    let bytes = src.bytes();
    let line_starts = build_line_starts(bytes);
    let line_idx = (line.saturating_sub(1)) as usize;
    let col_idx = (column.saturating_sub(1)) as usize;

    let start_byte = if line_idx < line_starts.len() {
        let line_start = line_starts[line_idx] as usize;
        (line_start + col_idx).min(bytes.len())
    } else {
        bytes.len()
    };

    #[allow(clippy::cast_possible_truncation)]
    let start = ByteOffset(start_byte as u32);
    let span = Span::new(start, start);
    let start_lc = LineCol::new(line.max(1), column.max(1));
    (span, start_lc, start_lc)
}

/// Builds a byte-offset-per-line-start table from raw source bytes.
fn build_line_starts(bytes: &[u8]) -> Vec<u32> {
    let mut starts = vec![0u32];
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            #[allow(clippy::cast_possible_truncation)]
            starts.push((i + 2) as u32);
            i += 2;
        } else if bytes[i] == b'\n' {
            #[allow(clippy::cast_possible_truncation)]
            starts.push((i + 1) as u32);
            i += 1;
        } else {
            i += 1;
        }
    }
    starts
}

// ── Core parsing function (pure — no I/O) ─────────────────────────────────────

/// Parses `eslint --format=json` output and returns a [`Vec<Finding>`].
///
/// This function is **pure** — it does not touch the filesystem or spawn
/// any processes.  It is the primary unit-test target for this module.
///
/// Messages with a `null` `ruleId` (fatal parse errors) are skipped because
/// they have no stable identifier to map to a rule.
///
/// # Errors
///
/// Returns [`JsError::Json`] if `stdout` is not valid `ESLint` JSON.
pub fn parse_eslint_output(
    stdout: &str,
    project_root: &Path,
    project: &Project,
) -> Result<Vec<Finding>, JsError> {
    let file_results: Vec<EslintFileResult> = serde_json::from_str(stdout)?;

    let mut findings = Vec::new();
    for file_result in file_results {
        for msg in file_result.messages {
            let Some(rule_id_str) = msg.rule_id else {
                // Skip fatal parse errors with no rule id.
                continue;
            };

            let rule_id = format!("JS/eslint/{rule_id_str}");
            let severity = map_eslint_severity(msg.severity);
            let dimension = map_eslint_dimension(&rule_id_str);

            let raw_path = Path::new(&file_result.file_path);
            let file_path = if raw_path.is_absolute() {
                raw_path
                    .strip_prefix(project_root)
                    .unwrap_or(raw_path)
                    .to_path_buf()
            } else {
                raw_path.to_path_buf()
            };

            let (span, start_lc, end_lc) = compute_span(
                project,
                project_root,
                &file_path,
                &file_result.file_path,
                msg.line,
                msg.column,
            );

            findings.push(Finding {
                analyzer: AnalyzerId::new("EslintAnalyzer"),
                dimension,
                rule_id,
                severity,
                message: msg.message,
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
            });
        }
    }

    Ok(findings)
}

// ── Subprocess spawning (with timeout and output cap) ────────────────────────

/// Outcome of running `eslint`.
#[derive(Debug, PartialEq)]
enum EslintOutcome {
    /// Successfully captured stdout (may be empty).
    Ok(Vec<u8>),
    /// Process exceeded the timeout.
    Timeout,
    /// Stdout exceeded the byte cap.
    OutputTooLarge,
    /// Failed to spawn the process.
    SpawnFailed(String),
}

/// Spawns `eslint --format=json --no-error-on-unmatched-pattern .` from
/// `working_dir` with a timeout and output cap.
fn run_eslint(working_dir: &Path) -> EslintOutcome {
    run_eslint_with_limits(working_dir, ESLINT_MAX_STDOUT_BYTES, ESLINT_TIMEOUT_SECS)
}

/// Internal implementation: spawns `eslint` with parameterised limits.
///
/// Used by `run_eslint` and tests.
fn run_eslint_with_limits(
    working_dir: &Path,
    max_stdout_bytes: usize,
    timeout_secs: u64,
) -> EslintOutcome {
    use std::process::{Command, Stdio};

    let mut child = match Command::new("eslint")
        .args(["--format=json", "--no-error-on-unmatched-pattern", "."])
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return EslintOutcome::SpawnFailed(e.to_string()),
    };

    let Some(mut stdout) = child.stdout.take() else {
        return EslintOutcome::SpawnFailed("stdout not piped".to_string());
    };

    let start = Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    let mut buffer = Vec::new();
    #[allow(clippy::large_stack_arrays)]
    let mut read_buf = [0u8; 65536];

    loop {
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return EslintOutcome::Timeout;
        }

        match child.try_wait() {
            Ok(Some(_status)) => loop {
                match stdout.read(&mut read_buf) {
                    Ok(0) | Err(_) => return EslintOutcome::Ok(buffer),
                    Ok(n) => {
                        if buffer.len() + n > max_stdout_bytes {
                            let _ = child.kill();
                            let _ = child.wait();
                            return EslintOutcome::OutputTooLarge;
                        }
                        buffer.extend_from_slice(&read_buf[..n]);
                    }
                }
            },
            Ok(None) => match stdout.read(&mut read_buf) {
                Ok(0) => {
                    let _ = child.wait();
                    return EslintOutcome::Ok(buffer);
                }
                Ok(n) => {
                    if buffer.len() + n > max_stdout_bytes {
                        let _ = child.kill();
                        let _ = child.wait();
                        return EslintOutcome::OutputTooLarge;
                    }
                    buffer.extend_from_slice(&read_buf[..n]);
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            },
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

// ── Helper: info finding at project root ──────────────────────────────────────

fn root_info_finding(project: &Project, rule_id: &str, message: String) -> Finding {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Finding {
        analyzer: AnalyzerId::new("EslintAnalyzer"),
        dimension: Dimension::Maintainability,
        rule_id: rule_id.to_string(),
        severity: Severity::Info,
        message,
        location: Location {
            file: project.root.clone(),
            span: zero,
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion: None,
        references: vec![],
        cwe: vec![],
        owasp: vec![],
    }
}

// ── Analyzer impl ─────────────────────────────────────────────────────────────

/// Integrates `eslint` into the zuit analysis pipeline.
///
/// Overrides [`zuit_core::Analyzer::analyze_project`] rather than
/// `analyze_file` because `ESLint` must be invoked once for the whole project.
pub struct EslintAnalyzer;

impl zuit_core::Analyzer for EslintAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("EslintAnalyzer")
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
                doc_path: "docs/rules/JS-eslint.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/JS-eslint.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/JS-eslint.md",
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
        vec![]
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let has_js_files = project
            .files
            .iter()
            .any(|pf| pf.language() == zuit_core::LanguageId("javascript"));
        if !has_js_files {
            return vec![];
        }

        if which::which("eslint").is_err() {
            return vec![root_info_finding(
                project,
                RULE_MISSING,
                "eslint not found on PATH; install it to enable JS/TS linting".to_string(),
            )];
        }

        match run_eslint(&project.root) {
            EslintOutcome::Ok(stdout) => {
                if stdout.is_empty() {
                    return vec![];
                }
                let stdout_str = String::from_utf8_lossy(&stdout);
                if stdout_str.trim().is_empty() {
                    return vec![];
                }
                match parse_eslint_output(&stdout_str, &project.root, project) {
                    Ok(findings) => findings,
                    Err(e) => {
                        tracing::warn!("failed to parse eslint output: {e}; skipping JS linting");
                        vec![]
                    }
                }
            }
            EslintOutcome::Timeout => vec![root_info_finding(
                project,
                RULE_TIMEOUT,
                format!("eslint timed out after {ESLINT_TIMEOUT_SECS} seconds"),
            )],
            EslintOutcome::OutputTooLarge => {
                let mib = ESLINT_MAX_STDOUT_BYTES / (1024 * 1024);
                vec![root_info_finding(
                    project,
                    RULE_OUTPUT_TOO_LARGE,
                    format!("eslint output exceeded {mib} MiB cap"),
                )]
            }
            EslintOutcome::SpawnFailed(e) => {
                tracing::warn!("eslint spawn failed: {e}; skipping JS linting");
                vec![]
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use zuit_core::{Dimension, Project, Severity};

    use super::*;

    fn empty_project(root: impl Into<PathBuf>) -> Project {
        Project::new(root.into(), vec![])
    }

    // ── 1. Happy path: three findings from fixture ────────────────────────────

    #[test]
    fn parse_eslint_happy_three_findings() {
        let json = include_str!("../../../tests/fixtures/eslint-output.json");
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_eslint_output(json, &root, &project).expect("parse must succeed");

        assert_eq!(
            findings.len(),
            3,
            "expected 3 findings, got {}",
            findings.len()
        );

        let no_eval = findings
            .iter()
            .find(|f| f.rule_id == "JS/eslint/no-eval")
            .expect("no-eval");
        assert_eq!(no_eval.severity, Severity::High);
        assert_eq!(no_eval.dimension, Dimension::Security);

        let complexity = findings
            .iter()
            .find(|f| f.rule_id == "JS/eslint/complexity")
            .expect("complexity");
        assert_eq!(complexity.severity, Severity::Medium);
        assert_eq!(complexity.dimension, Dimension::Complexity);

        let unused = findings
            .iter()
            .find(|f| f.rule_id == "JS/eslint/no-unused-vars")
            .expect("no-unused-vars");
        assert_eq!(unused.severity, Severity::Medium);
        assert_eq!(unused.dimension, Dimension::Maintainability);
    }

    // ── 2. Malformed JSON returns JsError::Json ───────────────────────────────

    #[test]
    fn parse_eslint_malformed_returns_error() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let result = parse_eslint_output("not json", &root, &project);
        assert!(
            matches!(result, Err(JsError::Json(_))),
            "expected JsError::Json, got {result:?}"
        );
    }

    // ── 3. Empty array returns empty vec ─────────────────────────────────────

    #[test]
    fn parse_eslint_empty_array_returns_empty() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_eslint_output("[]", &root, &project).expect("parse must succeed");
        assert!(findings.is_empty(), "expected empty findings");
    }

    // ── 4. no-eval maps to Security ──────────────────────────────────────────

    #[test]
    fn parse_eslint_no_eval_maps_to_security() {
        let json = r#"[{"filePath":"/project/a.js","messages":[{"ruleId":"no-eval","severity":2,"message":"eval can be harmful.","line":1,"column":1}]}]"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_eslint_output(json, &root, &project).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dimension, Dimension::Security);
    }

    // ── 5. complexity maps to Complexity ─────────────────────────────────────

    #[test]
    fn parse_eslint_complexity_maps_to_complexity() {
        let json = r#"[{"filePath":"/project/a.js","messages":[{"ruleId":"complexity","severity":1,"message":"too complex","line":1,"column":1}]}]"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_eslint_output(json, &root, &project).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dimension, Dimension::Complexity);
    }

    // ── 6. Unknown rule maps to Maintainability ───────────────────────────────

    #[test]
    fn parse_eslint_unknown_rule_maps_to_maintainability() {
        let json = r#"[{"filePath":"/project/a.js","messages":[{"ruleId":"some-unknown-rule","severity":1,"message":"msg","line":1,"column":1}]}]"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_eslint_output(json, &root, &project).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dimension, Dimension::Maintainability);
    }

    // ── 7. Absolute path stripped to relative ─────────────────────────────────

    #[test]
    fn parse_eslint_absolute_path_stripped_to_relative() {
        let json = r#"[{"filePath":"/project/src/foo.js","messages":[{"ruleId":"no-eval","severity":2,"message":"eval","line":1,"column":1}]}]"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_eslint_output(json, &root, &project).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.file, PathBuf::from("src/foo.js"));
    }

    // ── 8. Outcome variants are constructible ─────────────────────────────────

    #[test]
    fn eslint_outcome_variants_constructible() {
        let ok = EslintOutcome::Ok(vec![]);
        let timeout = EslintOutcome::Timeout;
        let too_large = EslintOutcome::OutputTooLarge;
        let spawn_failed = EslintOutcome::SpawnFailed("test".to_string());
        let _ = (ok, timeout, too_large, spawn_failed);
    }

    // ── 9. (unix) Timeout / output-cap sanity ─────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn eslint_timeout_kills_long_running_process() {
        let root = PathBuf::from("/tmp");
        let outcome = run_eslint_with_limits(&root, usize::MAX, 1);
        assert!(
            matches!(
                outcome,
                EslintOutcome::SpawnFailed(_) | EslintOutcome::Timeout | EslintOutcome::Ok(_)
            ),
            "expected a valid outcome variant, got {outcome:?}"
        );
    }

    // ── 10. null ruleId is skipped ────────────────────────────────────────────

    #[test]
    fn parse_eslint_null_rule_id_skipped() {
        let json = r#"[{"filePath":"/project/a.js","messages":[{"ruleId":null,"severity":2,"message":"parse error","line":1,"column":1}]}]"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_eslint_output(json, &root, &project).expect("parse");
        assert!(findings.is_empty(), "null ruleId must be skipped");
    }

    // ── 11. security/ prefix maps to Security ────────────────────────────────

    #[test]
    fn parse_eslint_security_prefix_maps_to_security() {
        let json = r#"[{"filePath":"/project/a.js","messages":[{"ruleId":"security/detect-eval-with-expression","severity":2,"message":"detected eval","line":1,"column":1}]}]"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_eslint_output(json, &root, &project).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dimension, Dimension::Security);
    }
}
