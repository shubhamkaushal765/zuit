//! `DependencyCruiserAnalyzer` — wraps `dependency-cruiser` as an external-tool
//! adapter.
//!
//! When called:
//!
//! 1. Searches `$PATH` for the `dependency-cruiser` binary. If missing, emits a
//!    single [`Severity::Info`] finding with rule `JS/dependency-cruiser-missing`
//!    and returns.
//! 2. Spawns `dependency-cruiser --output-type json --no-config .` from the
//!    project root. Captures stdout with a 60-second timeout and 32 MiB cap.
//! 3. Parses the JSON output with [`parse_dep_cruiser_output`].
//! 4. Returns the resulting [`Finding`]s.
//!
//! # JSON schema (depcruise v15+)
//!
//! ```json
//! {
//!   "summary": {
//!     "violations": [
//!       {
//!         "from": "src/a.js",
//!         "to": "src/b.js",
//!         "rule": { "name": "no-circular", "severity": "error" },
//!         "comment": "..."
//!       }
//!     ]
//!   }
//! }
//! ```

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use serde::Deserialize;

use crate::error::JsError;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Maximum time allowed for `dependency-cruiser` to complete, in seconds.
const DEP_CRUISER_TIMEOUT_SECS: u64 = 60;

/// Maximum size of stdout captured from `dependency-cruiser`, in bytes (32 MiB).
const DEP_CRUISER_MAX_STDOUT_BYTES: usize = 32 * 1024 * 1024;

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `dependency-cruiser` is absent from `$PATH`.
pub const RULE_MISSING: &str = "JS/dependency-cruiser-missing";

/// Rule ID emitted when `dependency-cruiser` exceeds the timeout.
const RULE_TIMEOUT: &str = "JS/dependency-cruiser-timeout";

/// Rule ID emitted when `dependency-cruiser` stdout exceeds the cap.
const RULE_OUTPUT_TOO_LARGE: &str = "JS/dependency-cruiser-output-too-large";

// ── JSON deserialization model ────────────────────────────────────────────────

/// Top-level structure of `dependency-cruiser --output-type json` output.
#[derive(Debug, Deserialize, Default)]
struct DepCruiserReport {
    /// Summary block containing violations.
    #[serde(default)]
    summary: DepCruiserSummary,
}

/// Summary section of the dependency-cruiser report.
#[derive(Debug, Deserialize, Default)]
struct DepCruiserSummary {
    /// All rule violations found.
    #[serde(default)]
    violations: Vec<DepCruiserViolation>,
}

/// A single dependency rule violation.
#[derive(Debug, Deserialize, Default)]
struct DepCruiserViolation {
    /// The source file of the dependency.
    #[serde(default)]
    from: String,
    /// The target file of the dependency.
    #[serde(default)]
    to: String,
    /// The rule that was violated.
    #[serde(default)]
    rule: DepCruiserRule,
    /// Optional human-readable comment.
    #[serde(default)]
    comment: String,
}

/// A dependency-cruiser rule descriptor.
#[derive(Debug, Deserialize, Default)]
struct DepCruiserRule {
    /// Rule name, e.g. `"no-circular"`.
    #[serde(default)]
    name: String,
    /// Rule severity: `"error"`, `"warn"`, or `"info"`.
    #[serde(default)]
    severity: String,
}

// ── Severity mapping ──────────────────────────────────────────────────────────

/// Maps a dependency-cruiser severity string to a zuit [`Severity`].
///
/// | depcruise severity | zuit [`Severity`] |
/// |---|---|
/// | `"error"` | [`Severity::High`] |
/// | `"warn"` | [`Severity::Medium`] |
/// | `"info"` | [`Severity::Low`] |
/// | other | [`Severity::Info`] |
#[must_use]
pub fn map_dep_cruiser_severity(s: &str) -> Severity {
    match s {
        "error" => Severity::High,
        "warn" => Severity::Medium,
        "info" => Severity::Low,
        _ => Severity::Info,
    }
}

// ── Core parsing function (pure — no I/O) ─────────────────────────────────────

/// Parses `dependency-cruiser --output-type json` output and returns a
/// [`Vec<Finding>`].
///
/// This function is **pure** — it does not touch the filesystem or spawn any
/// processes. It is the primary unit-test target for this module.
///
/// # Errors
///
/// Returns [`JsError::Json`] if `stdout` is not valid dependency-cruiser JSON.
pub fn parse_dep_cruiser_output(stdout: &str) -> Result<Vec<Finding>, JsError> {
    let report: DepCruiserReport = serde_json::from_str(stdout)?;

    let mut findings = Vec::new();
    for violation in &report.summary.violations {
        let severity = map_dep_cruiser_severity(&violation.rule.severity);
        let rule_id = format!("JS/dependency-cruiser/{}", violation.rule.name);

        let message = if violation.comment.is_empty() {
            format!(
                "dependency rule '{}' violated: '{}' → '{}'",
                violation.rule.name, violation.from, violation.to
            )
        } else {
            format!(
                "dependency rule '{}' violated: '{}' → '{}' — {}",
                violation.rule.name, violation.from, violation.to, violation.comment
            )
        };

        let zero = Span::new(ByteOffset(0), ByteOffset(0));
        findings.push(Finding {
            analyzer: AnalyzerId::new("DependencyCruiserAnalyzer"),
            dimension: Dimension::Maintainability,
            rule_id,
            severity,
            message,
            location: Location {
                file: PathBuf::from(&violation.from),
                span: zero,
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 1),
            },
            suggestion: Some(
                "Review the dependency graph and refactor to remove the offending dependency."
                    .to_string(),
            ),
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        });
    }

    Ok(findings)
}

// ── Subprocess spawning (with timeout and output cap) ────────────────────────

/// Outcome of running `dependency-cruiser`.
#[derive(Debug, PartialEq)]
enum DepCruiserOutcome {
    /// Successfully captured stdout (may be empty).
    Ok(Vec<u8>),
    /// Process exceeded the timeout.
    Timeout,
    /// Stdout exceeded the byte cap.
    OutputTooLarge,
    /// Failed to spawn the process.
    SpawnFailed(String),
}

/// Spawns `dependency-cruiser --output-type json --no-config .` from
/// `working_dir` with a timeout and output cap.
fn run_dep_cruiser(working_dir: &Path) -> DepCruiserOutcome {
    run_dep_cruiser_with_limits(
        working_dir,
        DEP_CRUISER_MAX_STDOUT_BYTES,
        DEP_CRUISER_TIMEOUT_SECS,
    )
}

/// Internal implementation: spawns `dependency-cruiser` with parameterised
/// limits.
///
/// Used by `run_dep_cruiser` and tests.
fn run_dep_cruiser_with_limits(
    working_dir: &Path,
    max_stdout_bytes: usize,
    timeout_secs: u64,
) -> DepCruiserOutcome {
    use std::process::{Command, Stdio};

    let mut child = match Command::new("dependency-cruiser")
        .args(["--output-type", "json", "--no-config", "."])
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return DepCruiserOutcome::SpawnFailed(e.to_string()),
    };

    let Some(mut stdout) = child.stdout.take() else {
        return DepCruiserOutcome::SpawnFailed("stdout not piped".to_string());
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
            return DepCruiserOutcome::Timeout;
        }

        match child.try_wait() {
            Ok(Some(_status)) => loop {
                match stdout.read(&mut read_buf) {
                    Ok(0) | Err(_) => return DepCruiserOutcome::Ok(buffer),
                    Ok(n) => {
                        if buffer.len() + n > max_stdout_bytes {
                            let _ = child.kill();
                            let _ = child.wait();
                            return DepCruiserOutcome::OutputTooLarge;
                        }
                        buffer.extend_from_slice(&read_buf[..n]);
                    }
                }
            },
            Ok(None) => match stdout.read(&mut read_buf) {
                Ok(0) => {
                    let _ = child.wait();
                    return DepCruiserOutcome::Ok(buffer);
                }
                Ok(n) => {
                    if buffer.len() + n > max_stdout_bytes {
                        let _ = child.kill();
                        let _ = child.wait();
                        return DepCruiserOutcome::OutputTooLarge;
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
        analyzer: AnalyzerId::new("DependencyCruiserAnalyzer"),
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

/// Integrates `dependency-cruiser` into the zuit analysis pipeline.
///
/// Runs `dependency-cruiser --output-type json --no-config .` once for the
/// whole project and converts violations into [`Finding`]s.
pub struct DependencyCruiserAnalyzer;

impl zuit_core::Analyzer for DependencyCruiserAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("DependencyCruiserAnalyzer")
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
                doc_path: "docs/rules/JS-dependency-cruiser.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/JS-dependency-cruiser.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/JS-dependency-cruiser.md",
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
        if which::which("dependency-cruiser").is_err() {
            return vec![root_info_finding(
                project,
                RULE_MISSING,
                "dependency-cruiser not found on PATH; install it with \
                 `npm install -g dependency-cruiser` to enable dependency graph analysis"
                    .to_string(),
            )];
        }

        match run_dep_cruiser(&project.root) {
            DepCruiserOutcome::Ok(stdout) => {
                if stdout.is_empty() {
                    return vec![];
                }
                let stdout_str = String::from_utf8_lossy(&stdout);
                if stdout_str.trim().is_empty() {
                    return vec![];
                }
                match parse_dep_cruiser_output(&stdout_str) {
                    Ok(findings) => findings,
                    Err(e) => {
                        tracing::warn!("failed to parse dependency-cruiser output: {e}; skipping");
                        vec![]
                    }
                }
            }
            DepCruiserOutcome::Timeout => vec![root_info_finding(
                project,
                RULE_TIMEOUT,
                format!("dependency-cruiser timed out after {DEP_CRUISER_TIMEOUT_SECS} seconds"),
            )],
            DepCruiserOutcome::OutputTooLarge => {
                let mib = DEP_CRUISER_MAX_STDOUT_BYTES / (1024 * 1024);
                vec![root_info_finding(
                    project,
                    RULE_OUTPUT_TOO_LARGE,
                    format!("dependency-cruiser output exceeded {mib} MiB cap"),
                )]
            }
            DepCruiserOutcome::SpawnFailed(e) => {
                tracing::warn!("dependency-cruiser spawn failed: {e}; skipping");
                vec![]
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use zuit_core::{Analyzer, Config, Dimension, Project, Severity};

    use super::*;

    fn empty_project(root: impl Into<PathBuf>) -> Project {
        Project::new(root.into(), vec![])
    }

    // 1. Happy path: fixture → ≥2 violations
    #[test]
    fn parse_dep_cruiser_happy_path() {
        let json = include_str!("../../../tests/fixtures/dependency-cruiser-output.json");
        let findings = parse_dep_cruiser_output(json).expect("parse must succeed");

        assert!(
            findings.len() >= 2,
            "expected ≥2 findings, got {}",
            findings.len()
        );

        // Check prefixed rule IDs.
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id.starts_with("JS/dependency-cruiser/")),
            "all rule ids must start with JS/dependency-cruiser/"
        );

        // Check Maintainability dimension.
        assert!(
            findings
                .iter()
                .all(|f| f.dimension == Dimension::Maintainability),
            "all findings must have Maintainability dimension"
        );
    }

    // 2. Empty violations → 0 findings
    #[test]
    fn parse_dep_cruiser_empty_violations_clean() {
        let json = r#"{"summary": {"violations": []}}"#;
        let findings = parse_dep_cruiser_output(json).expect("parse must succeed");
        assert!(
            findings.is_empty(),
            "expected 0 findings, got {findings:#?}"
        );
    }

    // 3. Malformed JSON → JsError::Json
    #[test]
    fn parse_dep_cruiser_malformed_returns_error() {
        let result = parse_dep_cruiser_output("not json");
        assert!(
            matches!(result, Err(JsError::Json(_))),
            "expected JsError::Json, got {result:?}"
        );
    }

    // 4. Missing binary → emits Info finding (or 0 findings if tool is installed)
    #[test]
    fn dep_cruiser_missing_binary_emits_single_info_or_zero() {
        // This test is environment-dependent: dependency-cruiser may or may not
        // be installed. The analyzer must not panic in either case.
        let tmp = tempfile::TempDir::new().unwrap();
        let project = empty_project(tmp.path());
        let analyzer = DependencyCruiserAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        // Accept 0 findings (tool runs and finds nothing) or 1 Info finding (tool missing).
        // In CI without dependency-cruiser installed, expect exactly 1.
        let is_missing_finding = findings.len() == 1 && findings[0].rule_id == RULE_MISSING;
        let is_empty = findings.is_empty();
        assert!(
            is_missing_finding || is_empty,
            "expected 0 findings or 1 JS/dependency-cruiser-missing Info, got {findings:#?}"
        );
    }

    // 5. Severity map: error → High
    #[test]
    fn dep_cruiser_severity_map_error() {
        assert_eq!(map_dep_cruiser_severity("error"), Severity::High);
    }

    // 6. Severity map: warn → Medium
    #[test]
    fn dep_cruiser_severity_map_warn() {
        assert_eq!(map_dep_cruiser_severity("warn"), Severity::Medium);
    }

    // 7. Severity map: info → Low
    #[test]
    fn dep_cruiser_severity_map_info() {
        assert_eq!(map_dep_cruiser_severity("info"), Severity::Low);
    }

    // 8. Severity map: unknown → Info
    #[test]
    fn dep_cruiser_severity_map_unknown() {
        assert_eq!(map_dep_cruiser_severity("bogus"), Severity::Info);
    }

    // 9. Rule ID format
    #[test]
    fn parse_dep_cruiser_rule_id_format() {
        let json = r#"{
            "summary": {
                "violations": [{
                    "from": "src/a.js",
                    "to": "src/b.js",
                    "rule": {"name": "no-circular", "severity": "error"},
                    "comment": ""
                }]
            }
        }"#;
        let findings = parse_dep_cruiser_output(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "JS/dependency-cruiser/no-circular");
        assert_eq!(findings[0].severity, Severity::High);
    }

    // 10. Comment included in message
    #[test]
    fn parse_dep_cruiser_comment_in_message() {
        let json = r#"{
            "summary": {
                "violations": [{
                    "from": "src/a.js",
                    "to": "src/b.js",
                    "rule": {"name": "no-circular", "severity": "warn"},
                    "comment": "Circular dependency detected"
                }]
            }
        }"#;
        let findings = parse_dep_cruiser_output(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("Circular dependency detected"),
            "comment must appear in message"
        );
    }

    // 11. Outcome variants are constructible
    #[test]
    fn dep_cruiser_outcome_variants_constructible() {
        let ok = DepCruiserOutcome::Ok(vec![]);
        let timeout = DepCruiserOutcome::Timeout;
        let too_large = DepCruiserOutcome::OutputTooLarge;
        let spawn_failed = DepCruiserOutcome::SpawnFailed("test".to_string());
        let _ = (ok, timeout, too_large, spawn_failed);
    }
}
