//! `CargoDenyAnalyzer` — wraps `cargo deny` as an external-tool adapter.
//!
//! When called:
//!
//! 1. Searches `$PATH` for the `cargo` binary.
//!    If missing, emits a single `Info` finding `RS/cargo-deny-missing`.
//! 2. Checks whether `deny.toml` exists in the project root.
//!    - If absent: emits `RS/deny/no-deny-config` Info AND runs
//!      `cargo deny check advisories` (advisory check works without deny.toml).
//!    - If present: runs `cargo deny check`.
//! 3. Parses the NDJSON diagnostic stream with [`parse_cargo_deny_output`].
//! 4. Returns the resulting [`Finding`]s.
//!
//! # Operational rule IDs
//!
//! - `RS/cargo-deny-missing` — `cargo deny` not found on `$PATH`
//! - `RS/cargo-deny-timeout` — process exceeded timeout
//! - `RS/cargo-deny-output-too-large` — stdout exceeded cap
//! - `RS/cargo-deny-spawn-failed` — OS-level spawn failure
//! - `RS/deny/no-deny-config` — no `deny.toml` in project root
//!
//! # Finding rule ID format
//!
//! `RS/deny/<check>` where check ∈ {`advisories`, `licenses`, `bans`, `sources`}.

use std::path::Path;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use serde::Deserialize;

use zuit_core::external::{DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS, Outcome, run_with_limits};

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `cargo deny` is absent from `$PATH`.
pub const RULE_MISSING: &str = "RS/cargo-deny-missing";
const RULE_TIMEOUT: &str = "RS/cargo-deny-timeout";
const RULE_OUTPUT_TOO_LARGE: &str = "RS/cargo-deny-output-too-large";
const RULE_SPAWN_FAILED: &str = "RS/cargo-deny-spawn-failed";
/// Rule ID emitted when `deny.toml` is absent from the project root.
pub const RULE_NO_DENY_CONFIG: &str = "RS/deny/no-deny-config";

// ── JSON wire types ───────────────────────────────────────────────────────────

/// A single NDJSON diagnostic line from `cargo deny --format json`.
#[derive(Debug, Deserialize)]
struct DenyDiag {
    #[serde(rename = "type")]
    #[serde(default)]
    kind: String,
    #[serde(default)]
    fields: DenyFields,
}

#[derive(Debug, Default, Deserialize)]
struct DenyFields {
    #[serde(default)]
    severity: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    #[allow(dead_code)]
    graphs: Vec<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    labels: Vec<DenyLabel>,
}

#[derive(Debug, Default, Deserialize)]
struct DenyLabel {
    #[serde(default)]
    #[allow(dead_code)]
    message: String,
    #[serde(default)]
    #[allow(dead_code)]
    span: Option<u64>,
}

// ── Mapping helpers ───────────────────────────────────────────────────────────

/// Maps a `cargo deny` code prefix to a rule ID and dimension.
fn map_deny_code(code: &str) -> (&'static str, Dimension) {
    let lower = code.to_lowercase();
    if lower.contains("vuln") || lower.contains("advisory") || lower.contains("rustsec") {
        ("RS/deny/advisories", Dimension::Security)
    } else if lower.contains("license") {
        ("RS/deny/licenses", Dimension::Maintainability)
    } else if lower.contains("ban") || lower.contains("unwanted") {
        ("RS/deny/bans", Dimension::Maintainability)
    } else if lower.contains("source") || lower.contains("registry") {
        ("RS/deny/sources", Dimension::Maintainability)
    } else {
        ("RS/deny/advisories", Dimension::Security)
    }
}

/// Maps a `cargo deny` severity string to a zuit [`Severity`].
fn map_deny_severity(sev: &str) -> Severity {
    match sev {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        _ => Severity::Low, // help, note, etc.
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn project_finding(
    project_root: &Path,
    rule_id: &str,
    severity: Severity,
    dimension: Dimension,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Finding {
        analyzer: AnalyzerId::new("CargoDenyAnalyzer"),
        dimension,
        rule_id: rule_id.to_string(),
        severity,
        message,
        location: Location {
            file: project_root.to_path_buf(),
            span: zero,
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion,
        references: vec!["https://embarkstudios.github.io/cargo-deny/".to_string()],
        cwe: vec![],
        owasp: vec![],
    }
}

// ── Core parsing function (pure — no I/O) ────────────────────────────────────

/// Parses `cargo deny check --format json` NDJSON output and returns a
/// [`Vec<Finding>`].
///
/// This function is **pure** — it performs no I/O and is the primary unit-test
/// target for this module.
///
/// # Errors
///
/// Returns [`crate::error::RustError::Json`] if any line is not valid JSON.
pub fn parse_cargo_deny_output(
    stdout: &str,
    project_root: &Path,
    _project: &Project,
) -> Result<Vec<Finding>, crate::error::RustError> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let diag: DenyDiag = serde_json::from_str(line)?;
        if diag.kind != "diagnostic" {
            continue;
        }
        let (rule_id, dimension) = map_deny_code(&diag.fields.code);
        let severity = map_deny_severity(&diag.fields.severity);
        let message = if diag.fields.message.is_empty() {
            format!(
                "cargo deny: {} ({})",
                diag.fields.code, diag.fields.severity
            )
        } else {
            diag.fields.message.clone()
        };

        findings.push(project_finding(
            project_root,
            rule_id,
            severity,
            dimension,
            message,
            None,
        ));
    }

    Ok(findings)
}

// ── Analyzer impl ─────────────────────────────────────────────────────────────

/// Integrates `cargo deny` into the zuit analysis pipeline.
///
/// Overrides [`zuit_core::Analyzer::analyze_project`] because `cargo deny`
/// operates on the whole workspace.
pub struct CargoDenyAnalyzer;

impl zuit_core::Analyzer for CargoDenyAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("CargoDenyAnalyzer")
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
                doc_path: "docs/rules/RS-cargo-deny.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-deny.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-deny.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_SPAWN_FAILED,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-deny.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_NO_DENY_CONFIG,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-deny.md",
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
        let has_rust = project
            .files
            .iter()
            .any(|pf| pf.language() == zuit_core::LanguageId("rust"));
        let has_cargo_toml = project.root.join("Cargo.toml").exists();
        if !has_rust && !has_cargo_toml {
            return Vec::new();
        }

        let mut findings: Vec<Finding> = Vec::new();

        if which::which("cargo").is_err() {
            findings.push(project_finding(
                &project.root,
                RULE_MISSING,
                Severity::Info,
                Dimension::Security,
                "cargo not found on PATH; install Rust to enable cargo deny".to_string(),
                Some("Install Rust: https://www.rust-lang.org/tools/install".to_string()),
            ));
            return findings;
        }

        // Check for deny.toml.
        let has_deny_toml = project.root.join("deny.toml").exists();
        let deny_args: &[&str] = if has_deny_toml {
            &["deny", "check", "--format", "json"]
        } else {
            findings.push(project_finding(
                &project.root,
                RULE_NO_DENY_CONFIG,
                Severity::Info,
                Dimension::Maintainability,
                "No `deny.toml` found in project root; cargo deny is not configured. \
                 Running advisory-only check."
                    .to_string(),
                Some(
                    "Create a `deny.toml` to configure license, ban, and source checks. \
                     See https://embarkstudios.github.io/cargo-deny/."
                        .to_string(),
                ),
            ));
            &["deny", "check", "advisories", "--format", "json"]
        };

        let mut deny_findings = match run_with_limits(
            "cargo",
            deny_args,
            &project.root,
            DEFAULT_MAX_STDOUT_BYTES,
            DEFAULT_TIMEOUT_SECS,
        ) {
            Outcome::Ok(stdout) => {
                let s = String::from_utf8_lossy(&stdout);
                if s.trim().is_empty() {
                    Vec::new()
                } else {
                    match parse_cargo_deny_output(&s, &project.root, project) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            tracing::warn!("failed to parse cargo deny output: {e}; skipping");
                            Vec::new()
                        }
                    }
                }
            }
            Outcome::Timeout => {
                findings.push(project_finding(
                    &project.root,
                    RULE_TIMEOUT,
                    Severity::Info,
                    Dimension::Security,
                    format!("cargo deny timed out after {DEFAULT_TIMEOUT_SECS} seconds"),
                    None,
                ));
                Vec::new()
            }
            Outcome::OutputTooLarge => {
                let mib = DEFAULT_MAX_STDOUT_BYTES / (1024 * 1024);
                findings.push(project_finding(
                    &project.root,
                    RULE_OUTPUT_TOO_LARGE,
                    Severity::Info,
                    Dimension::Security,
                    format!("cargo deny output exceeded {mib} MiB cap"),
                    None,
                ));
                Vec::new()
            }
            Outcome::SpawnFailed(e) => {
                tracing::warn!("cargo deny spawn failed: {e}");
                findings.push(project_finding(
                    &project.root,
                    RULE_SPAWN_FAILED,
                    Severity::Info,
                    Dimension::Security,
                    format!("cargo deny failed to spawn: {e}"),
                    None,
                ));
                Vec::new()
            }
        };

        findings.append(&mut deny_findings);
        findings
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use zuit_core::{Dimension, Project, Severity};

    use super::*;

    fn empty_project() -> Project {
        Project::new(PathBuf::from("/project"), vec![])
    }

    const ADVISORY_NDJSON: &str = r#"{"type":"diagnostic","fields":{"severity":"error","message":"Vulnerable dep found","code":"vulnerability","graphs":[],"labels":[]}}"#;
    const LICENSE_NDJSON: &str = r#"{"type":"diagnostic","fields":{"severity":"warning","message":"License not allowed","code":"license-not-allowed","graphs":[],"labels":[]}}"#;

    /// 1. Happy path: advisory diagnostic → 1 finding, Security.
    #[test]
    fn parse_cargo_deny_advisories_maps_security() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let findings =
            parse_cargo_deny_output(ADVISORY_NDJSON, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "RS/deny/advisories");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].dimension, Dimension::Security);
    }

    /// 2. License diagnostic → Maintainability.
    #[test]
    fn parse_cargo_deny_license_maps_maintainability() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let findings =
            parse_cargo_deny_output(LICENSE_NDJSON, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "RS/deny/licenses");
        assert_eq!(findings[0].dimension, Dimension::Maintainability);
    }

    /// 3. Empty input → 0 findings.
    #[test]
    fn parse_cargo_deny_empty_no_findings() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let findings = parse_cargo_deny_output("", &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 0);
    }

    /// 4. Malformed JSON → Err.
    #[test]
    fn parse_cargo_deny_malformed_returns_error() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let result = parse_cargo_deny_output("{not json}", &root, &project);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::error::RustError::Json(_))));
    }

    /// 5. Non-diagnostic lines are skipped.
    #[test]
    fn parse_cargo_deny_skips_non_diagnostic_lines() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let ndjson = r#"{"type":"other","fields":{"severity":"error","message":"x","code":"y","graphs":[],"labels":[]}}"#;
        let findings =
            parse_cargo_deny_output(ndjson, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 0);
    }

    /// 6. Multiple NDJSON lines → multiple findings.
    #[test]
    fn parse_cargo_deny_multiple_lines() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let ndjson = format!("{ADVISORY_NDJSON}\n{LICENSE_NDJSON}");
        let findings =
            parse_cargo_deny_output(&ndjson, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 2);
    }
}
