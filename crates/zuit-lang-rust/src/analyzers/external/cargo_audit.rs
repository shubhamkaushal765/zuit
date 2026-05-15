//! `CargoAuditAnalyzer` — wraps `cargo audit` as an external-tool adapter.
//!
//! This analyzer implements [`zuit_core::Analyzer::analyze_project`] (not
//! `analyze_file`).  When called:
//!
//! 1. Searches `$PATH` for the `cargo` binary (via the `which` crate).
//!    If missing, emits a single [`Severity::Info`] finding with rule
//!    `RS/cargo-audit-missing` and returns.
//! 2. Spawns `cargo audit --json` from the project root.
//!    Captures stdout with a 60-second timeout and 32 MiB cap.  A non-zero
//!    exit code is normal when vulnerabilities exist; only a spawn failure is
//!    treated as an error.
//! 3. Parses the JSON output with [`parse_cargo_audit_output`].
//! 4. Returns the resulting [`Finding`]s.
//!
//! # Operational rule IDs
//!
//! - `RS/cargo-audit-missing` — `cargo` not found on `$PATH`
//! - `RS/cargo-audit-timeout` — process exceeded 60-second timeout
//! - `RS/cargo-audit-output-too-large` — stdout exceeded 32 MiB cap
//! - `RS/cargo-audit-spawn-failed` — OS-level spawn failure
//!
//! # Finding rule ID format
//!
//! `RS/audit/<RUSTSEC-ID>` e.g. `RS/audit/RUSTSEC-2021-0003`.

use std::path::Path;

use serde::Deserialize;
use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

use zuit_core::external::{
    DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS, Outcome, run_with_limits,
};

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `cargo` (and thus `cargo audit`) is absent from `$PATH`.
pub const RULE_MISSING: &str = "RS/cargo-audit-missing";
/// Rule ID emitted when `cargo audit` exceeds the timeout.
const RULE_TIMEOUT: &str = "RS/cargo-audit-timeout";
/// Rule ID emitted when `cargo audit` stdout exceeds the cap.
const RULE_OUTPUT_TOO_LARGE: &str = "RS/cargo-audit-output-too-large";
/// Rule ID emitted when the OS cannot spawn `cargo audit`.
const RULE_SPAWN_FAILED: &str = "RS/cargo-audit-spawn-failed";

/// Prefix for advisory-specific rule IDs.
const AUDIT_RULE_PREFIX: &str = "RS/audit/";

// ── JSON wire types ───────────────────────────────────────────────────────────

/// Top-level JSON output of `cargo audit --json`.
#[derive(Debug, Deserialize)]
struct AuditOutput {
    /// Vulnerabilities reported by the audit.
    #[serde(default)]
    vulnerabilities: AuditVulns,
    /// Warnings grouped by kind (e.g. `"unmaintained"`, `"yanked"`).
    #[serde(default)]
    warnings: serde_json::Map<String, serde_json::Value>,
}

/// Container for vulnerability list inside [`AuditOutput`].
#[derive(Debug, Default, Deserialize)]
struct AuditVulns {
    /// Individual vulnerability entries.
    #[serde(default)]
    list: Vec<AuditVuln>,
}

/// A single vulnerability entry.
#[derive(Debug, Deserialize)]
struct AuditVuln {
    /// Advisory metadata.
    advisory: AuditAdvisory,
    /// Affected package.
    package: AuditPackage,
}

/// Advisory metadata for a RUSTSEC advisory.
#[derive(Debug, Deserialize)]
struct AuditAdvisory {
    /// Advisory identifier, e.g. `"RUSTSEC-2021-0003"`.
    #[serde(default)]
    id: String,
    /// Short title of the advisory.
    #[serde(default)]
    title: String,
    /// Semantic categories, e.g. `["memory-corruption"]`.
    #[serde(default)]
    categories: Vec<String>,
    /// Advisory URL (optional).
    #[serde(default)]
    url: Option<String>,
    /// CVSS score string (optional); captured for completeness but not currently used
    /// in severity calculations (all advisories default to High).
    #[serde(default)]
    #[allow(dead_code)]
    cvss: Option<String>,
}

/// Package info associated with an advisory.
#[derive(Debug, Deserialize)]
struct AuditPackage {
    /// Crate name.
    #[serde(default)]
    name: String,
    /// Installed version.
    #[serde(default)]
    version: String,
}

/// A single warning entry in `cargo audit --json` output.
#[derive(Debug, Default, Deserialize)]
struct AuditWarning {
    /// Warning kind, e.g. `"unmaintained"` or `"yanked"`.
    #[serde(default)]
    kind: String,
    /// Advisory for this warning (may be absent for yanked versions).
    #[serde(default)]
    advisory: Option<AuditAdvisory>,
    /// Package information.
    #[serde(default)]
    package: Option<AuditPackage>,
}

// ── CWE mapping ───────────────────────────────────────────────────────────────

/// Maps RUSTSEC advisory categories to CWE identifiers.
///
/// | Category | CWE |
/// |---|---|
/// | `memory-corruption` | CWE-119 |
/// | `crypto-failure` | CWE-327 |
/// | `denial-of-service` | CWE-400 |
/// | `code-execution` | CWE-94 |
/// | anything else | (empty) |
#[must_use]
pub fn map_rustsec_cwe(categories: &[String]) -> Vec<String> {
    let mut cwes = Vec::new();
    for cat in categories {
        let cwe = match cat.as_str() {
            "memory-corruption" => Some("CWE-119"),
            "crypto-failure" => Some("CWE-327"),
            "denial-of-service" => Some("CWE-400"),
            "code-execution" => Some("CWE-94"),
            _ => None,
        };
        if let Some(c) = cwe {
            let owned = c.to_string();
            if !cwes.contains(&owned) {
                cwes.push(owned);
            }
        }
    }
    cwes
}

// ── Helper: operational finding at project root ───────────────────────────────

/// Builds an operational [`Finding`] pointing at the project root.
///
/// Used for missing-binary, timeout, output-too-large, and spawn-failed conditions.
#[must_use]
pub fn operational_finding(
    project: &Project,
    rule_id: &str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
    references: Vec<String>,
) -> Finding {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Finding {
        analyzer: AnalyzerId::new("CargoAuditAnalyzer"),
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

// ── Helpers for building findings ─────────────────────────────────────────────

/// Builds a zero-span [`Finding`] pinned to `Cargo.lock` in the project root.
fn cargo_lock_finding(
    project_root: &Path,
    rule_id: String,
    severity: Severity,
    dimension: Dimension,
    message: String,
    references: Vec<String>,
    cwe: Vec<String>,
) -> Finding {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Finding {
        analyzer: AnalyzerId::new("CargoAuditAnalyzer"),
        dimension,
        rule_id,
        severity,
        message,
        location: Location {
            file: project_root.join("Cargo.lock"),
            span: zero,
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion: None,
        references,
        cwe,
        owasp: vec![],
    }
}

/// Converts a single [`AuditWarning`] to an optional [`Finding`].
///
/// Returns `None` for unknown warning kinds.
fn warning_to_finding(warn: &AuditWarning, project_root: &Path) -> Option<Finding> {
    let (rule_id, severity, dimension) = match warn.kind.as_str() {
        "unmaintained" => {
            let id = warn.advisory.as_ref().map_or_else(
                || format!("{AUDIT_RULE_PREFIX}unmaintained"),
                |a| format!("{AUDIT_RULE_PREFIX}{}", a.id),
            );
            (id, Severity::Medium, Dimension::Maintainability)
        }
        "yanked" => {
            let id = warn.advisory.as_ref().map_or_else(
                || {
                    let pkg_name = warn.package.as_ref().map_or("unknown", |p| p.name.as_str());
                    format!("{AUDIT_RULE_PREFIX}{pkg_name}-yanked")
                },
                |a| format!("{AUDIT_RULE_PREFIX}{}", a.id),
            );
            (id, Severity::Medium, Dimension::Maintainability)
        }
        _ => return None,
    };

    let pkg_name = warn.package.as_ref().map_or("", |p| p.name.as_str());
    let pkg_version = warn.package.as_ref().map_or("", |p| p.version.as_str());
    let title = warn
        .advisory
        .as_ref()
        .map_or("no title", |a| a.title.as_str());

    let message = if pkg_name.is_empty() {
        format!("{}: {}", warn.kind, title)
    } else {
        format!("{} ({}@{}): {}", warn.kind, pkg_name, pkg_version, title)
    };

    let mut references = Vec::new();
    if let Some(adv) = &warn.advisory
        && let Some(url) = &adv.url
    {
        references.push(url.clone());
    }

    Some(cargo_lock_finding(
        project_root,
        rule_id,
        severity,
        dimension,
        message,
        references,
        vec![],
    ))
}

// ── Core parsing function (pure — no I/O) ────────────────────────────────────

/// Parses `cargo audit --json` output and returns a [`Vec<Finding>`].
///
/// This function is **pure** — it does not touch the filesystem or spawn any
/// processes.  It is the primary unit-test target for this module.
///
/// Vulnerabilities produce `Severity::High` findings with `Dimension::Security`.
/// Unmaintained / yanked warnings produce `Severity::Medium` findings with
/// `Dimension::Maintainability`.
///
/// # Errors
///
/// Returns [`crate::error::RustError::Json`] if `json` is not valid `cargo audit` output.
pub fn parse_cargo_audit_output(
    json: &str,
    project_root: &Path,
    _project: &Project,
) -> Result<Vec<Finding>, crate::error::RustError> {
    let output: AuditOutput = serde_json::from_str(json)?;

    let mut findings = Vec::new();

    // Vulnerabilities → High, Security.
    for vuln in output.vulnerabilities.list {
        let rule_id = format!("{AUDIT_RULE_PREFIX}{}", vuln.advisory.id);
        let cwe = map_rustsec_cwe(&vuln.advisory.categories);
        let message = format!(
            "{} ({}@{}): {}",
            vuln.advisory.id, vuln.package.name, vuln.package.version, vuln.advisory.title
        );
        let references: Vec<String> = vuln.advisory.url.into_iter().collect();
        findings.push(cargo_lock_finding(
            project_root,
            rule_id,
            Severity::High,
            Dimension::Security,
            message,
            references,
            cwe,
        ));
    }

    // Warnings (unmaintained, yanked) → Medium, Maintainability.
    for (_kind_key, value) in &output.warnings {
        let warn_list: Vec<AuditWarning> = match serde_json::from_value(value.clone()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for warn in &warn_list {
            if let Some(f) = warning_to_finding(warn, project_root) {
                findings.push(f);
            }
        }
    }

    Ok(findings)
}

// ── Analyzer impl ─────────────────────────────────────────────────────────────

/// Integrates `cargo audit` into the zuit analysis pipeline.
///
/// Overrides [`zuit_core::Analyzer::analyze_project`] rather than
/// `analyze_file`, because `cargo audit` operates on the whole workspace.
///
/// # Binary detection
///
/// If `cargo` is not found on `$PATH`, a single [`Severity::Info`] finding
/// with rule `RS/cargo-audit-missing` is returned.
///
/// # Non-zero exit codes
///
/// `cargo audit` exits non-zero when vulnerabilities exist.  This is normal;
/// only a spawn failure is treated as an error.
pub struct CargoAuditAnalyzer;

impl zuit_core::Analyzer for CargoAuditAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("CargoAuditAnalyzer")
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
                doc_path: "docs/rules/RS-cargo-audit.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-audit.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-audit.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_SPAWN_FAILED,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-audit.md",
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
        // All work is done at project level.
        Vec::new()
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        // 1. Early-exit if no Rust files and no Cargo.toml.
        let has_rust_files = project
            .files
            .iter()
            .any(|pf| pf.language() == zuit_core::LanguageId("rust"));
        let has_cargo_toml = project.root.join("Cargo.toml").exists();
        if !has_rust_files && !has_cargo_toml {
            return Vec::new();
        }

        let mut findings: Vec<Finding> = Vec::new();

        // 2. Check for `cargo` on PATH.
        if which::which("cargo").is_err() {
            findings.push(operational_finding(
                project,
                RULE_MISSING,
                Severity::Info,
                "cargo not found on PATH; install Rust to enable cargo audit".to_string(),
                Some("Install Rust: https://www.rust-lang.org/tools/install".to_string()),
                vec!["https://rustsec.org/".to_string()],
            ));
            return findings;
        }

        // 3. Spawn `cargo audit --json`.
        let mut audit_findings = match run_with_limits(
            "cargo",
            &["audit", "--json"],
            &project.root,
            DEFAULT_MAX_STDOUT_BYTES,
            DEFAULT_TIMEOUT_SECS,
        ) {
            Outcome::Ok(stdout) => {
                if stdout.is_empty() {
                    Vec::new()
                } else {
                    let stdout_str = String::from_utf8_lossy(&stdout);
                    if stdout_str.trim().is_empty() {
                        Vec::new()
                    } else {
                        // 4. Parse.
                        match parse_cargo_audit_output(&stdout_str, &project.root, project) {
                            Ok(parsed) => parsed,
                            Err(e) => {
                                tracing::warn!("failed to parse cargo audit output: {e}; skipping");
                                Vec::new()
                            }
                        }
                    }
                }
            }
            // 5. Operational outcomes.
            Outcome::Timeout => {
                findings.push(operational_finding(
                    project,
                    RULE_TIMEOUT,
                    Severity::Info,
                    format!("cargo audit timed out after {DEFAULT_TIMEOUT_SECS} seconds"),
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
                    format!("cargo audit output exceeded {mib_cap} MiB cap"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
            Outcome::SpawnFailed(e) => {
                tracing::warn!("cargo audit spawn failed: {e}");
                findings.push(operational_finding(
                    project,
                    RULE_SPAWN_FAILED,
                    Severity::Info,
                    format!("cargo audit failed to spawn: {e}"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
        };

        findings.append(&mut audit_findings);
        findings
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

    // ── Fixture JSON ──────────────────────────────────────────────────────────

    const TWO_VULNS_JSON: &str = r#"{
        "vulnerabilities": {
            "list": [
                {
                    "advisory": {
                        "id": "RUSTSEC-2021-0003",
                        "title": "Memory safety flaw in example-crate",
                        "categories": ["memory-corruption"],
                        "url": "https://rustsec.org/advisories/RUSTSEC-2021-0003.html",
                        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    },
                    "package": { "name": "example-crate", "version": "1.0.0" }
                },
                {
                    "advisory": {
                        "id": "RUSTSEC-2022-0010",
                        "title": "Denial of service in another-crate",
                        "categories": ["denial-of-service"],
                        "url": null,
                        "cvss": null
                    },
                    "package": { "name": "another-crate", "version": "2.3.1" }
                }
            ]
        },
        "warnings": {}
    }"#;

    const EMPTY_JSON: &str = r#"{"vulnerabilities": {"list": []}, "warnings": {}}"#;

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// 1. Happy path: two vulnerabilities produce two findings with correct prefixes and severity.
    #[test]
    fn parse_cargo_audit_happy_two_vulnerabilities() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings =
            parse_cargo_audit_output(TWO_VULNS_JSON, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 2, "expected 2 findings");

        for f in &findings {
            assert!(
                f.rule_id.starts_with("RS/audit/"),
                "rule_id must start with RS/audit/, got: {}",
                f.rule_id
            );
            assert_eq!(f.severity, Severity::High, "vulnerabilities must be High");
            assert_eq!(f.dimension, Dimension::Security, "must be Security");
        }

        // Check the specific IDs.
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "RS/audit/RUSTSEC-2021-0003")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "RS/audit/RUSTSEC-2022-0010")
        );
    }

    /// 2. Malformed JSON returns an error.
    #[test]
    fn parse_cargo_audit_malformed_returns_error() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let result = parse_cargo_audit_output("{not json", &root, &project);
        assert!(result.is_err(), "malformed JSON must return an error");
        assert!(matches!(result, Err(crate::error::RustError::Json(_))));
    }

    /// 3. Advisory with `categories: ["memory-corruption"]` maps to `CWE-119`.
    #[test]
    fn cargo_audit_rustsec_maps_cwe_memory_corruption() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings =
            parse_cargo_audit_output(TWO_VULNS_JSON, &root, &project).expect("parse must succeed");

        let rustsec_0003 = findings
            .iter()
            .find(|f| f.rule_id == "RS/audit/RUSTSEC-2021-0003")
            .expect("RUSTSEC-2021-0003 must be present");

        assert_eq!(
            rustsec_0003.cwe,
            vec!["CWE-119".to_string()],
            "memory-corruption must map to CWE-119"
        );
    }

    /// 4. Unmaintained warning produces a Medium, Maintainability finding.
    #[test]
    fn parse_cargo_audit_unmaintained_warning_medium() {
        let json = r#"{
            "vulnerabilities": {"list": []},
            "warnings": {
                "unmaintained": [
                    {
                        "kind": "unmaintained",
                        "advisory": {
                            "id": "RUSTSEC-2020-0071",
                            "title": "Crate is unmaintained",
                            "categories": [],
                            "url": null,
                            "cvss": null
                        },
                        "package": { "name": "old-crate", "version": "0.1.0" }
                    }
                ]
            }
        }"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_cargo_audit_output(json, &root, &project).expect("parse must succeed");

        assert_eq!(findings.len(), 1, "expected 1 warning finding");
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Medium, "unmaintained must be Medium");
        assert_eq!(
            f.dimension,
            Dimension::Maintainability,
            "unmaintained must be Maintainability"
        );
        assert!(
            f.rule_id.starts_with("RS/audit/"),
            "rule_id must start with RS/audit/"
        );
    }

    /// 5. Empty list produces zero findings.
    #[test]
    fn parse_cargo_audit_empty_no_findings() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings =
            parse_cargo_audit_output(EMPTY_JSON, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 0, "empty output must produce 0 findings");
    }

    /// Bonus: the `operational_finding` helper builds a well-formed Info finding.
    #[test]
    fn missing_binary_finding_is_well_formed() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let f = operational_finding(
            &project,
            RULE_MISSING,
            Severity::Info,
            "cargo not found".to_string(),
            None,
            vec![],
        );
        assert_eq!(f.rule_id, RULE_MISSING);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.dimension, Dimension::Security);
    }

    /// CWE mapping: denial-of-service → CWE-400.
    #[test]
    fn map_rustsec_cwe_denial_of_service() {
        let cats = vec!["denial-of-service".to_string()];
        assert_eq!(map_rustsec_cwe(&cats), vec!["CWE-400".to_string()]);
    }

    /// CWE mapping: crypto-failure → CWE-327.
    #[test]
    fn map_rustsec_cwe_crypto_failure() {
        let cats = vec!["crypto-failure".to_string()];
        assert_eq!(map_rustsec_cwe(&cats), vec!["CWE-327".to_string()]);
    }

    /// CWE mapping: code-execution → CWE-94.
    #[test]
    fn map_rustsec_cwe_code_execution() {
        let cats = vec!["code-execution".to_string()];
        assert_eq!(map_rustsec_cwe(&cats), vec!["CWE-94".to_string()]);
    }

    /// CWE mapping: unknown category → empty.
    #[test]
    fn map_rustsec_cwe_unknown_empty() {
        let cats = vec!["unknown-category".to_string()];
        assert!(map_rustsec_cwe(&cats).is_empty());
    }
}
