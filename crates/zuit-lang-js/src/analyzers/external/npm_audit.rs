//! `NpmAuditAnalyzer` — reads a saved `npm audit --json` output file and emits
//! security findings.
//!
//! # Critical design decision
//!
//! This adapter **never** spawns `npm audit`. It only reads a pre-saved JSON
//! file. This is intentional: `npm audit` requires network access and a valid
//! `node_modules` tree; both violate the project's "strictly offline" policy.
//!
//! # Saved-file path
//!
//! The adapter looks for `<project_root>/zuit-npm-audit.json`.  If the
//! file is absent, one `JS/npm-audit-missing` [`Severity::Info`] finding is
//! emitted to inform the user how to produce the file.  This is an
//! *informational* state — the absence of the file is the expected default for
//! projects that have not yet opted in.
//!
//! # JSON schema
//!
//! Supports npm v7+ audit JSON (`auditReportVersion: 2`):
//!
//! ```json
//! {
//!   "vulnerabilities": {
//!     "<pkg>": {
//!       "name": "...",
//!       "severity": "low|moderate|high|critical",
//!       "via": [{"source": 12345, "name": "...", "url": "...", "title": "..."}]
//!     }
//!   }
//! }
//! ```
//!
//! All fields use `#[serde(default)]` to tolerate schema drift across npm
//! versions.

use std::collections::HashMap;
use std::path::PathBuf;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use serde::Deserialize;

use crate::error::JsError;

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when the saved audit file is absent.
pub const RULE_MISSING: &str = "JS/npm-audit-missing";

/// File name zuit looks for in the project root.
const AUDIT_FILE_NAME: &str = "zuit-npm-audit.json";

// ── JSON deserialization model ────────────────────────────────────────────────

/// Top-level structure of npm v7+ audit JSON.
#[derive(Debug, Deserialize, Default)]
struct NpmAuditReport {
    /// Map of package name → vulnerability entry.
    #[serde(default)]
    vulnerabilities: HashMap<String, NpmVulnerability>,
}

/// A single vulnerability entry for a package.
#[derive(Debug, Deserialize, Default)]
struct NpmVulnerability {
    /// Package name (may differ from the map key for transitive deps).
    #[serde(default)]
    name: String,
    /// Overall severity string: `"low"`, `"moderate"`, `"high"`, `"critical"`.
    #[serde(default)]
    severity: String,
    /// Advisory chain — the first entry is the primary advisory.
    #[serde(default)]
    via: Vec<NpmVia>,
}

/// One advisory in the `via` chain.
#[derive(Debug, Deserialize, Default)]
struct NpmVia {
    /// npm advisory ID (numeric).
    #[serde(default)]
    source: u64,
    /// Advisory title / description.
    #[serde(default)]
    title: String,
    /// Advisory URL.
    #[serde(default)]
    url: String,
}

// ── Severity mapping ──────────────────────────────────────────────────────────

/// Maps an npm audit severity string to a zuit [`Severity`].
///
/// | npm severity | zuit [`Severity`] |
/// |---|---|
/// | `"critical"` | [`Severity::Critical`] |
/// | `"high"` | [`Severity::High`] |
/// | `"moderate"` | [`Severity::Medium`] |
/// | `"low"` | [`Severity::Low`] |
/// | other | [`Severity::Info`] |
fn map_npm_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

// ── Core parsing function (pure — no I/O) ─────────────────────────────────────

/// Parses npm audit JSON and returns a [`Vec<Finding>`].
///
/// This function is **pure** — it does not touch the filesystem or spawn any
/// processes. It is the primary unit-test target for this module.
///
/// # Rule ID convention
///
/// Each finding's rule id is `JS/npm-audit/<advisory_id>` where
/// `<advisory_id>` is the numeric `via[0].source` when available, otherwise
/// the package name.
///
/// # Errors
///
/// Returns [`JsError::Json`] if `json` is not valid npm audit JSON.
pub fn parse_npm_audit_output(json: &str) -> Result<Vec<Finding>, JsError> {
    let report: NpmAuditReport = serde_json::from_str(json)?;

    let mut findings = Vec::new();
    for vuln in report.vulnerabilities.values() {
        let severity = map_npm_severity(&vuln.severity);

        // Use the primary advisory's source ID when available.
        let advisory_id = vuln
            .via
            .first()
            .filter(|v| v.source != 0)
            .map_or_else(|| vuln.name.clone(), |v| v.source.to_string());

        let rule_id = format!("JS/npm-audit/{advisory_id}");

        let (message, url) = if let Some(via) = vuln.via.first() {
            let msg = if via.title.is_empty() {
                format!("Vulnerable dependency '{}' ({})", vuln.name, vuln.severity)
            } else {
                format!(
                    "Vulnerable dependency '{}': {} ({})",
                    vuln.name, via.title, vuln.severity
                )
            };
            (msg, via.url.clone())
        } else {
            (
                format!("Vulnerable dependency '{}' ({})", vuln.name, vuln.severity),
                String::new(),
            )
        };

        let references = if url.is_empty() { vec![] } else { vec![url] };

        let zero = Span::new(ByteOffset(0), ByteOffset(0));
        findings.push(Finding {
            analyzer: AnalyzerId::new("NpmAuditAnalyzer"),
            dimension: Dimension::Security,
            rule_id,
            severity,
            message,
            location: Location {
                file: PathBuf::from(AUDIT_FILE_NAME),
                span: zero,
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 1),
            },
            suggestion: Some(
                "Run `npm audit fix` or upgrade the affected dependency to a patched version."
                    .to_string(),
            ),
            references,
            cwe: vec![],
            owasp: vec![],
        });
    }

    Ok(findings)
}

// ── Helper: info finding at project root ──────────────────────────────────────

fn root_info_finding(project: &Project, rule_id: &str, message: String) -> Finding {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Finding {
        analyzer: AnalyzerId::new("NpmAuditAnalyzer"),
        dimension: Dimension::Security,
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

/// Reads a saved `npm audit --json` output and emits security findings.
///
/// This adapter never spawns `npm audit`. It only reads
/// `<project_root>/zuit-npm-audit.json`. If the file is absent, one
/// `JS/npm-audit-missing` Info finding is emitted.
pub struct NpmAuditAnalyzer;

impl zuit_core::Analyzer for NpmAuditAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("NpmAuditAnalyzer")
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        &[RuleMeta {
            id: RULE_MISSING,
            default_severity: Severity::Info,
            doc_path: "docs/rules/JS-npm-audit.md",
            cwe: &[],
            owasp: &[],
        }]
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
        let audit_path = project.root.join(AUDIT_FILE_NAME);

        if !audit_path.exists() {
            return vec![root_info_finding(
                project,
                RULE_MISSING,
                format!(
                    "No saved npm audit file found at '{AUDIT_FILE_NAME}'. \
                     To enable npm audit findings, run `npm audit --json > {AUDIT_FILE_NAME}` \
                     from the project root and commit the file."
                ),
            )];
        }

        let json = match std::fs::read_to_string(&audit_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "failed to read {}: {}; skipping npm audit",
                    audit_path.display(),
                    e
                );
                return vec![];
            }
        };

        match parse_npm_audit_output(&json) {
            Ok(findings) => findings,
            Err(e) => {
                tracing::warn!("failed to parse npm audit output: {e}; skipping");
                vec![]
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use zuit_core::{Analyzer, Config, Project, Severity};

    use super::*;

    fn empty_project(root: impl Into<PathBuf>) -> Project {
        Project::new(root.into(), vec![])
    }

    // 1. Happy path: fixture file → ≥2 findings with correct severities/rule ids
    #[test]
    fn parse_npm_audit_happy_path() {
        let json = include_str!("../../../tests/fixtures/npm-audit-output.json");
        let findings = parse_npm_audit_output(json).expect("parse must succeed");

        assert!(
            findings.len() >= 2,
            "expected ≥2 findings, got {}",
            findings.len()
        );

        // Check that we have findings with JS/npm-audit/ prefix.
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id.starts_with("JS/npm-audit/")),
            "all rule ids must start with JS/npm-audit/"
        );

        // Check that a High finding exists (lodash advisory).
        assert!(
            findings.iter().any(|f| f.severity == Severity::High),
            "expected a High severity finding"
        );

        // Check that a Critical finding exists (minimist advisory).
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "expected a Critical severity finding"
        );

        // Check that a Low finding exists.
        assert!(
            findings.iter().any(|f| f.severity == Severity::Low),
            "expected a Low severity finding"
        );

        // All findings use Security dimension.
        assert!(
            findings
                .iter()
                .all(|f| f.dimension == zuit_core::Dimension::Security),
            "all findings must have Security dimension"
        );
    }

    // 2. Empty vulnerabilities map → 0 findings
    #[test]
    fn parse_npm_audit_empty_clean() {
        let json = r#"{"vulnerabilities": {}}"#;
        let findings = parse_npm_audit_output(json).expect("parse must succeed");
        assert!(
            findings.is_empty(),
            "expected 0 findings, got {findings:#?}"
        );
    }

    // 3. Malformed JSON → JsError::Json
    #[test]
    fn parse_npm_audit_malformed_returns_error() {
        let result = parse_npm_audit_output("not json");
        assert!(
            matches!(result, Err(JsError::Json(_))),
            "expected JsError::Json, got {result:?}"
        );
    }

    // 4. Saved file missing → exactly 1 JS/npm-audit-missing Info finding
    #[test]
    fn npm_audit_saved_file_missing_emits_single_info() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project = empty_project(tmp.path());
        let analyzer = NpmAuditAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding, got {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_MISSING);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    // 5. Severity map: critical
    #[test]
    fn parse_npm_audit_severity_map_critical() {
        let json = r#"{
            "vulnerabilities": {
                "pkg": {"name": "pkg", "severity": "critical", "via": []}
            }
        }"#;
        let findings = parse_npm_audit_output(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    // 6. Severity map: moderate → Medium
    #[test]
    fn parse_npm_audit_severity_map_moderate() {
        let json = r#"{
            "vulnerabilities": {
                "pkg": {"name": "pkg", "severity": "moderate", "via": []}
            }
        }"#;
        let findings = parse_npm_audit_output(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    // 7. Severity map: unknown → Info
    #[test]
    fn parse_npm_audit_severity_map_unknown() {
        let json = r#"{
            "vulnerabilities": {
                "pkg": {"name": "pkg", "severity": "bogus", "via": []}
            }
        }"#;
        let findings = parse_npm_audit_output(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    // 8. Rule ID uses via[0].source when available
    #[test]
    fn parse_npm_audit_rule_id_uses_advisory_source() {
        let json = r#"{
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "via": [{"source": 999888, "title": "Prototype Pollution", "url": ""}]
                }
            }
        }"#;
        let findings = parse_npm_audit_output(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "JS/npm-audit/999888");
    }

    // 9. Rule ID falls back to package name when source is 0 / absent
    #[test]
    fn parse_npm_audit_rule_id_falls_back_to_pkg_name() {
        let json = r#"{
            "vulnerabilities": {
                "mypkg": {
                    "name": "mypkg",
                    "severity": "low",
                    "via": []
                }
            }
        }"#;
        let findings = parse_npm_audit_output(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "JS/npm-audit/mypkg");
    }
}
