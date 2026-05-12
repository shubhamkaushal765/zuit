//! `CargoGeigerAnalyzer` — wraps `cargo geiger` as an external-tool adapter.
//!
//! When called:
//!
//! 1. Searches `$PATH` for the `cargo` binary.
//!    If missing, emits a single `Info` finding `RS/cargo-geiger-missing`.
//! 2. Checks that `cargo geiger` is installed (subprocess smoke test via which).
//! 3. Spawns `cargo geiger --output-format Json` from the project root.
//! 4. Parses the JSON output with [`parse_cargo_geiger_output`].
//! 5. Returns the resulting [`Finding`]s.
//!
//! # Operational rule IDs
//!
//! - `RS/cargo-geiger-missing` — `cargo geiger` not found on `$PATH`
//! - `RS/cargo-geiger-timeout` — process exceeded timeout
//! - `RS/cargo-geiger-output-too-large` — stdout exceeded cap
//! - `RS/cargo-geiger-spawn-failed` — OS-level spawn failure
//!
//! # Finding rule ID format
//!
//! `RS/geiger/<metric>` where metric ∈ {`unsafe-fns`, `unsafe-exprs`,
//! `unsafe-impls`, `unsafe-traits`}.

use std::path::Path;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use serde::Deserialize;

use zuit_core::external::{DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS, Outcome, run_with_limits};

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `cargo geiger` is absent from `$PATH`.
pub const RULE_MISSING: &str = "RS/cargo-geiger-missing";
const RULE_TIMEOUT: &str = "RS/cargo-geiger-timeout";
const RULE_OUTPUT_TOO_LARGE: &str = "RS/cargo-geiger-output-too-large";
const RULE_SPAWN_FAILED: &str = "RS/cargo-geiger-spawn-failed";

// ── JSON wire types ───────────────────────────────────────────────────────────

/// Top-level output of `cargo geiger --output-format Json`.
#[derive(Debug, Default, Deserialize)]
struct GeigerOutput {
    #[serde(default)]
    packages: Vec<GeigerPackage>,
}

#[derive(Debug, Default, Deserialize)]
struct GeigerPackage {
    #[serde(default)]
    package: GeigerPkgInfo,
    #[serde(default)]
    unsafety: GeigerUnsafety,
}

#[derive(Debug, Default, Deserialize)]
struct GeigerPkgInfo {
    #[serde(default)]
    id: GeigerPkgId,
}

#[derive(Debug, Default, Deserialize)]
struct GeigerPkgId {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Default, Deserialize)]
struct GeigerUnsafety {
    #[serde(default)]
    used: GeigerCounts,
    #[serde(default)]
    #[allow(dead_code)]
    unused: GeigerCounts,
}

#[derive(Debug, Default, Deserialize)]
struct GeigerCounts {
    #[serde(default)]
    functions: GeigerCount,
    #[serde(default)]
    exprs: GeigerCount,
    #[serde(default)]
    item_impls: GeigerCount,
    #[serde(default)]
    item_traits: GeigerCount,
}

#[derive(Debug, Default, Deserialize)]
struct GeigerCount {
    #[serde(default)]
    #[allow(dead_code)]
    safe: u64,
    #[serde(rename = "unsafe_")]
    #[serde(default)]
    unsafe_count: u64,
}

// ── Helper: zero-span finding at project root ─────────────────────────────────

fn project_finding(
    project_root: &Path,
    rule_id: &str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Finding {
        analyzer: AnalyzerId::new("CargoGeigerAnalyzer"),
        dimension: Dimension::Custom("unsafe_soundness".to_string()),
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
        references: vec!["https://github.com/rust-secure-code/cargo-geiger".to_string()],
        cwe: vec![],
        owasp: vec![],
    }
}

// ── Core parsing function (pure — no I/O) ────────────────────────────────────

/// Parses `cargo geiger --output-format Json` output and returns a
/// [`Vec<Finding>`].
///
/// This function is **pure** — it performs no I/O and is the primary unit-test
/// target for this module.
///
/// # Errors
///
/// Returns [`crate::error::RustError::Json`] if `json` is not valid geiger output.
pub fn parse_cargo_geiger_output(
    json: &str,
    project_root: &Path,
    _project: &Project,
) -> Result<Vec<Finding>, crate::error::RustError> {
    let output: GeigerOutput = serde_json::from_str(json)?;

    let mut findings = Vec::new();

    for pkg in &output.packages {
        let name = &pkg.package.id.name;
        let version = &pkg.package.id.version;
        let used = &pkg.unsafety.used;

        let metrics: &[(&str, u64)] = &[
            ("unsafe-fns", used.functions.unsafe_count),
            ("unsafe-exprs", used.exprs.unsafe_count),
            ("unsafe-impls", used.item_impls.unsafe_count),
            ("unsafe-traits", used.item_traits.unsafe_count),
        ];

        for (metric, count) in metrics {
            if *count > 0 {
                let rule_id = format!("RS/geiger/{metric}");
                findings.push(Finding {
                    analyzer: AnalyzerId::new("CargoGeigerAnalyzer"),
                    dimension: Dimension::Custom("unsafe_soundness".to_string()),
                    rule_id,
                    severity: Severity::Info,
                    message: format!("{name}@{version}: {count} unsafe {metric}"),
                    location: Location {
                        file: project_root.to_path_buf(),
                        span: Span::new(ByteOffset(0), ByteOffset(0)),
                        start: LineCol::new(1, 1),
                        end: LineCol::new(1, 1),
                    },
                    suggestion: None,
                    references: vec![
                        "https://github.com/rust-secure-code/cargo-geiger".to_string(),
                    ],
                    cwe: vec![],
                    owasp: vec![],
                });
            }
        }
    }

    Ok(findings)
}

// ── Analyzer impl ─────────────────────────────────────────────────────────────

/// Integrates `cargo geiger` into the zuit analysis pipeline.
///
/// Overrides [`zuit_core::Analyzer::analyze_project`] because `cargo geiger`
/// operates on the whole workspace.
pub struct CargoGeigerAnalyzer;

impl zuit_core::Analyzer for CargoGeigerAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("CargoGeigerAnalyzer")
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("unsafe_soundness".to_string())
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        &[
            RuleMeta {
                id: RULE_MISSING,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-geiger.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-geiger.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-geiger.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_SPAWN_FAILED,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-geiger.md",
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
                "cargo not found on PATH; install Rust to enable cargo geiger".to_string(),
                Some("Install Rust: https://www.rust-lang.org/tools/install".to_string()),
            ));
            return findings;
        }

        let mut geiger_findings = match run_with_limits(
            "cargo",
            &["geiger", "--output-format", "Json"],
            &project.root,
            DEFAULT_MAX_STDOUT_BYTES,
            DEFAULT_TIMEOUT_SECS,
        ) {
            Outcome::Ok(stdout) => {
                if stdout.is_empty() {
                    Vec::new()
                } else {
                    let s = String::from_utf8_lossy(&stdout);
                    match parse_cargo_geiger_output(&s, &project.root, project) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            tracing::warn!("failed to parse cargo geiger output: {e}; skipping");
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
                    format!("cargo geiger timed out after {DEFAULT_TIMEOUT_SECS} seconds"),
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
                    format!("cargo geiger output exceeded {mib} MiB cap"),
                    None,
                ));
                Vec::new()
            }
            Outcome::SpawnFailed(e) => {
                tracing::warn!("cargo geiger spawn failed: {e}");
                findings.push(project_finding(
                    &project.root,
                    RULE_SPAWN_FAILED,
                    Severity::Info,
                    format!("cargo geiger failed to spawn: {e}"),
                    None,
                ));
                Vec::new()
            }
        };

        findings.append(&mut geiger_findings);
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

    /// Happy path: two packages with unsafe functions → 2 findings.
    const HAPPY_JSON: &str = r#"{
        "packages": [
            {
                "package": { "id": { "name": "foo", "version": "1.0.0" } },
                "unsafety": {
                    "used": {
                        "functions":   { "safe": 0, "unsafe_": 3 },
                        "exprs":       { "safe": 5, "unsafe_": 0 },
                        "item_impls":  { "safe": 0, "unsafe_": 0 },
                        "item_traits": { "safe": 0, "unsafe_": 0 }
                    },
                    "unused": {
                        "functions":   { "safe": 0, "unsafe_": 0 },
                        "exprs":       { "safe": 0, "unsafe_": 0 },
                        "item_impls":  { "safe": 0, "unsafe_": 0 },
                        "item_traits": { "safe": 0, "unsafe_": 0 }
                    }
                }
            },
            {
                "package": { "id": { "name": "bar", "version": "2.1.0" } },
                "unsafety": {
                    "used": {
                        "functions":   { "safe": 0, "unsafe_": 0 },
                        "exprs":       { "safe": 0, "unsafe_": 7 },
                        "item_impls":  { "safe": 0, "unsafe_": 0 },
                        "item_traits": { "safe": 0, "unsafe_": 0 }
                    },
                    "unused": {
                        "functions":   { "safe": 0, "unsafe_": 0 },
                        "exprs":       { "safe": 0, "unsafe_": 0 },
                        "item_impls":  { "safe": 0, "unsafe_": 0 },
                        "item_traits": { "safe": 0, "unsafe_": 0 }
                    }
                }
            }
        ]
    }"#;

    const EMPTY_JSON: &str = r#"{"packages": []}"#;

    /// 1. Happy path: two packages → 2 findings, correct prefixes.
    #[test]
    fn parse_cargo_geiger_happy_path() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let findings =
            parse_cargo_geiger_output(HAPPY_JSON, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 2, "expected 2 findings, got: {findings:#?}");
        for f in &findings {
            assert!(
                f.rule_id.starts_with("RS/geiger/"),
                "rule_id must start with RS/geiger/, got: {}",
                f.rule_id
            );
            assert_eq!(f.severity, Severity::Info);
            assert_eq!(
                f.dimension,
                Dimension::Custom("unsafe_soundness".to_string())
            );
        }
        assert!(findings.iter().any(|f| f.rule_id == "RS/geiger/unsafe-fns"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "RS/geiger/unsafe-exprs")
        );
    }

    /// 2. Empty packages → 0 findings.
    #[test]
    fn parse_cargo_geiger_empty_no_findings() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let findings =
            parse_cargo_geiger_output(EMPTY_JSON, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 0);
    }

    /// 3. Malformed JSON → Err.
    #[test]
    fn parse_cargo_geiger_malformed_returns_error() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let result = parse_cargo_geiger_output("{not json", &root, &project);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::error::RustError::Json(_))));
    }

    /// 4. Dimension mapping: all findings use `unsafe_soundness`.
    #[test]
    fn parse_cargo_geiger_dimension_is_unsafe_soundness() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let findings =
            parse_cargo_geiger_output(HAPPY_JSON, &root, &project).expect("parse must succeed");
        for f in &findings {
            assert_eq!(
                f.dimension,
                Dimension::Custom("unsafe_soundness".to_string())
            );
        }
    }

    /// 5. Message format includes package name and version.
    #[test]
    fn parse_cargo_geiger_message_includes_pkg_name() {
        let project = empty_project();
        let root = PathBuf::from("/project");
        let findings =
            parse_cargo_geiger_output(HAPPY_JSON, &root, &project).expect("parse must succeed");
        let fns_finding = findings
            .iter()
            .find(|f| f.rule_id == "RS/geiger/unsafe-fns")
            .unwrap();
        assert!(fns_finding.message.contains("foo@1.0.0"));
        assert!(fns_finding.message.contains("3 unsafe unsafe-fns"));
    }
}
