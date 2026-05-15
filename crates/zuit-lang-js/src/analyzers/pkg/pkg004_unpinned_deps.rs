//! `PKG004-unpinned-deps` — flags dependency ranges that are unpinned.
//!
//! Ranges starting with `*`, `latest`, `>`, or the empty string accept
//! arbitrary future versions, creating a supply-chain risk. Deps in
//! `dependencies` are Medium; those in `devDependencies` are Low (they only
//! affect the developer machine, not consumers).

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

/// Rule ID for the unpinned-deps check.
const RULE_ID: &str = "PKG004-unpinned-deps";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG004-unpinned-deps.md",
    cwe: &[],
    owasp: &[],
};

/// Returns `true` if the version range is considered unpinned.
fn is_unpinned(range: &str) -> bool {
    let trimmed = range.trim();
    trimmed.is_empty() || trimmed == "*" || trimmed == "latest" || trimmed.starts_with('>')
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

/// Scan a single dep map (either `dependencies` or `devDependencies`), emitting
/// one finding per unpinned entry.
fn scan_deps(
    root: &std::path::Path,
    deps: &serde_json::Map<String, serde_json::Value>,
    severity: Severity,
    findings: &mut Vec<Finding>,
) {
    for (name, version_val) in deps {
        let version = version_val.as_str().unwrap_or_default();
        if is_unpinned(version) {
            let display_version = if version.is_empty() {
                "<empty>".to_string()
            } else {
                version.to_string()
            };
            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Custom("supply_chain".to_string()),
                rule_id: RULE_ID.to_string(),
                severity,
                message: format!(
                    "dependency `{name}` has an unpinned version range `{display_version}`; \
                     use an exact version or a narrow semver range"
                ),
                location: pkg_json_location(root),
                suggestion: Some(format!(
                    "Pin `{name}` to a specific version (e.g. `\"1.2.3\"`) or a \
                     narrow range (e.g. `\"^1.2.3\"`) to prevent unexpected updates."
                )),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }
    }
}

/// Analyzer that emits `PKG004-unpinned-deps` for dependency ranges that
/// accept arbitrary future versions.
pub struct Pkg004UnpinnedDepsAnalyzer;

impl Analyzer for Pkg004UnpinnedDepsAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("supply_chain".to_string())
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

        let mut findings = Vec::new();

        if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) {
            scan_deps(&project.root, deps, Severity::Medium, &mut findings);
        }
        if let Some(dev_deps) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
            scan_deps(&project.root, dev_deps, Severity::Low, &mut findings);
        }

        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use zuit_core::{Config, Project};

    fn write(dir: &std::path::Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).expect("invariant: temp dir is writable");
    }

    fn run(dir: &std::path::Path) -> Vec<Finding> {
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let project = Project::new(dir.to_path_buf(), vec![]);
        Pkg004UnpinnedDepsAnalyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn star_dep_in_dependencies_emits_medium() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"lodash":"*"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(findings[0].message.contains("lodash"));
    }

    #[test]
    fn star_dep_in_dev_dependencies_emits_low() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"devDependencies":{"jest":"*"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn latest_range_emits_finding() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"react":"latest"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn greater_than_range_emits_finding() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"express":">4.0.0"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
    }

    #[test]
    fn pinned_dep_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"lodash":"^4.17.21","react":"~18.2.0"}}"#,
        );
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_deps_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","version":"1.0.0"}"#,
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
    fn empty_string_version_emits_finding() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "package.json", r#"{"dependencies":{"foo":""}}"#);
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
    }
}
