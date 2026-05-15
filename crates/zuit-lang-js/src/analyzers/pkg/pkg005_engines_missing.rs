//! `PKG005-engines-missing` — flags packages that do not declare a `node`
//! engine constraint.
//!
//! Without an `engines.node` field, consumers cannot know which Node.js
//! versions are supported, leading to silent runtime failures on incompatible
//! runtimes. This is a low-severity packaging hygiene issue.

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

/// Rule ID for the engines-missing check.
const RULE_ID: &str = "PKG005-engines-missing";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG005-engines-missing.md",
    cwe: &[],
    owasp: &[],
};

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

/// Analyzer that emits `PKG005-engines-missing` when `package.json` lacks an
/// `engines.node` field.
pub struct Pkg005EnginesMissingAnalyzer;

impl Analyzer for Pkg005EnginesMissingAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("packaging".to_string())
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

        let has_node_engine = pkg.get("engines").and_then(|e| e.get("node")).is_some();

        if has_node_engine {
            return vec![];
        }

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Custom("packaging".to_string()),
            rule_id: RULE_ID.to_string(),
            severity: Severity::Low,
            message: "package.json has no `engines.node` field; consumers cannot determine \
                      the required Node.js version"
                .to_string(),
            location: pkg_json_location(&project.root),
            suggestion: Some(
                "Add `\"engines\": {\"node\": \">=18\"}` (or your actual minimum version) \
                 to package.json."
                    .to_string(),
            ),
            references: vec![
                "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines".to_string(),
            ],
            cwe: META.cwe_vec(),
            owasp: META.owasp_vec(),
        }]
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
        Pkg005EnginesMissingAnalyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn engines_missing_emits_one_low() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","version":"1.0.0"}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn engines_node_present_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","engines":{"node":">=18"}}"#,
        );
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn engines_without_node_key_emits_one() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","engines":{"npm":">=8"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
    }

    #[test]
    fn no_package_json_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }
}
