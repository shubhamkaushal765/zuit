//! `PKG008-keywords-categories-missing` — emits when `[package]` has neither
//! `keywords` nor `categories`.
//!
//! Keywords and categories help users discover a crate on crates.io.  Omitting
//! both makes the crate significantly harder to find via search or browsing.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::cargo_toml_finding;

const RULE_ID: &str = "PKG008-keywords-categories-missing";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG008-keywords-categories-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG008` when both `keywords` and `categories` are
/// absent from `[package]`.
pub struct Pkg008KeywordsCategoriesMissing;

impl zuit_core::Analyzer for Pkg008KeywordsCategoriesMissing {
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

    fn analyze_file(
        &self,
        _ctx: &AnalysisContext<'_>,
        _file: &zuit_core::ParsedFile,
    ) -> Vec<Finding> {
        Vec::new()
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let manifest = manifest_for(project);
        let Some(doc) = &manifest.cargo_toml else {
            return Vec::new();
        };

        let cargo_toml_path = manifest
            .cargo_toml_path
            .clone()
            .unwrap_or_else(|| project.root.join("Cargo.toml"));

        let Some(pkg_table) = doc.get("package").and_then(|v| v.as_table()) else {
            return Vec::new();
        };

        let has_keywords = pkg_table.get("keywords").is_some();
        let has_categories = pkg_table.get("categories").is_some();

        if has_keywords || has_categories {
            return Vec::new();
        }

        vec![cargo_toml_finding(
            project,
            &cargo_toml_path,
            RULE_ID,
            Severity::Low,
            "Cargo.toml [package] has neither `keywords` nor `categories`; \
             the crate will be harder to discover on crates.io"
                .to_string(),
            Some(
                "Add `keywords = [\"parser\", \"cli\"]` and/or \
                 `categories = [\"command-line-utilities\"]` to [package].  \
                 See <https://crates.io/categories> for the allowed category slugs."
                    .to_string(),
            ),
        )]
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zuit_core::{Analyzer, Config, Project};

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg008KeywordsCategoriesMissing;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg008_both_missing_emits_one_low() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n");
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG008 finding");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(
            findings[0].location.file,
            std::path::Path::new("Cargo.toml")
        );
    }

    #[test]
    fn pkg008_keywords_present_emits_zero() {
        let findings =
            run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\nkeywords = [\"parser\"]\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings with keywords: {findings:#?}"
        );
    }

    #[test]
    fn pkg008_categories_present_emits_zero() {
        let findings = run(
            "[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\ncategories = [\"parser-implementations\"]\n",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings with categories: {findings:#?}"
        );
    }

    #[test]
    fn pkg008_suppression_directive_works() {
        let findings = run(
            "# zuit: ignore PKG008\n[package]\nname = \"x\"\nversion = \"1.0\"\nkeywords = [\"x\"]\n",
        );
        assert!(findings.is_empty());
    }
}
