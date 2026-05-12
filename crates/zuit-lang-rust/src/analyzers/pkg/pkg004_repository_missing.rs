//! `PKG004-repository-missing` — emits when `[package]` has no `repository`
//! key.
//!
//! Without a repository link, users and security teams cannot find the source
//! code, file issues, or audit the crate's history.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::cargo_toml_finding;

const RULE_ID: &str = "PKG004-repository-missing";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG004-repository-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG004` when `[package]` has no `repository` key.
pub struct Pkg004RepositoryMissing;

impl zuit_core::Analyzer for Pkg004RepositoryMissing {
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

        if pkg_table.get("repository").is_some() {
            return Vec::new();
        }

        vec![cargo_toml_finding(
            project,
            &cargo_toml_path,
            RULE_ID,
            Severity::Low,
            "Cargo.toml [package] has no `repository` field; users cannot find \
             the source code or file issues"
                .to_string(),
            Some("Add `repository = \"https://github.com/org/crate\"` to [package].".to_string()),
        )]
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::io::Write as _;

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg004RepositoryMissing;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg004_repository_missing_emits_one_low() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n");
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG004 finding");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(
            findings[0].location.file,
            std::path::Path::new("Cargo.toml")
        );
    }

    #[test]
    fn pkg004_repository_present_emits_zero() {
        let findings = run(
            "[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\nrepository = \"https://github.com/example/my-crate\"\n",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings with repository set: {findings:#?}"
        );
    }

    #[test]
    fn pkg004_suppression_directive_works() {
        let findings = run(
            "# zuit: ignore PKG004\n[package]\nname = \"x\"\nversion = \"1.0\"\nrepository = \"https://github.com/x/x\"\n",
        );
        assert!(findings.is_empty());
    }
}
