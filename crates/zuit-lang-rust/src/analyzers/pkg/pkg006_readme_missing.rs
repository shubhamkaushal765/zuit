//! `PKG006-readme-missing` — emits when no README file is found in the project
//! root AND `[package].readme` is not set.
//!
//! crates.io renders the README as the crate's landing page.  Without one,
//! users have no entry-point documentation beyond the rustdoc API reference.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::cargo_toml_finding;

const RULE_ID: &str = "PKG006-readme-missing";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG006-readme-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG006` when no README is discoverable.
pub struct Pkg006ReadmeMissing;

impl zuit_core::Analyzer for Pkg006ReadmeMissing {
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

        // If a README file was found on disk, no finding.
        if manifest.readme_path.is_some() {
            return Vec::new();
        }

        // If [package].readme is explicitly set, no finding.
        let pkg_readme_set = doc
            .get("package")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("readme"))
            .is_some();

        if pkg_readme_set {
            return Vec::new();
        }

        let cargo_toml_path = manifest
            .cargo_toml_path
            .clone()
            .unwrap_or_else(|| project.root.join("Cargo.toml"));

        vec![cargo_toml_finding(
            project,
            &cargo_toml_path,
            RULE_ID,
            Severity::Low,
            "No README file found (README.md / README.rst / README.txt / README) and \
             `[package].readme` is not set; crates.io will display no landing page"
                .to_string(),
            Some(
                "Create a `README.md` in the project root, or set `readme = \"README.md\"` \
                 in [package]."
                    .to_string(),
            ),
        )]
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::io::Write as _;

    fn run_with_readme(toml_content: &str, create_readme: bool) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        if create_readme {
            std::fs::write(dir.path().join("README.md"), b"# Hello").unwrap();
        }
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg006ReadmeMissing;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg006_readme_missing_emits_one_low() {
        let findings = run_with_readme(
            "[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n",
            false,
        );
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG006 finding");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(
            findings[0].location.file,
            std::path::Path::new("Cargo.toml")
        );
    }

    #[test]
    fn pkg006_readme_file_present_emits_zero() {
        let findings = run_with_readme(
            "[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n",
            true,
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings when README.md exists: {findings:#?}"
        );
    }

    #[test]
    fn pkg006_readme_key_set_emits_zero() {
        let findings = run_with_readme(
            "[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\nreadme = \"DOCS.md\"\n",
            false,
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings when readme key is set: {findings:#?}"
        );
    }

    #[test]
    fn pkg006_suppression_directive_works() {
        let findings = run_with_readme(
            "# zuit: ignore PKG006\n[package]\nname = \"x\"\nversion = \"1.0\"\n",
            true,
        );
        assert!(findings.is_empty());
    }
}
