//! `PKG004-license-not-declared` — emits when `[project]` has no `license`
//! or `license-files` field.
//!
//! A package without a declared license is legally "all rights reserved" by
//! default in most jurisdictions.  This prevents organisations from legally
//! using or distributing the package.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::pkg001_invalid_pyproject::pyproject_finding;

const RULE_ID: &str = "PKG004-license-not-declared";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG004-license-not-declared.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG004` when the license is absent from `[project]`.
pub struct Pkg004LicenseNotDeclared;

impl zuit_core::Analyzer for Pkg004LicenseNotDeclared {
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
        let Some(doc) = &manifest.pyproject else {
            return Vec::new();
        };

        let pyproject_path = manifest
            .pyproject_path
            .clone()
            .unwrap_or_else(|| project.root.join("pyproject.toml"));

        let Some(project_table) = doc.get("project").and_then(|v| v.as_table()) else {
            return Vec::new(); // PKG002 will report the missing table
        };

        let has_license =
            project_table.get("license").is_some() || project_table.get("license-files").is_some();

        if has_license {
            return Vec::new();
        }

        vec![pyproject_finding(
            project,
            &pyproject_path,
            RULE_ID,
            Severity::Medium,
            "pyproject.toml [project] table has no `license` or `license-files` field; \
             without a declared license the package is legally 'all rights reserved'"
                .to_string(),
            Some(
                "Add `license = { text = \"MIT\" }` or `license-files = [\"LICENSE\"]` \
                 to [project]."
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

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg004LicenseNotDeclared;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg004_license_missing_emits_one_medium() {
        let findings = run("[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\n");
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG004 finding");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(
            findings[0].location.file,
            std::path::Path::new("pyproject.toml")
        );
    }

    #[test]
    fn pkg004_license_present_emits_zero() {
        let findings = run(
            "[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\nlicense = { text = \"MIT\" }\n",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings with license set: {findings:#?}"
        );
    }

    #[test]
    fn pkg004_license_files_accepted() {
        let findings = run(
            "[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\nlicense-files = [\"LICENSE\"]\n",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings with license-files: {findings:#?}"
        );
    }

    #[test]
    fn pkg004_suppression_directive_works() {
        // A valid pyproject.toml with license → no finding.
        let findings = run(
            "# zuit: ignore PKG004\n[project]\nname = \"x\"\nversion = \"1.0\"\nlicense = { text = \"MIT\" }\n",
        );
        assert!(findings.is_empty());
    }
}
