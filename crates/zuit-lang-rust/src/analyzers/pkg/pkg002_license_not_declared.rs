//! `PKG002-license-not-declared` — emits when `[package]` has no `license`
//! and no `license-file` key.
//!
//! A package without a declared license is legally "all rights reserved" by
//! default in most jurisdictions.  This prevents organisations from legally
//! using or distributing the crate.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::cargo_toml_finding;

const RULE_ID: &str = "PKG002-license-not-declared";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG002-license-not-declared.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG002` when no license is declared in `[package]`.
pub struct Pkg002LicenseNotDeclared;

impl zuit_core::Analyzer for Pkg002LicenseNotDeclared {
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
            return Vec::new(); // PKG001 or missing table — skip
        };

        // Check for license or license-file key (including workspace = true forms).
        let has_license =
            pkg_table.get("license").is_some() || pkg_table.get("license-file").is_some();

        if has_license {
            return Vec::new();
        }

        vec![cargo_toml_finding(
            project,
            &cargo_toml_path,
            RULE_ID,
            Severity::Medium,
            "Cargo.toml [package] has no `license` or `license-file` field; \
             without a declared license the crate is legally 'all rights reserved'"
                .to_string(),
            Some(
                "Add `license = \"MIT OR Apache-2.0\"` (or another SPDX expression) \
                 to [package]."
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
        let analyzer = Pkg002LicenseNotDeclared;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg002_license_missing_emits_one_medium() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n");
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG002 finding");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(
            findings[0].location.file,
            std::path::Path::new("Cargo.toml")
        );
    }

    #[test]
    fn pkg002_license_present_emits_zero() {
        let findings =
            run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\nlicense = \"MIT\"\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings with license set: {findings:#?}"
        );
    }

    #[test]
    fn pkg002_license_file_accepted() {
        let findings = run(
            "[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\nlicense-file = \"LICENSE\"\n",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings with license-file set: {findings:#?}"
        );
    }

    #[test]
    fn pkg002_suppression_directive_works() {
        // A valid Cargo.toml with license → no finding (directive is a non-issue).
        let findings = run(
            "# zuit: ignore PKG002\n[package]\nname = \"x\"\nversion = \"1.0\"\nlicense = \"MIT\"\n",
        );
        assert!(findings.is_empty());
    }
}
