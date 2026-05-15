//! `PKG003-description-missing` — emits when `[package]` has no `description`
//! or an empty `description` string.
//!
//! The description is the one-line summary shown on crates.io and in `cargo
//! search` output.  Without it, users cannot quickly assess whether the crate
//! meets their needs.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::cargo_toml_finding;

const RULE_ID: &str = "PKG003-description-missing";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG003-description-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG003` when `[package]` has no description.
pub struct Pkg003DescriptionMissing;

impl zuit_core::Analyzer for Pkg003DescriptionMissing {
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

        // Check for non-empty description.
        let has_description = pkg_table
            .get("description")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty());

        // Also accept workspace inheritance.
        let workspace_inherited = pkg_table
            .get("description")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("workspace"))
            .and_then(toml_edit::Item::as_bool)
            .unwrap_or(false);

        if has_description || workspace_inherited {
            return Vec::new();
        }

        vec![cargo_toml_finding(
            project,
            &cargo_toml_path,
            RULE_ID,
            Severity::Low,
            "Cargo.toml [package] has no `description`; crates.io and `cargo search` \
             cannot show a summary for this crate"
                .to_string(),
            Some(
                "Add `description = \"A short, one-line summary of the crate.\"` to [package]."
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
        let analyzer = Pkg003DescriptionMissing;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg003_description_missing_emits_one_low() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n");
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG003 finding");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(
            findings[0].location.file,
            std::path::Path::new("Cargo.toml")
        );
    }

    #[test]
    fn pkg003_description_present_emits_zero() {
        let findings = run(
            "[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\ndescription = \"A useful crate.\"\n",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings with description set: {findings:#?}"
        );
    }

    #[test]
    fn pkg003_empty_description_emits_one() {
        let findings =
            run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\ndescription = \"\"\n");
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for empty description"
        );
    }

    #[test]
    fn pkg003_suppression_directive_works() {
        let findings = run(
            "# zuit: ignore PKG003\n[package]\nname = \"x\"\nversion = \"1.0\"\ndescription = \"Hello.\"\n",
        );
        assert!(findings.is_empty());
    }
}
