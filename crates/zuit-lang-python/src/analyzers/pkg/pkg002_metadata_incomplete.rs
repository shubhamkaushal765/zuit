//! `PKG002-metadata-incomplete` — emits when `[project]` table is missing
//! the required `name` or `version` fields.
//!
//! PEP 517/518/621 requires both `name` and `version` (or `dynamic = ["version"]`)
//! in `[project]`.  Without them, build tools fail silently or produce broken
//! distributions.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::pkg001_invalid_pyproject::pyproject_finding;

const RULE_ID: &str = "PKG002-metadata-incomplete";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG002-metadata-incomplete.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG002` when `[project]` is missing `name` or `version`.
pub struct Pkg002MetadataIncomplete;

impl zuit_core::Analyzer for Pkg002MetadataIncomplete {
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
            return vec![pyproject_finding(
                project,
                &pyproject_path,
                RULE_ID,
                Severity::Medium,
                "pyproject.toml is missing the required [project] table".to_string(),
                Some(
                    "Add a [project] table with at least `name` and `version` fields.".to_string(),
                ),
            )];
        };

        let mut missing: Vec<&str> = Vec::new();
        if project_table.get("name").is_none() {
            missing.push("name");
        }

        // `version` is optional when listed in `dynamic`.
        let has_version = project_table.get("version").is_some();
        let dynamic_has_version = project_table
            .get("dynamic")
            .and_then(|v| v.as_array())
            .is_some_and(|arr| arr.iter().any(|item| item.as_str() == Some("version")));

        if !has_version && !dynamic_has_version {
            missing.push("version");
        }

        if missing.is_empty() {
            return Vec::new();
        }

        vec![pyproject_finding(
            project,
            &pyproject_path,
            RULE_ID,
            Severity::Medium,
            format!(
                "pyproject.toml [project] table is missing required field(s): {}",
                missing.join(", ")
            ),
            Some("Add the missing fields to [project] or list them under `dynamic`.".to_string()),
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
        let analyzer = Pkg002MetadataIncomplete;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg002_missing_name_and_version_emits_medium() {
        let findings = run("[project]\n");
        assert_eq!(findings.len(), 1, "expected 1 PKG002 finding");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("name"));
        assert!(findings[0].message.contains("version"));
    }

    #[test]
    fn pkg002_complete_project_emits_zero() {
        let findings = run("[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\n");
        assert!(findings.is_empty(), "expected 0 findings: {findings:#?}");
    }

    #[test]
    fn pkg002_dynamic_version_accepted() {
        let findings = run("[project]\nname = \"my-pkg\"\ndynamic = [\"version\"]\n");
        assert!(
            findings.is_empty(),
            "dynamic version should be accepted: {findings:#?}"
        );
    }

    #[test]
    fn pkg002_suppression_directive_works() {
        // Valid pyproject.toml — no finding to suppress (see PKG001 note).
        let findings = run("[project]\nname = \"x\"\nversion = \"1.0\"\n");
        assert!(findings.is_empty());
    }
}
