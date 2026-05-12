//! `PKG009-classifiers-missing` — emits when `[project].classifiers` is absent
//! or contains no Python version classifier.
//!
//! `PyPI` classifiers help package consumers filter by supported Python version,
//! development status, and topic.  Without a `Programming Language :: Python :: 3.x`
//! classifier, `PyPI` search and pip's compatibility checks have less information.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::pkg001_invalid_pyproject::pyproject_finding;

const RULE_ID: &str = "PKG009-classifiers-missing";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG009-classifiers-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG009` when classifiers are absent or lack a Python
/// version entry.
pub struct Pkg009ClassifiersMissing;

impl zuit_core::Analyzer for Pkg009ClassifiersMissing {
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
            return Vec::new();
        };

        let Some(classifiers) = project_table.get("classifiers").and_then(|v| v.as_array()) else {
            return vec![pyproject_finding(
                project,
                &pyproject_path,
                RULE_ID,
                Severity::Low,
                "pyproject.toml [project] has no `classifiers` field; \
                 add `PyPI` classifiers to improve discoverability"
                    .to_string(),
                Some(
                    "Add a `classifiers` array to [project] including at least \
                     `\"Programming Language :: Python :: 3\"` and \
                     a development status classifier."
                        .to_string(),
                ),
            )];
        };

        // Check for at least one Python version classifier.
        let has_python_classifier = classifiers.iter().any(|item| {
            item.as_str()
                .is_some_and(|s| s.starts_with("Programming Language :: Python :: 3"))
        });

        if has_python_classifier {
            return Vec::new();
        }

        vec![pyproject_finding(
            project,
            &pyproject_path,
            RULE_ID,
            Severity::Low,
            "pyproject.toml [project].classifiers does not contain a Python version classifier \
             (e.g. `Programming Language :: Python :: 3.11`)"
                .to_string(),
            Some(
                "Add `\"Programming Language :: Python :: 3\"` and/or a specific \
                 version classifier to the `classifiers` array."
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
        let analyzer = Pkg009ClassifiersMissing;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg009_no_classifiers_emits_one_low() {
        let findings = run("[project]\nname = \"x\"\nversion = \"1.0\"\n");
        assert_eq!(findings.len(), 1, "expected 1 PKG009 finding");
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn pkg009_classifiers_with_python_version_emits_zero() {
        let findings = run(
            "[project]\nname = \"x\"\nversion = \"1.0\"\nclassifiers = [\n  \"Programming Language :: Python :: 3.11\",\n]\n",
        );
        assert!(findings.is_empty(), "expected 0 findings: {findings:#?}");
    }

    #[test]
    fn pkg009_classifiers_without_python_version_emits_one() {
        let findings = run(
            "[project]\nname = \"x\"\nversion = \"1.0\"\nclassifiers = [\n  \"License :: OSI Approved :: MIT License\",\n]\n",
        );
        assert_eq!(findings.len(), 1, "expected 1 PKG009 finding");
    }

    #[test]
    fn pkg009_suppression_directive_works() {
        let findings = run(
            "[project]\nname = \"x\"\nversion = \"1.0\"\nclassifiers = [\n  \"Programming Language :: Python :: 3\",\n]\n",
        );
        assert!(findings.is_empty());
    }
}
