//! `PKG005-python-version-unconstrained` — emits when `[project]` has no
//! `requires-python` field.
//!
//! Without a `requires-python` constraint, pip may install the package on
//! Python versions where it does not work, causing confusing runtime errors.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::pkg001_invalid_pyproject::pyproject_finding;

const RULE_ID: &str = "PKG005-python-version-unconstrained";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG005-python-version-unconstrained.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG005` when `requires-python` is absent.
pub struct Pkg005PythonVersionUnconstrained;

impl zuit_core::Analyzer for Pkg005PythonVersionUnconstrained {
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

        if project_table.get("requires-python").is_some() {
            return Vec::new();
        }

        vec![pyproject_finding(
            project,
            &pyproject_path,
            RULE_ID,
            Severity::Low,
            "pyproject.toml [project] table has no `requires-python` constraint; \
             pip may install the package on incompatible Python versions"
                .to_string(),
            Some(
                "Add `requires-python = \">=3.9\"` (or the appropriate floor) \
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
        let analyzer = Pkg005PythonVersionUnconstrained;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg005_python_unconstrained_emits_one_low() {
        let findings = run("[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\n");
        assert_eq!(findings.len(), 1, "expected 1 PKG005 finding");
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn pkg005_requires_python_present_emits_zero() {
        let findings =
            run("[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\nrequires-python = \">=3.9\"\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings when requires-python set: {findings:#?}"
        );
    }

    #[test]
    fn pkg005_suppression_directive_works() {
        let findings =
            run("[project]\nname = \"x\"\nversion = \"1.0\"\nrequires-python = \">=3.8\"\n");
        assert!(findings.is_empty());
    }
}
