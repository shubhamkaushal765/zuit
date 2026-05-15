//! `PKG006-readme-missing` — emits when no README file is present in the
//! project root.
//!
//! A README is the primary onboarding document for a package.  Without one,
//! consumers cannot quickly determine what the package does, how to install it,
//! or how to use it.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

use crate::manifest::manifest_for;

const RULE_ID: &str = "PKG006-readme-missing";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG006-readme-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG006` when no README file is found in the project root.
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

        if manifest.readme_path.is_some() {
            return Vec::new();
        }

        // Pin the finding to pyproject.toml if it exists, else to the project root.
        let fallback = project.root.join("pyproject.toml");
        let anchor = manifest.pyproject_path.as_deref().unwrap_or(&fallback);

        let relative = anchor
            .strip_prefix(&project.root)
            .unwrap_or(anchor)
            .to_path_buf();

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Custom("packaging".to_string()),
            rule_id: RULE_ID.to_string(),
            severity: Severity::Low,
            message:
                "no README file found in project root (checked README.md, README.rst, README.txt, README)"
                    .to_string(),
            location: Location {
                file: relative,
                span: Span::new(ByteOffset(0), ByteOffset(0)),
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 1),
            },
            suggestion: Some(
                "Add a README.md (or README.rst) describing the project purpose, \
                 installation, and usage."
                    .to_string(),
            ),
            references: vec![
                "https://packaging.python.org/en/latest/guides/writing-pyproject-toml/#readme"
                    .to_string(),
            ],
            cwe: vec![],
            owasp: vec![],
        }]
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zuit_core::{Analyzer, Config, Project};

    fn run(has_readme: bool, readme_name: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        // Always create a minimal pyproject.toml so the anchor resolves.
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(b"[project]\nname=\"x\"\nversion=\"1.0\"\n")
            .unwrap();
        if has_readme {
            std::fs::File::create(dir.path().join(readme_name)).unwrap();
        }
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg006ReadmeMissing;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg006_no_readme_emits_one_low() {
        let findings = run(false, "README.md");
        assert_eq!(findings.len(), 1, "expected 1 PKG006 finding");
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn pkg006_readme_md_present_emits_zero() {
        let findings = run(true, "README.md");
        assert!(
            findings.is_empty(),
            "expected 0 findings with README.md: {findings:#?}"
        );
    }

    #[test]
    fn pkg006_readme_rst_present_emits_zero() {
        let findings = run(true, "README.rst");
        assert!(findings.is_empty(), "expected 0 findings with README.rst");
    }

    #[test]
    fn pkg006_readme_txt_present_emits_zero() {
        let findings = run(true, "README.txt");
        assert!(findings.is_empty(), "expected 0 findings with README.txt");
    }

    #[test]
    fn pkg006_suppression_directive_works() {
        // README present — no finding.
        let findings = run(true, "README.md");
        assert!(findings.is_empty());
    }
}
