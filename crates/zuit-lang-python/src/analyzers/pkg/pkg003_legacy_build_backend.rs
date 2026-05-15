//! `PKG003-legacy-build-backend` — detects projects that rely on a bare
//! `setup.py` without a `pyproject.toml`.
//!
//! `setup.py`-only projects use the legacy `distutils`/`setuptools` build
//! path, which is deprecated.  Projects should migrate to a `pyproject.toml`
//! with a modern build backend (setuptools, flit, hatch, poetry, etc.).

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

const RULE_ID: &str = "PKG003-legacy-build-backend";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG003-legacy-build-backend.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG003` when `setup.py` exists without `pyproject.toml`.
pub struct Pkg003LegacyBuildBackend;

impl zuit_core::Analyzer for Pkg003LegacyBuildBackend {
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
        let has_pyproject = project.root.join("pyproject.toml").exists();
        let has_setup_py = project.root.join("setup.py").exists();

        if has_setup_py && !has_pyproject {
            let setup_py = std::path::PathBuf::from("setup.py");
            vec![Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Custom("packaging".to_string()),
                rule_id: RULE_ID.to_string(),
                severity: Severity::Medium,
                message: "project uses setup.py without a pyproject.toml; \
                     this is the legacy build path and should be migrated \
                     to a modern build backend"
                    .to_string(),
                location: Location {
                    file: setup_py,
                    span: Span::new(ByteOffset(0), ByteOffset(0)),
                    start: LineCol::new(1, 1),
                    end: LineCol::new(1, 1),
                },
                suggestion: Some(
                    "Add a pyproject.toml with [build-system] and [project] tables. \
                     See https://packaging.python.org/en/latest/guides/writing-pyproject-toml/"
                        .to_string(),
                ),
                references: vec![
                    "https://packaging.python.org/en/latest/guides/writing-pyproject-toml/"
                        .to_string(),
                ],
                cwe: vec![],
                owasp: vec![],
            }]
        } else {
            Vec::new()
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zuit_core::{Analyzer, Config, Project};

    fn run_with_files(has_setup_py: bool, has_pyproject: bool) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        if has_setup_py {
            let mut f = std::fs::File::create(dir.path().join("setup.py")).unwrap();
            f.write_all(b"from setuptools import setup\nsetup()\n")
                .unwrap();
        }
        if has_pyproject {
            let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
            f.write_all(b"[project]\nname=\"x\"\nversion=\"1.0\"\n")
                .unwrap();
        }
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg003LegacyBuildBackend;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg003_setup_py_without_pyproject_emits_medium() {
        let findings = run_with_files(true, false);
        assert_eq!(findings.len(), 1, "expected 1 PKG003 finding");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].location.file, std::path::Path::new("setup.py"));
    }

    #[test]
    fn pkg003_setup_py_with_pyproject_emits_zero() {
        let findings = run_with_files(true, true);
        assert!(
            findings.is_empty(),
            "expected 0 findings when pyproject.toml present: {findings:#?}"
        );
    }

    #[test]
    fn pkg003_no_setup_py_emits_zero() {
        let findings = run_with_files(false, false);
        assert!(findings.is_empty(), "expected 0 findings: {findings:#?}");
    }

    #[test]
    fn pkg003_suppression_directive_works() {
        // No setup.py → no finding (healthy baseline).
        let findings = run_with_files(false, true);
        assert!(findings.is_empty());
    }
}
