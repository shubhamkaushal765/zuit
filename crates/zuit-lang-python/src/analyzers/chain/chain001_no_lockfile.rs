//! `CHAIN001-no-lockfile` — emits when `pyproject.toml` is present but no
//! recognised lock file exists alongside it.
//!
//! A missing lock file means dependency versions are not reproducibly pinned,
//! making builds non-deterministic and potentially pulling in future vulnerable
//! or malicious releases of transitive dependencies.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::chain_finding;

const RULE_ID: &str = "CHAIN001-no-lockfile";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/CHAIN001-no-lockfile.md",
    cwe: &[],
    owasp: &[],
};

/// Lock-file candidates recognised by this rule.
///
/// The pattern `requirements*.txt` is handled by a prefix/suffix check below.
const EXACT_LOCKFILES: &[&str] = &["poetry.lock", "uv.lock", "pdm.lock"];

/// Returns `true` if a recognised lock file exists next to `pyproject.toml`.
fn has_lockfile(root: &std::path::Path) -> bool {
    // Check exact names first.
    for name in EXACT_LOCKFILES {
        if root.join(name).exists() {
            return true;
        }
    }
    // Check for any `requirements*.txt` file.
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("requirements") && name_str.ends_with(".txt") {
                return true;
            }
        }
    }
    false
}

/// Analyzer that emits `CHAIN001` when `pyproject.toml` exists without a lock
/// file.
pub struct Chain001NoLockfile;

impl zuit_core::Analyzer for Chain001NoLockfile {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("supply_chain".to_string())
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

        // Only fire when pyproject.toml is present.
        if manifest.pyproject_path.is_none() {
            return Vec::new();
        }

        if has_lockfile(&project.root) {
            return Vec::new();
        }

        let pyproject_path = manifest
            .pyproject_path
            .clone()
            .unwrap_or_else(|| project.root.join("pyproject.toml"));

        vec![chain_finding(
            project,
            &pyproject_path,
            RULE_ID,
            Severity::Medium,
            "pyproject.toml found but no lock file (poetry.lock, uv.lock, pdm.lock, \
             requirements*.txt) exists; dependency versions are not reproducibly pinned"
                .to_string(),
            Some(
                "Generate a lock file with your package manager: `poetry lock`, `uv lock`, \
                 `pdm lock`, or `pip-compile requirements.in`."
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

    fn run(root: &std::path::Path) -> Vec<Finding> {
        crate::manifest::clear_cache();
        let project = Project::new(root, vec![]);
        let analyzer = Chain001NoLockfile;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    fn write_pyproject(dir: &tempfile::TempDir) {
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(b"[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\n")
            .unwrap();
    }

    #[test]
    fn chain001_no_lockfile_emits_medium() {
        let dir = tempfile::TempDir::new().unwrap();
        write_pyproject(&dir);
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "expected exactly 1 CHAIN001 finding");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn chain001_poetry_lock_silences() {
        let dir = tempfile::TempDir::new().unwrap();
        write_pyproject(&dir);
        std::fs::write(dir.path().join("poetry.lock"), b"# lock").unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "poetry.lock present → no finding: {findings:#?}"
        );
    }

    #[test]
    fn chain001_uv_lock_silences() {
        let dir = tempfile::TempDir::new().unwrap();
        write_pyproject(&dir);
        std::fs::write(dir.path().join("uv.lock"), b"# lock").unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "uv.lock present → no finding: {findings:#?}"
        );
    }

    #[test]
    fn chain001_requirements_txt_silences() {
        let dir = tempfile::TempDir::new().unwrap();
        write_pyproject(&dir);
        std::fs::write(dir.path().join("requirements.txt"), b"requests==2.31.0\n").unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "requirements.txt → no finding: {findings:#?}"
        );
    }

    #[test]
    fn chain001_no_pyproject_is_silent() {
        let dir = tempfile::TempDir::new().unwrap();
        // No pyproject.toml — should not fire.
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "no pyproject.toml → no finding: {findings:#?}"
        );
    }

    /// Healthy baseline: pyproject.toml + pdm.lock → zero findings.
    #[test]
    fn chain001_healthy_baseline() {
        let dir = tempfile::TempDir::new().unwrap();
        write_pyproject(&dir);
        std::fs::write(dir.path().join("pdm.lock"), b"# pdm lock").unwrap();
        let findings = run(dir.path());
        assert!(findings.is_empty());
    }
}
