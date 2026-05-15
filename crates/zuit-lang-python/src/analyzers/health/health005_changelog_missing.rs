//! `HEALTH005-changelog-missing` — emits when no `CHANGELOG*` or `HISTORY*`
//! file with non-trivial content exists at the project root.
//!
//! A changelog documents the history of user-facing changes between releases,
//! enabling consumers to make informed upgrade decisions.

use std::path::Path;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::health_finding;

const RULE_ID: &str = "HEALTH005-changelog-missing";

/// Minimum non-whitespace byte count to consider a changelog "non-trivial".
const MIN_CONTENT_BYTES: usize = 50;

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/HEALTH005-changelog-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `HEALTH005` when no changelog file is found.
pub struct Health005ChangelogMissing;

impl zuit_core::Analyzer for Health005ChangelogMissing {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("project_health".to_string())
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

        if has_changelog(&project.root) {
            return Vec::new();
        }

        // Suppress if there's no pyproject.toml at all (not a Python project root).
        if manifest.pyproject.is_none() && manifest.pyproject_path.is_none() {
            return Vec::new();
        }

        vec![health_finding(
            project,
            RULE_ID,
            Severity::Low,
            "No changelog file found at project root. A `CHANGELOG.md` or `HISTORY.rst` \
             helps users and package managers understand what changed between releases."
                .to_string(),
            Some(
                "Create a `CHANGELOG.md` following the Keep a Changelog format \
                 (https://keepachangelog.com). Tools like `towncrier` can automate \
                 changelog generation."
                    .to_string(),
            ),
        )]
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns `true` if a non-trivially-populated changelog file exists in `root`.
pub(crate) fn has_changelog(root: &Path) -> bool {
    // Enumerate candidate filenames.
    let candidates: &[&str] = &[
        "CHANGELOG.md",
        "CHANGELOG.rst",
        "CHANGELOG.txt",
        "CHANGELOG",
        "HISTORY.md",
        "HISTORY.rst",
        "HISTORY.txt",
        "HISTORY",
        "CHANGES.md",
        "CHANGES.rst",
        "CHANGES.txt",
        "CHANGES",
    ];

    for name in candidates {
        let path = root.join(name);
        if let Ok(content) = std::fs::read(&path) {
            let non_ws: usize = content
                .iter()
                .filter(|&&b| !b.is_ascii_whitespace())
                .count();
            if non_ws >= MIN_CONTENT_BYTES {
                return true;
            }
        }
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zuit_core::{Analyzer, Config, Project};

    fn run(root: &Path) -> Vec<Finding> {
        let project = Project::new(root, vec![]);
        let analyzer = Health005ChangelogMissing;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    fn make_project_dir() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        // Write a minimal pyproject.toml so the analyzer treats it as a valid root.
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(b"[project]\nname = \"x\"\nversion = \"1.0\"\n")
            .unwrap();
        dir
    }

    /// Plan test 4: tempdir without CHANGELOG.md / HISTORY.rst → one HEALTH005 Low.
    #[test]
    fn health005_changelog_missing() {
        let dir = make_project_dir();
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "expected 1 HEALTH005 finding: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, "HEALTH005-changelog-missing");
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn health005_changelog_present_clean() {
        let dir = make_project_dir();
        // Write a substantial CHANGELOG.md
        let content = "# Changelog\n\n## [1.0.0] - 2024-01-01\n### Added\n- Initial release with \
                        core features implemented and documented properly.\n";
        std::fs::write(dir.path().join("CHANGELOG.md"), content).unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "CHANGELOG.md present → no finding: {findings:#?}"
        );
    }

    #[test]
    fn health005_history_rst_accepted() {
        let dir = make_project_dir();
        let content = "History\n=======\n\n1.0.0 (2024-01-01)\n-------------------\n\n* Initial release with all the core features properly documented for users.\n";
        std::fs::write(dir.path().join("HISTORY.rst"), content).unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "HISTORY.rst present → no finding: {findings:#?}"
        );
    }

    #[test]
    fn health005_trivial_changelog_still_triggers() {
        let dir = make_project_dir();
        // A nearly-empty file (fewer than MIN_CONTENT_BYTES non-whitespace bytes).
        std::fs::write(dir.path().join("CHANGELOG.md"), "# WIP\n").unwrap();
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "trivially-empty changelog should still trigger: {findings:#?}"
        );
    }

    /// Suppression note: project-level analyzers read pyproject.toml, not per-file
    /// comments. Suppression via `# zuit: ignore HEALTH005` in a source file
    /// is not supported; suppress via the engine's global ignore list instead.
    /// This test verifies the "healthy baseline" (no false positive when changelog present).
    #[test]
    fn health005_healthy_baseline() {
        let dir = make_project_dir();
        let content = "# Changelog\n\n## v1.0.0\n- Initial release with comprehensive feature \
                        documentation for downstream users and package managers.\n";
        std::fs::write(dir.path().join("CHANGELOG.md"), content).unwrap();
        let findings = run(dir.path());
        assert!(findings.is_empty());
    }
}
