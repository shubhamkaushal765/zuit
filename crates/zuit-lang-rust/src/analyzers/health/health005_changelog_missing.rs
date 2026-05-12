//! `HEALTH005-changelog-missing` — emits when no `CHANGELOG*` or `HISTORY*`
//! file exists at the project root.
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

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/HEALTH005-changelog-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `HEALTH005` when no changelog file is found at the
/// project root.
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

        // Suppress if there is no Cargo.toml at all (not a Rust project root).
        if manifest.cargo_toml_path.is_none() {
            return Vec::new();
        }

        if has_changelog(&project.root) {
            return Vec::new();
        }

        vec![health_finding(
            project,
            RULE_ID,
            Severity::Low,
            "No changelog file found at project root. A `CHANGELOG.md` or `HISTORY.md` \
             helps crate consumers understand what changed between releases."
                .to_string(),
            Some(
                "Create a `CHANGELOG.md` following the Keep a Changelog format \
                 (https://keepachangelog.com). Tools like `git-cliff` can automate \
                 changelog generation from conventional commits."
                    .to_string(),
            ),
        )]
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns `true` if a changelog file exists in `root` (case-insensitive
/// prefix `CHANGELOG` or `HISTORY`, any extension or none).
pub(crate) fn has_changelog(root: &Path) -> bool {
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
        if root.join(name).exists() {
            return true;
        }
    }

    // Also scan directory entries for case variations.
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_upper = name.to_string_lossy().to_uppercase();
            if name_upper.starts_with("CHANGELOG")
                || name_upper.starts_with("HISTORY")
                || name_upper.starts_with("CHANGES")
            {
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
    use zuit_core::{Analyzer, Config, Project};

    fn run(root: &Path) -> Vec<Finding> {
        crate::manifest::clear_cache();
        let project = Project::new(root, vec![]);
        let analyzer = Health005ChangelogMissing;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    fn make_project_dir() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            b"[package]\nname = \"x\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        dir
    }

    /// Plan test: tempdir without CHANGELOG.md / HISTORY.rst → one HEALTH005 Low.
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
    fn health005_changelog_md_present_clean() {
        let dir = make_project_dir();
        std::fs::write(dir.path().join("CHANGELOG.md"), b"# Changelog\n").unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "CHANGELOG.md present → no finding: {findings:#?}"
        );
    }

    #[test]
    fn health005_history_rst_accepted() {
        let dir = make_project_dir();
        std::fs::write(dir.path().join("HISTORY.rst"), b"History\n").unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "HISTORY.rst present → no finding: {findings:#?}"
        );
    }

    #[test]
    fn health005_no_cargo_toml_is_silent() {
        let dir = tempfile::TempDir::new().unwrap();
        // No Cargo.toml — should not fire.
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "no Cargo.toml → no HEALTH005: {findings:#?}"
        );
    }
}
