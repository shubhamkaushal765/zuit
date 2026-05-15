//! `CI005-no-dependabot` — fires when `.github/dependabot.yml` (or
//! `.github/dependabot.yaml`) does not exist.
//!
//! Dependabot automatically opens pull requests to keep dependencies up to
//! date, including security patches.  Without it, dependency updates are
//! entirely manual and may be delayed.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use super::ci_finding;

const RULE_ID: &str = "CI005-no-dependabot";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/CI005-no-dependabot.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer for `CI005-no-dependabot`.
pub struct Ci005NoDependabot;

impl zuit_core::Analyzer for Ci005NoDependabot {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("ci_release".to_string())
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
        let github_dir = project.root.join(".github");
        let has_dependabot = github_dir.join("dependabot.yml").exists()
            || github_dir.join("dependabot.yaml").exists();

        if has_dependabot {
            return Vec::new();
        }

        vec![ci_finding(
            project,
            RULE_ID,
            Severity::Low,
            "`.github/dependabot.yml` not found; automated dependency update PRs are not \
             configured."
                .to_string(),
            Some(
                "Create `.github/dependabot.yml` with a `cargo` ecosystem entry to enable \
                 automated dependency updates."
                    .to_string(),
            ),
        )]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use zuit_core::{Analyzer, Config, Project};

    fn run_in_dir(dir: &std::path::Path) -> Vec<Finding> {
        let project = Project::new(dir.to_path_buf(), vec![]);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Ci005NoDependabot.analyze_project(&ctx, &project)
    }

    /// Positive: no dependabot.yml → 1 finding.
    #[test]
    fn ci005_no_dependabot_emits_low() {
        let dir = tempfile::TempDir::new().unwrap();
        let findings = run_in_dir(dir.path());
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Negative: dependabot.yml exists → 0 findings.
    #[test]
    fn ci005_with_dependabot_yml_emits_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".github")).unwrap();
        fs::write(
            dir.path().join(".github").join("dependabot.yml"),
            "version: 2\nupdates: []\n",
        )
        .unwrap();
        let findings = run_in_dir(dir.path());
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: dependabot.yaml (alternate extension) → 0 findings.
    #[test]
    fn ci005_with_dependabot_yaml_emits_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".github")).unwrap();
        fs::write(
            dir.path().join(".github").join("dependabot.yaml"),
            "version: 2\nupdates: []\n",
        )
        .unwrap();
        let findings = run_in_dir(dir.path());
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
