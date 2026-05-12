//! `CI001-no-ci-config` — fires when no CI configuration is found in the
//! project root.
//!
//! Checks for:
//! - `.github/workflows/*.{yml,yaml}`
//! - `.gitlab-ci.yml`
//! - `.circleci/config.yml`
//!
//! A project without CI configuration has no automated quality gate; bugs,
//! test failures, and regressions may go undetected before release.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use super::{ci_finding, has_ci_config};

const RULE_ID: &str = "CI001-no-ci-config";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/CI001-no-ci-config.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer for `CI001-no-ci-config`.
pub struct Ci001NoCiConfig;

impl zuit_core::Analyzer for Ci001NoCiConfig {
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
        if has_ci_config(&project.root) {
            return Vec::new();
        }

        vec![ci_finding(
            project,
            RULE_ID,
            Severity::Medium,
            "No CI configuration found (`.github/workflows/*.yml`, `.gitlab-ci.yml`, \
             or `.circleci/config.yml`); the project has no automated test gate."
                .to_string(),
            Some(
                "Add a GitHub Actions workflow, GitLab CI pipeline, or CircleCI config \
                 to run `cargo test` and `cargo clippy` on every push."
                    .to_string(),
            ),
        )]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::fs;

    fn run_in_dir(dir: &std::path::Path) -> Vec<Finding> {
        let project = Project::new(dir.to_path_buf(), vec![]);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Ci001NoCiConfig.analyze_project(&ctx, &project)
    }

    /// Positive: no CI config → 1 finding.
    #[test]
    fn ci001_no_ci_config_emits_medium() {
        let dir = tempfile::TempDir::new().unwrap();
        let findings = run_in_dir(dir.path());
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Negative: .github/workflows/ci.yml exists → 0 findings.
    #[test]
    fn ci001_with_github_workflow_emits_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        let wf_dir = dir.path().join(".github").join("workflows");
        fs::create_dir_all(&wf_dir).unwrap();
        fs::write(wf_dir.join("ci.yml"), "on: [push]\njobs: {}").unwrap();
        let findings = run_in_dir(dir.path());
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: .gitlab-ci.yml exists → 0 findings.
    #[test]
    fn ci001_with_gitlab_ci_emits_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        fs::write(dir.path().join(".gitlab-ci.yml"), "stages: []").unwrap();
        let findings = run_in_dir(dir.path());
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: .circleci/config.yml exists → 0 findings.
    #[test]
    fn ci001_with_circleci_config_emits_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".circleci")).unwrap();
        fs::write(
            dir.path().join(".circleci").join("config.yml"),
            "version: 2",
        )
        .unwrap();
        let findings = run_in_dir(dir.path());
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
