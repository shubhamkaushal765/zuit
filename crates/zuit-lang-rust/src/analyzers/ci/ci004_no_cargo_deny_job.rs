//! `CI004-no-cargo-deny-job` — fires when CI config exists but no workflow
//! mentions `cargo deny` or `EmbarkStudios/cargo-deny-action`.
//!
//! `cargo deny` enforces license compliance, bans unwanted dependencies, and
//! checks for security advisories.  Without a CI job running it, these checks
//! can silently regress.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use super::{ci_finding, has_ci_config, read_workflow_contents};

const RULE_ID: &str = "CI004-no-cargo-deny-job";

const DENY_MARKERS: &[&str] = &["cargo deny", "EmbarkStudios/cargo-deny-action"];

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/CI004-no-cargo-deny-job.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer for `CI004-no-cargo-deny-job`.
pub struct Ci004NoCargoDenyJob;

impl zuit_core::Analyzer for Ci004NoCargoDenyJob {
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
        if !has_ci_config(&project.root) {
            return Vec::new();
        }

        let content = read_workflow_contents(&project.root);
        let has_deny = DENY_MARKERS.iter().any(|&marker| content.contains(marker));
        if has_deny {
            return Vec::new();
        }

        vec![ci_finding(
            project,
            RULE_ID,
            Severity::Low,
            "CI workflows do not run `cargo deny`; license compliance, bans, and advisory \
             checks are not automated."
                .to_string(),
            Some(
                "Add a CI step using `cargo deny check` or the \
                 `EmbarkStudios/cargo-deny-action` GitHub Action."
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

    fn setup_and_run(workflow_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let wf_dir = dir.path().join(".github").join("workflows");
        fs::create_dir_all(&wf_dir).unwrap();
        fs::write(wf_dir.join("ci.yml"), workflow_content).unwrap();
        let project = Project::new(dir.path().to_path_buf(), vec![]);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Ci004NoCargoDenyJob.analyze_project(&ctx, &project)
    }

    /// Positive: CI exists but no cargo deny → 1 finding.
    #[test]
    fn ci004_no_cargo_deny_emits_low() {
        let findings = setup_and_run("on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Negative: workflow contains `cargo deny` → 0 findings.
    #[test]
    fn ci004_with_cargo_deny_emits_zero() {
        let findings = setup_and_run(
            "on: [push]\njobs:\n  deny:\n    steps:\n      - run: cargo deny check\n",
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: workflow contains `EmbarkStudios/cargo-deny-action` → 0 findings.
    #[test]
    fn ci004_with_embark_action_emits_zero() {
        let findings = setup_and_run(
            "on: [push]\njobs:\n  deny:\n    steps:\n      - uses: EmbarkStudios/cargo-deny-action@v1\n",
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
