//! `CI003-no-windows-job` — fires when CI config exists but no workflow file
//! mentions a Windows runner (`windows-latest`, `windows-2019`, `windows-2022`).
//!
//! Cross-platform testing is essential for Rust crates distributed on
//! crates.io; path separator differences, FFI ABI issues, and timing
//! differences can cause Windows-only failures.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use super::{ci_finding, has_ci_config, read_workflow_contents};

const RULE_ID: &str = "CI003-no-windows-job";

const WINDOWS_RUNNERS: &[&str] = &["windows-latest", "windows-2019", "windows-2022"];

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/CI003-no-windows-job.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer for `CI003-no-windows-job`.
pub struct Ci003NoWindowsJob;

impl zuit_core::Analyzer for Ci003NoWindowsJob {
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
        let has_windows = WINDOWS_RUNNERS.iter().any(|&r| content.contains(r));
        if has_windows {
            return Vec::new();
        }

        vec![ci_finding(
            project,
            RULE_ID,
            Severity::Low,
            "CI workflows do not include a Windows runner (`windows-latest`, `windows-2019`, \
             or `windows-2022`); cross-platform regressions may go undetected."
                .to_string(),
            Some(
                "Add a matrix entry with `runs-on: windows-latest` to your CI workflow."
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

    fn setup_and_run(workflow_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let wf_dir = dir.path().join(".github").join("workflows");
        fs::create_dir_all(&wf_dir).unwrap();
        fs::write(wf_dir.join("ci.yml"), workflow_content).unwrap();
        let project = Project::new(dir.path().to_path_buf(), vec![]);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Ci003NoWindowsJob.analyze_project(&ctx, &project)
    }

    /// Positive: CI exists, no windows runner → 1 finding.
    #[test]
    fn ci003_no_windows_runner_emits_low() {
        let findings = setup_and_run("on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Negative: CI with windows-latest → 0 findings.
    #[test]
    fn ci003_with_windows_latest_emits_zero() {
        let findings = setup_and_run("on: [push]\njobs:\n  test:\n    runs-on: windows-latest\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: CI with windows-2019 → 0 findings.
    #[test]
    fn ci003_with_windows_2019_emits_zero() {
        let findings = setup_and_run("on: [push]\njobs:\n  test:\n    runs-on: windows-2019\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
