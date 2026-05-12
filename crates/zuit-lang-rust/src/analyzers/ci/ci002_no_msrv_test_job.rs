//! `CI002-no-msrv-test-job` — fires when CI config exists AND `Cargo.toml`
//! declares `rust-version = "…"` AND no workflow file mentions the version
//! string.
//!
//! Without a CI job that installs the declared MSRV and runs `cargo test`, the
//! MSRV guarantee is purely nominal and may silently break.
//!
//! **Heuristic:** performs a best-effort substring match of the `rust-version`
//! value against all workflow file contents.  If the version string appears
//! anywhere (even in a comment), the rule is suppressed.
//!
//! Silently skipped when `rust-version` is absent from `Cargo.toml`.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::{ci_finding, has_ci_config, read_workflow_contents};

const RULE_ID: &str = "CI002-no-msrv-test-job";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/CI002-no-msrv-test-job.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer for `CI002-no-msrv-test-job`.
pub struct Ci002NoMsrvTestJob;

impl zuit_core::Analyzer for Ci002NoMsrvTestJob {
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
        // CI must exist; if not, CI001 already fires — skip silently here.
        if !has_ci_config(&project.root) {
            return Vec::new();
        }

        let manifest = manifest_for(project);
        let Some(doc) = &manifest.cargo_toml else {
            return Vec::new();
        };

        // Extract rust-version from Cargo.toml [package].
        let rust_version = doc
            .get("package")
            .and_then(|v| v.get("rust-version"))
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        let Some(msrv) = rust_version else {
            // No MSRV declared — rule is silent.
            return Vec::new();
        };

        // Scan all workflow files for the MSRV version string.
        let workflow_content = read_workflow_contents(&project.root);
        if workflow_content.contains(msrv.as_str()) {
            return Vec::new();
        }

        vec![ci_finding(
            project,
            RULE_ID,
            Severity::Low,
            format!(
                "CI config does not mention the declared MSRV `{msrv}` (from \
                 `Cargo.toml [package].rust-version`); the MSRV guarantee is untested."
            ),
            Some(format!(
                "Add a CI matrix entry that installs Rust `{msrv}` and runs `cargo test --locked`."
            )),
        )]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::fs;
    use std::io::Write as _;

    fn setup_ci_and_run(toml: &str, workflow_content: Option<&str>) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml.as_bytes()).unwrap();

        let wf_dir = dir.path().join(".github").join("workflows");
        fs::create_dir_all(&wf_dir).unwrap();
        let content = workflow_content.unwrap_or("on: [push]\njobs: {}");
        fs::write(wf_dir.join("ci.yml"), content).unwrap();

        crate::manifest::clear_cache();
        let project = Project::new(dir.path().to_path_buf(), vec![]);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Ci002NoMsrvTestJob.analyze_project(&ctx, &project)
    }

    /// Positive: CI exists, MSRV declared, version not in workflow → 1 finding.
    #[test]
    fn ci002_msrv_not_in_workflow_emits_low() {
        let findings = setup_ci_and_run(
            "[package]\nname = \"x\"\nversion = \"1.0.0\"\nrust-version = \"1.70\"\n",
            Some("on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"),
        );
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(findings[0].message.contains("1.70"));
    }

    /// Negative: MSRV present in workflow → 0 findings.
    #[test]
    fn ci002_msrv_in_workflow_emits_zero() {
        let findings = setup_ci_and_run(
            "[package]\nname = \"x\"\nversion = \"1.0.0\"\nrust-version = \"1.70\"\n",
            Some("on: [push]\njobs:\n  test:\n    uses: 1.70\n"),
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: no rust-version → 0 findings.
    #[test]
    fn ci002_no_rust_version_emits_zero() {
        let findings = setup_ci_and_run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n", None);
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
