//! CI006-warnings-not-denied — fires when CI config exists but neither Cargo.toml nor any
//! workflow file denies warnings.
//!
//! ## Why
//!
//! Rust's `#[deny(warnings)]` / `RUSTFLAGS=-D warnings` turns all compiler warnings into hard
//! errors, ensuring the build fails before silently-degraded code reaches production.
//! Without either a `[workspace.lints.rust] warnings = "deny"` entry in `Cargo.toml` or an
//! explicit `RUSTFLAGS=-D warnings` in CI, warning regressions accumulate unnoticed.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::{ci_finding, has_ci_config, read_workflow_contents};

const RULE_ID: &str = "CI006-warnings-not-denied";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/CI006-warnings-not-denied.md",
    cwe: &["CWE-1127"],
    owasp: &[],
};

/// Analyzer for `CI006-warnings-not-denied`.
pub struct Ci006WarningsNotDenied;

impl zuit_core::Analyzer for Ci006WarningsNotDenied {
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
        // If there is no CI config at all, CI001 already fires — stay silent here.
        if !has_ci_config(&project.root) {
            return Vec::new();
        }

        // Check Cargo.toml for `[workspace.lints.rust] warnings = "deny"|"forbid"`
        // or `[lints.rust] warnings = "deny"|"forbid"`.
        let manifest = manifest_for(project);
        if let Some(doc) = &manifest.cargo_toml
            && warnings_denied_in_toml(doc)
        {
            return Vec::new();
        }

        // Check workflow files for `RUSTFLAGS=-D warnings` or `RUSTDOCFLAGS=-D warnings`.
        let content = read_workflow_contents(&project.root);
        if workflow_denies_warnings(&content) {
            return Vec::new();
        }

        let mut finding = ci_finding(
            project,
            RULE_ID,
            Severity::Low,
            "Project does not deny warnings: neither Cargo.toml ([lints.rust]/\
             [workspace.lints.rust] warnings = \"deny\") nor CI workflows set \
             RUSTFLAGS=-D warnings, so warnings will not fail the build."
                .to_string(),
            Some(
                "Set warnings = \"deny\" under [workspace.lints.rust] in Cargo.toml \
                 (Cargo 1.74+), or add `env: RUSTFLAGS: -D warnings` to your CI workflow."
                    .to_string(),
            ),
        );
        finding.cwe = vec!["CWE-1127".to_string()];
        vec![finding]
    }
}

/// Returns `true` if the TOML document declares `warnings = "deny"` or `warnings = "forbid"`
/// under either `[workspace.lints.rust]` or `[lints.rust]`.
fn warnings_denied_in_toml(doc: &toml_edit::DocumentMut) -> bool {
    let deny_or_forbid = |item: &toml_edit::Item| -> bool {
        item.as_str().is_some_and(|s| s == "deny" || s == "forbid")
    };

    // [workspace.lints.rust]
    if let Some(val) = doc
        .get("workspace")
        .and_then(|w| w.get("lints"))
        .and_then(|l| l.get("rust"))
        .and_then(|r| r.get("warnings"))
        && deny_or_forbid(val)
    {
        return true;
    }

    // [lints.rust]
    if let Some(val) = doc
        .get("lints")
        .and_then(|l| l.get("rust"))
        .and_then(|r| r.get("warnings"))
        && deny_or_forbid(val)
    {
        return true;
    }

    false
}

/// Returns `true` if the workflow content contains a `RUSTFLAGS` (or `RUSTDOCFLAGS`) mention
/// combined with a `-D warnings` or `-Dwarnings` flag.
fn workflow_denies_warnings(content: &str) -> bool {
    (content.contains("RUSTFLAGS") || content.contains("RUSTDOCFLAGS"))
        && (content.contains("-D warnings") || content.contains("-Dwarnings"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write as _;
    use zuit_core::{Analyzer, Config, Project};

    /// Creates a temp dir with the given Cargo.toml content and an optional workflow.
    /// Clears the manifest cache so each test gets a fresh parse.
    fn setup_and_run(toml: &str, workflow_content: Option<&str>) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();

        // Write Cargo.toml.
        let mut f = fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml.as_bytes()).unwrap();

        // Optionally write a CI workflow.
        if let Some(wf) = workflow_content {
            let wf_dir = dir.path().join(".github").join("workflows");
            fs::create_dir_all(&wf_dir).unwrap();
            fs::write(wf_dir.join("ci.yml"), wf).unwrap();
        }

        crate::manifest::clear_cache();
        let project = Project::new(dir.path().to_path_buf(), vec![]);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Ci006WarningsNotDenied.analyze_project(&ctx, &project)
    }

    const MINIMAL_TOML: &str = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n";
    const MINIMAL_WF: &str = "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n";

    /// CI exists, no deny anywhere → 1 Low finding with CWE-1127.
    #[test]
    fn ci006_no_deny_anywhere_emits_low() {
        let findings = setup_and_run(MINIMAL_TOML, Some(MINIMAL_WF));
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-1127"),
            "expected CWE-1127 in {:?}",
            findings[0].cwe
        );
    }

    /// [workspace.lints.rust] warnings = "deny" → silent.
    #[test]
    fn ci006_workspace_lints_deny_silent() {
        let toml = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
                    [workspace.lints.rust]\nwarnings = \"deny\"\n";
        let findings = setup_and_run(toml, Some(MINIMAL_WF));
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// [workspace.lints.rust] warnings = "forbid" → silent.
    #[test]
    fn ci006_workspace_lints_forbid_silent() {
        let toml = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
                    [workspace.lints.rust]\nwarnings = \"forbid\"\n";
        let findings = setup_and_run(toml, Some(MINIMAL_WF));
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// [lints.rust] warnings = "deny" → silent.
    #[test]
    fn ci006_package_lints_deny_silent() {
        let toml =
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n[lints.rust]\nwarnings = \"deny\"\n";
        let findings = setup_and_run(toml, Some(MINIMAL_WF));
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Workflow contains `RUSTFLAGS: -D warnings` → silent.
    #[test]
    fn ci006_rustflags_deny_in_workflow_silent() {
        let wf = "on: [push]\njobs:\n  test:\n    env:\n      RUSTFLAGS: -D warnings\n";
        let findings = setup_and_run(MINIMAL_TOML, Some(wf));
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Workflow contains `RUSTFLAGS: -Dwarnings` (no space) → silent.
    #[test]
    fn ci006_rustflags_dwarnings_no_space_silent() {
        let wf = "on: [push]\njobs:\n  test:\n    env:\n      RUSTFLAGS: -Dwarnings\n";
        let findings = setup_and_run(MINIMAL_TOML, Some(wf));
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Workflow contains `RUSTDOCFLAGS: -D warnings` → silent.
    #[test]
    fn ci006_rustdocflags_silent() {
        let wf = "on: [push]\njobs:\n  test:\n    env:\n      RUSTDOCFLAGS: -D warnings\n";
        let findings = setup_and_run(MINIMAL_TOML, Some(wf));
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Workflow contains both RUSTFLAGS and `-D warnings` (clippy context) → silent.
    #[test]
    fn ci006_clippy_deny_in_workflow_silent() {
        let wf = "on: [push]\njobs:\n  test:\n    env:\n      RUSTFLAGS: -D warnings\n    \
                  steps:\n      - run: cargo clippy -- -D warnings\n";
        let findings = setup_and_run(MINIMAL_TOML, Some(wf));
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// No `.github/workflows` directory → 0 findings (CI001 covers this).
    #[test]
    fn ci006_no_ci_config_silent() {
        let findings = setup_and_run(MINIMAL_TOML, None);
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
