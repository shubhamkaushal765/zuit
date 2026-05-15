//! `ECO002-async-runtime-coupling` — fires when a crate hard-depends on
//! `tokio` without also depending on a runtime-agnostic alternative or
//! an async abstraction layer.
//!
//! **Heuristic:** checks `[dependencies]` for `tokio` AND the absence of
//! `async-std`, `smol`, `futures`, or `async-trait`.  A hard `tokio` dependency
//! forces all downstream consumers to also depend on `tokio`, even if they
//! prefer `async-std` or `smol`.
//!
//! **Limitation:** this rule cannot detect `cfg(…)`-gated runtime selection or
//! feature-gated `tokio` dependencies.  It is a conservative heuristic.
//! Projects with `tokio` as a dev-dependency only are not flagged because
//! dev-dependencies are not checked.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::eco_finding;

const RULE_ID: &str = "ECO002-async-runtime-coupling";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/ECO002-async-runtime-coupling.md",
    cwe: &[],
    owasp: &[],
};

/// Runtime-agnostic / alternative async crates whose presence suppresses the
/// rule.
const AGNOSTIC_CRATES: &[&str] = &["async-std", "smol", "futures", "async-trait"];

/// Analyzer for `ECO002-async-runtime-coupling`.
pub struct Eco002AsyncRuntimeCoupling;

impl zuit_core::Analyzer for Eco002AsyncRuntimeCoupling {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("ecosystem".to_string())
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
        let Some(doc) = &manifest.cargo_toml else {
            return Vec::new();
        };

        let cargo_toml_path = manifest
            .cargo_toml_path
            .clone()
            .unwrap_or_else(|| project.root.join("Cargo.toml"));

        let Some(deps_table) = doc.get("dependencies").and_then(|v| v.as_table()) else {
            return Vec::new();
        };

        // Check for tokio in dependencies.
        let has_tokio = deps_table.contains_key("tokio");
        if !has_tokio {
            return Vec::new();
        }

        // Check for runtime-agnostic alternatives.
        let has_agnostic = AGNOSTIC_CRATES
            .iter()
            .any(|&alt| deps_table.contains_key(alt));

        if has_agnostic {
            return Vec::new();
        }

        vec![eco_finding(
            project,
            &cargo_toml_path,
            RULE_ID,
            Severity::Low,
            "Hard dependency on `tokio` without a runtime-agnostic alternative (e.g. \
             `async-std`, `smol`, `futures`); forces all downstream consumers to use `tokio`."
                .to_string(),
            Some(
                "Consider abstracting async runtime requirements behind a feature flag, or \
                 using the `futures` crate for executor-agnostic traits."
                    .to_string(),
            ),
        )]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zuit_core::{Analyzer, Config, Project};

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path().to_path_buf(), vec![]);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Eco002AsyncRuntimeCoupling.analyze_project(&ctx, &project)
    }

    /// Positive: tokio only → 1 finding.
    #[test]
    fn eco002_tokio_only_emits_low() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = \"1\"\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Negative: tokio + futures → 0 findings.
    #[test]
    fn eco002_tokio_with_futures_emits_zero() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = \"1\"\nfutures = \"0.3\"\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: no tokio → 0 findings.
    #[test]
    fn eco002_no_tokio_emits_zero() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\nserde = \"1\"\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: tokio + async-std → 0 findings.
    #[test]
    fn eco002_tokio_with_async_std_emits_zero() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = \"1\"\nasync-std = \"1\"\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
