//! `ECO001-no-no-std-feature` — fires when a library crate does not declare any
//! `no_std`, `no-std`, `alloc`, or `std` feature gates, indicating no clear
//! `no_std` compatibility story.
//!
//! **Trigger:** the project's `Cargo.toml` declares a `[lib]` section OR has
//! `src/lib.rs` AND the `[features]` table is absent or contains no key
//! matching `no_std`, `no-std`, `alloc`, or `std`.
//!
//! Library crates that support `no_std` environments (embedded, WASM,
//! kernel-mode) must expose a feature gate so downstream consumers can disable
//! the standard library dependency.  The absence of such a gate forces
//! consumers to vendor or patch the crate.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::eco_finding;

const RULE_ID: &str = "ECO001-no-no-std-feature";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/ECO001-no-no-std-feature.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer for `ECO001-no-no-std-feature`.
pub struct Eco001NoNoStdFeature;

impl zuit_core::Analyzer for Eco001NoNoStdFeature {
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

        // Check if this is a library crate.
        let has_lib_section = doc.get("lib").is_some();
        let has_src_lib_rs = project.root.join("src").join("lib.rs").exists();
        if !has_lib_section && !has_src_lib_rs {
            return Vec::new();
        }

        // Check for a no_std / std feature gate.
        let no_std_gate_names = ["no_std", "no-std", "alloc", "std"];
        let features_ok = doc
            .get("features")
            .and_then(|v| v.as_table())
            .is_some_and(|tbl| tbl.iter().any(|(key, _)| no_std_gate_names.contains(&key)));

        if features_ok {
            return Vec::new();
        }

        vec![eco_finding(
            project,
            &cargo_toml_path,
            RULE_ID,
            Severity::Low,
            "Library crate has no `no_std`, `no-std`, `alloc`, or `std` feature gate; \
             downstream consumers cannot use this crate in `#![no_std]` environments."
                .to_string(),
            Some(
                "Add `[features]\nno_std = []` and gate `std`-requiring items behind \
                 `#[cfg(feature = \"std\")]`."
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

    fn run_with_files(toml_content: &str, create_lib_rs: bool) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        if create_lib_rs {
            std::fs::create_dir_all(dir.path().join("src")).unwrap();
            std::fs::File::create(dir.path().join("src").join("lib.rs")).unwrap();
        }
        crate::manifest::clear_cache();
        let project = Project::new(dir.path().to_path_buf(), vec![]);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Eco001NoNoStdFeature.analyze_project(&ctx, &project)
    }

    /// Positive: lib crate with no features table → 1 finding.
    #[test]
    fn eco001_no_no_std_feature_emits_low() {
        let findings = run_with_files(
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\n[lib]\n",
            false,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Positive: src/lib.rs exists but no features → 1 finding.
    #[test]
    fn eco001_src_lib_rs_no_features_emits() {
        let findings = run_with_files("[package]\nname = \"mylib\"\nversion = \"1.0.0\"\n", true);
        assert_eq!(findings.len(), 1);
    }

    /// Negative: lib crate with `no_std` feature → 0 findings.
    #[test]
    fn eco001_with_no_std_feature_emits_zero() {
        let findings = run_with_files(
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\n[lib]\n\
             [features]\nno_std = []\n",
            false,
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: no lib section, no src/lib.rs → 0 findings (binary crate).
    #[test]
    fn eco001_binary_crate_emits_zero() {
        let findings = run_with_files(
            "[package]\nname = \"mybinary\"\nversion = \"1.0.0\"\n",
            false,
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: lib with `std` feature → 0 findings.
    #[test]
    fn eco001_with_std_feature_emits_zero() {
        let findings = run_with_files(
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\n[lib]\n\
             [features]\nstd = []\n",
            false,
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
