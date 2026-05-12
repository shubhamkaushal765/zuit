//! `CHAIN004-path-dependency-in-published-crate` — emits for each `path = "..."`
//! dependency in `Cargo.toml` that has no accompanying `version = "..."` key.
//!
//! `path` dependencies without a `version` sibling are incompatible with
//! publishing to crates.io: `cargo publish` will reject them.  The fix is to
//! add a `version` key so that the registry version is used when published.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::chain_finding;

const RULE_ID: &str = "CHAIN004-path-dependency-in-published-crate";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/CHAIN004-path-dependency-in-published-crate.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `CHAIN004` for path dependencies lacking a `version` key.
pub struct Chain004PathDependencyInPublishedCrate;

impl zuit_core::Analyzer for Chain004PathDependencyInPublishedCrate {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("supply_chain".to_string())
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

        let mut findings = Vec::new();

        for table_key in &["dependencies", "dev-dependencies"] {
            if let Some(deps) = doc.get(table_key).and_then(|v| v.as_table()) {
                for (name, val) in deps {
                    // Resolve `path` and `version` regardless of table style.
                    let (has_path, has_version) = if let Some(t) = val.as_inline_table() {
                        (t.get("path").is_some(), t.get("version").is_some())
                    } else if let Some(t) = val.as_table() {
                        (t.get("path").is_some(), t.get("version").is_some())
                    } else {
                        continue; // plain version string
                    };

                    if !has_path {
                        continue;
                    }

                    if has_version {
                        continue;
                    }

                    findings.push(chain_finding(
                        project,
                        &cargo_toml_path,
                        RULE_ID,
                        Severity::Medium,
                        format!(
                            "Path dependency `{name}` has no `version` key; `cargo publish` \
                             will reject this crate because path-only dependencies cannot be \
                             resolved by downstream users."
                        ),
                        Some(format!(
                            "Add `version = \"^x.y\"` alongside `path = \"...\"` in the \
                             `{name}` entry so that crates.io consumers resolve via the registry \
                             while local development uses the path."
                        )),
                    ));
                }
            }
        }

        findings
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Chain004PathDependencyInPublishedCrate;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    /// Plan test: path without version → one CHAIN004 Medium.
    #[test]
    fn chain004_path_no_version_emits_medium() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\nmy-local = { path = \"../my-local\" }\n");
        assert_eq!(
            findings.len(),
            1,
            "expected 1 CHAIN004 finding: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Plan test (negative): path with version → 0 findings.
    #[test]
    fn chain004_path_with_version_clean() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\nmy-local = { path = \"../my-local\", version = \"^1.0\" }\n");
        assert!(
            findings.is_empty(),
            "path dep with version should not trigger: {findings:#?}"
        );
    }

    /// Registry deps are not flagged.
    #[test]
    fn chain004_registry_dep_clean() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = { version = \"1\", features = [\"rt\"] }\n");
        assert!(
            findings.is_empty(),
            "registry dep must not trigger CHAIN004: {findings:#?}"
        );
    }

    /// dev-dependencies are also checked.
    #[test]
    fn chain004_dev_dep_path_no_version_emits() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dev-dependencies]\ntest-helper = { path = \"../test-helper\" }\n");
        assert_eq!(
            findings.len(),
            1,
            "dev-dep path without version should trigger: {findings:#?}"
        );
    }
}
