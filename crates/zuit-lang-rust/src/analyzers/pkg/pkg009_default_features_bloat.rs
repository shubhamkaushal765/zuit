//! `PKG009-default-features-bloat` — detects dependencies that request a
//! `"full"` feature without disabling default features.
//!
//! A typical offender is `tokio = { version = "1", features = ["full"] }`.
//! The `"full"` feature enables every sub-component, significantly increasing
//! compile time and binary size even when only a small subset is needed.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::cargo_toml_finding;

const RULE_ID: &str = "PKG009-default-features-bloat";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG009-default-features-bloat.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG009` for each dependency using the `"full"` feature
/// without `default-features = false`.
pub struct Pkg009DefaultFeaturesBloat;

impl zuit_core::Analyzer for Pkg009DefaultFeaturesBloat {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("packaging".to_string())
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

        // Check both [dependencies] and [dev-dependencies].
        for section in &["dependencies", "dev-dependencies"] {
            let Some(deps_table) = doc.get(section).and_then(|v| v.as_table()) else {
                continue;
            };

            for (dep_name, dep_value) in deps_table {
                // Check if features array contains "full".
                // Support both inline table ({ version = "1", features = ["full"] })
                // and standard table forms.
                let has_full_feature = dep_value
                    .get("features")
                    .and_then(|v| v.as_array())
                    .is_some_and(|arr| arr.iter().any(|item| item.as_str() == Some("full")));

                if !has_full_feature {
                    continue;
                }

                // Check if default-features = false is set.
                let default_features_disabled = dep_value
                    .get("default-features")
                    .and_then(toml_edit::Item::as_bool)
                    .is_some_and(|b| !b);

                if default_features_disabled {
                    continue;
                }

                findings.push(cargo_toml_finding(
                    project,
                    &cargo_toml_path,
                    RULE_ID,
                    Severity::Medium,
                    format!("{dep_name} uses heavy default-features (full); compile-time bloat"),
                    Some(format!(
                        "Replace `features = [\"full\"]` with only the features you actually use, \
                         and add `default-features = false` to `{dep_name}` in [{section}]."
                    )),
                ));
            }
        }

        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::io::Write as _;

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg009DefaultFeaturesBloat;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg009_tokio_full_features_emits_one_medium() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = { version = \"1\", features = [\"full\"] }\n");
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG009 finding");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("tokio"));
        assert_eq!(
            findings[0].location.file,
            std::path::Path::new("Cargo.toml")
        );
    }

    #[test]
    fn pkg009_tokio_selective_features_emits_zero() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = { version = \"1\", features = [\"rt\", \"macros\"] }\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings with selective features: {findings:#?}"
        );
    }

    #[test]
    fn pkg009_full_with_default_features_false_emits_zero() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = { version = \"1\", features = [\"full\"], default-features = false }\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings when default-features = false: {findings:#?}"
        );
    }

    #[test]
    fn pkg009_dev_dep_full_emits_one() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dev-dependencies]\ntokio = { version = \"1\", features = [\"full\"] }\n");
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for dev-dependency with full: {findings:#?}"
        );
    }

    #[test]
    fn pkg009_suppression_directive_works() {
        let findings = run(
            "# zuit: ignore PKG009\n[package]\nname = \"x\"\nversion = \"1.0\"\n\
             [dependencies]\ntokio = { version = \"1\", features = [\"rt\"] }\n",
        );
        assert!(findings.is_empty());
    }
}
