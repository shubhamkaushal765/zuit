//! `PERF001-heavy-default-features` — detects dependencies that opt into
//! heavy feature sets without explicitly disabling default features.
//!
//! Two triggers:
//! 1. Any dependency with `features = ["full"]` (case-insensitive on `"full"`).
//! 2. Known-heavy crates (`tokio`, `reqwest`, `axum`, `actix-web`) that do NOT
//!    have `default-features = false`.
//!
//! **Note:** This rule overlaps with `PKG009-default-features-bloat`, which
//! fires under the `packaging` dimension.  Both rules are intentionally kept:
//! PKG009 is a packaging hygiene signal; PERF001 is a runtime-performance
//! signal.  Projects should evaluate both.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::perf_finding;

const RULE_ID: &str = "PERF001-heavy-default-features";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PERF001-heavy-default-features.md",
    cwe: &[],
    owasp: &[],
};

/// Known-heavy crates that should use `default-features = false`.
const HEAVY_CRATES: &[&str] = &["tokio", "reqwest", "axum", "actix-web"];

/// Analyzer for `PERF001-heavy-default-features`.
pub struct Perf001HeavyDefaultFeatures;

impl zuit_core::Analyzer for Perf001HeavyDefaultFeatures {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("performance".to_string())
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

        for section in &["dependencies", "dev-dependencies"] {
            let Some(deps_table) = doc.get(section).and_then(|v| v.as_table()) else {
                continue;
            };

            for (dep_name, dep_value) in deps_table {
                let default_features_disabled = dep_value
                    .get("default-features")
                    .and_then(toml_edit::Item::as_bool)
                    .is_some_and(|b| !b);

                // Trigger 1: any dep with features = ["full"] (case-insensitive).
                let has_full_feature = dep_value
                    .get("features")
                    .and_then(|v| v.as_array())
                    .is_some_and(|arr| {
                        arr.iter().any(|item| {
                            item.as_str()
                                .is_some_and(|s| s.eq_ignore_ascii_case("full"))
                        })
                    });

                if has_full_feature && !default_features_disabled {
                    findings.push(perf_finding(
                        project,
                        &cargo_toml_path,
                        RULE_ID,
                        Severity::Medium,
                        format!(
                            "{dep_name} enables the `full` feature set, pulling in every \
                             sub-component and increasing compile time and binary size."
                        ),
                        Some(format!(
                            "Replace `features = [\"full\"]` with only the features your code \
                             uses, and add `default-features = false` to `{dep_name}` in \
                             [{section}]."
                        )),
                    ));
                    continue; // already flagged this dep
                }

                // Trigger 2: known-heavy crate without default-features = false.
                let dep_name_str = dep_name.to_string();
                if HEAVY_CRATES.contains(&dep_name_str.as_str())
                    && !default_features_disabled
                    && dep_value.as_table_like().is_some()
                {
                    findings.push(perf_finding(
                        project,
                        &cargo_toml_path,
                        RULE_ID,
                        Severity::Medium,
                        format!(
                            "{dep_name} is a known-heavy crate and does not set \
                             `default-features = false`; its default feature set may include \
                             components your project does not need."
                        ),
                        Some(format!(
                            "Audit which features of `{dep_name}` your project actually uses and \
                             add `default-features = false` in [{section}]."
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
    use zuit_core::{Analyzer, Config, Project, Severity};
    use std::io::Write as _;

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Perf001HeavyDefaultFeatures.analyze_project(&ctx, &project)
    }

    /// Positive: `features = ["full"]` without `default-features = false` → 1 finding.
    #[test]
    fn perf001_full_feature_emits_medium() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = { version = \"1\", features = [\"full\"] }\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(findings[0].message.contains("tokio"));
    }

    /// Negative: `features = ["full"]` WITH `default-features = false` → 0 findings.
    #[test]
    fn perf001_full_feature_with_no_default_emits_zero() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = { version = \"1\", features = [\"full\"], \
             default-features = false }\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Positive: known-heavy crate as inline table without default-features = false.
    #[test]
    fn perf001_known_heavy_crate_without_default_false_emits() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\nreqwest = { version = \"0.11\" }\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("reqwest"));
    }

    /// Negative: known-heavy crate with `default-features = false` → 0 findings.
    #[test]
    fn perf001_known_heavy_crate_with_default_false_emits_zero() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\nreqwest = { version = \"0.11\", default-features = false }\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: unknown crate without default-features = false → 0 findings.
    #[test]
    fn perf001_unknown_crate_string_dep_emits_zero() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\nserde = \"1\"\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Case-insensitive: `features = ["Full"]` → 1 finding.
    #[test]
    fn perf001_full_feature_case_insensitive() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [dependencies]\nsomecrate = { version = \"1\", features = [\"Full\"] }\n");
        assert_eq!(findings.len(), 1);
    }
}
