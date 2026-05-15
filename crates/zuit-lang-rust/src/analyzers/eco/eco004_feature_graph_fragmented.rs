//! `ECO004-feature-graph-fragmented` — fires when the `[features]` table
//! contains a feature that appears to be non-additive: a feature whose
//! enabled list starts with `"!"` (a disabled dependency in Cargo's
//! mutually-exclusive feature syntax) or whose name starts with `dep:`
//! without the `?` qualifier (a non-optional dependency override).
//!
//! **Heuristic:** this check is conservative and may produce false-positives
//! on intentionally non-additive feature designs.  The rule exists to surface
//! complex feature graphs for manual review, not to prevent them.
//!
//! **False-positive risk:** some valid Cargo features use `dep:` prefixes for
//! optional dependency renaming.  Always review findings manually.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::eco_finding;

const RULE_ID: &str = "ECO004-feature-graph-fragmented";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/ECO004-feature-graph-fragmented.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer for `ECO004-feature-graph-fragmented`.
pub struct Eco004FeatureGraphFragmented;

impl zuit_core::Analyzer for Eco004FeatureGraphFragmented {
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

        let Some(features_table) = doc.get("features").and_then(|v| v.as_table()) else {
            return Vec::new();
        };

        for (feat_name, feat_value) in features_table {
            // Check for dep: prefix without ? (non-optional dependency override).
            if feat_name.starts_with("dep:") && !feat_name.starts_with("dep:?") {
                return vec![eco_finding(
                    project,
                    &cargo_toml_path,
                    RULE_ID,
                    Severity::Low,
                    format!(
                        "Feature `{feat_name}` uses the `dep:` prefix without the `?` optional \
                         qualifier; this may indicate a non-additive feature that overrides \
                         dependency resolution."
                    ),
                    Some(
                        "Review the feature graph for non-additive behaviour. Consider using \
                         `dep:?` for optional dependency features."
                            .to_string(),
                    ),
                )];
            }

            // Check for values that start with "!" (disabled feature).
            if let Some(arr) = feat_value.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str()
                        && s.starts_with('!')
                    {
                        return vec![eco_finding(
                            project,
                            &cargo_toml_path,
                            RULE_ID,
                            Severity::Low,
                            format!(
                                "Feature `{feat_name}` contains `{s}` (a negated/disabled \
                                 dependency); non-additive features can break downstream \
                                 consumers that enable multiple feature sets."
                            ),
                            Some(
                                "Redesign the feature graph to use additive features only. \
                                 See the Cargo book on features."
                                    .to_string(),
                            ),
                        )];
                    }
                }
            }
        }

        vec![]
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
        Eco004FeatureGraphFragmented.analyze_project(&ctx, &project)
    }

    /// Positive: feature with negated value `!` → 1 finding.
    #[test]
    fn eco004_negated_feature_value_emits_low() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [features]\nno-default = [\"!default\"]\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Positive: feature name with `dep:` prefix without `?` → 1 finding.
    #[test]
    fn eco004_dep_prefix_without_question_emits_low() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [features]\n\"dep:serde\" = []\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    /// Negative: normal additive features → 0 findings.
    #[test]
    fn eco004_additive_features_emits_zero() {
        let findings = run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n\
             [features]\nfull = [\"std\", \"serde\"]\nstd = []\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: no features table → 0 findings.
    #[test]
    fn eco004_no_features_table_emits_zero() {
        let findings =
            run("[package]\nname = \"x\"\nversion = \"1.0.0\"\n[dependencies]\nserde = \"1\"\n");
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
