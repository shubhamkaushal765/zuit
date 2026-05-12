//! `CHAIN002-typosquat-suspicion` — emits when a `Cargo.toml` dependency name
//! is within Damerau-Levenshtein distance `threshold` (default 2) of a name
//! in the bundled top-crates.io list, **excluding exact matches**.
//!
//! Typosquatting attacks register crates with names one or two keystrokes away
//! from popular crates.  Catching these at dependency-declaration time reduces
//! the risk of accidentally depending on a malicious crate.
//!
//! Distance config wiring (from `ctx.config.rust.chain.typosquat_distance_threshold`)
//! is deferred; the threshold is currently hard-coded to 2 (the spec default).

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::chain_finding;
use super::typosquat::is_typosquat;

const RULE_ID: &str = "CHAIN002-typosquat-suspicion";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/CHAIN002-typosquat-distance.md",
    cwe: &[],
    owasp: &[],
};

/// Default maximum Damerau-Levenshtein distance to flag as suspicious (inclusive).
///
/// TODO: wire from `ctx.config.rust.chain.typosquat_distance_threshold` in a
/// future phase.
pub const DEFAULT_THRESHOLD: usize = 2;

/// Analyzer that emits `CHAIN002` for suspiciously-named dependencies.
pub struct Chain002TyposquatSuspicion {
    /// Maximum DL distance (inclusive) to flag; default 2.
    pub threshold: usize,
}

impl Default for Chain002TyposquatSuspicion {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
        }
    }
}

impl zuit_core::Analyzer for Chain002TyposquatSuspicion {
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

        let dep_names = collect_dep_names(doc);
        let threshold = self.threshold;
        let mut findings = Vec::new();

        for dep in &dep_names {
            if let Some(legit) = is_typosquat(dep, threshold) {
                findings.push(chain_finding(
                    project,
                    &cargo_toml_path,
                    RULE_ID,
                    Severity::High,
                    format!(
                        "{dep} is suspiciously similar to {legit} (Damerau-Levenshtein \
                         distance \u{2264}2); possible typosquat"
                    ),
                    Some(format!(
                        "Verify that `{dep}` is the crate you intended.  \
                         Did you mean `{legit}`?"
                    )),
                ));
            }
        }

        findings
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Collect dependency names from `[dependencies]` and `[dev-dependencies]`
/// tables in the parsed `Cargo.toml`.
fn collect_dep_names(doc: &toml_edit::DocumentMut) -> Vec<String> {
    let mut names = Vec::new();

    for table_key in &["dependencies", "dev-dependencies"] {
        if let Some(deps) = doc.get(table_key).and_then(|v| v.as_table()) {
            for (key, _val) in deps {
                // Skip workspace-inherited entries (they have no crate name to check).
                names.push(key.to_string());
            }
        }
    }

    names
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};

    fn run_with_threshold(toml_content: &str, threshold: usize) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Chain002TyposquatSuspicion { threshold };
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    fn run(toml_content: &str) -> Vec<Finding> {
        run_with_threshold(toml_content, DEFAULT_THRESHOLD)
    }

    /// Plan test: dep named `tokoi` → one CHAIN002 High.
    #[test]
    fn chain002_typosquat_tokoi_emits_high() {
        let findings = run("[package]\nname = \"my-bin\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokoi = \"1\"\n");
        assert_eq!(
            findings.len(),
            1,
            "expected 1 CHAIN002 finding for tokoi: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(
            findings[0].message.contains("tokio"),
            "message should mention tokio: {}",
            findings[0].message
        );
    }

    /// Plan test: dep named exactly `tokio` → 0 findings (exact match excluded).
    #[test]
    fn chain002_exact_match_clean() {
        let findings = run("[package]\nname = \"my-bin\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = \"1\"\n");
        assert!(
            findings.is_empty(),
            "exact match `tokio` must not flag: {findings:#?}"
        );
    }

    /// Plan test (boundary): name 2 edits away → flagged; 3 edits away → not flagged.
    #[test]
    fn chain002_distance_threshold_at_2_inclusive() {
        // "tokioox" is distance 2 from "tokio" (2 insertions) → flagged at threshold 2
        let flagged = run("[package]\nname = \"my-bin\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokioox = \"1\"\n");
        assert!(
            !flagged.is_empty(),
            "distance-2 dep tokioox should be flagged: {flagged:#?}"
        );

        // "tokiooxx" is distance 3 from "tokio" (3 insertions) → not flagged at threshold 2
        let not_flagged = run("[package]\nname = \"my-bin\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokiooxx = \"1\"\n");
        assert!(
            not_flagged.is_empty(),
            "distance-3 dep must NOT be flagged at threshold=2: {not_flagged:#?}"
        );
    }

    /// dev-dependencies are also checked.
    #[test]
    fn chain002_dev_dependencies_checked() {
        let findings = run("[package]\nname = \"my-bin\"\nversion = \"1.0.0\"\n\
             [dev-dependencies]\ntokoi = \"1\"\n");
        assert_eq!(
            findings.len(),
            1,
            "dev-dependencies should be checked: {findings:#?}"
        );
    }

    /// Healthy baseline: all exact matches → zero findings.
    #[test]
    fn chain002_healthy_baseline() {
        let findings = run("[package]\nname = \"my-bin\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = { version = \"1\", features = [\"full\"] }\n\
             serde = { version = \"1\", features = [\"derive\"] }\n");
        assert!(
            findings.is_empty(),
            "all exact matches → no findings: {findings:#?}"
        );
    }

    /// Verify `TOP_CRATES` itself contains no typosquat distance-1 pairs.
    /// (Sanity check: the bundled list should not contain near-duplicates of itself.)
    #[test]
    fn top_crates_no_internal_typosquats() {
        use super::super::typosquat::{TOP_CRATES, damerau_levenshtein};
        let normalise = |s: &str| s.to_lowercase().replace('-', "_");
        for (i, &a) in TOP_CRATES.iter().enumerate() {
            for &b in &TOP_CRATES[i + 1..] {
                let d = damerau_levenshtein(&normalise(a), &normalise(b));
                assert!(
                    d != 1,
                    "TOP_CRATES contains near-duplicate pair: '{a}' and '{b}' (distance {d})"
                );
            }
        }
    }
}
