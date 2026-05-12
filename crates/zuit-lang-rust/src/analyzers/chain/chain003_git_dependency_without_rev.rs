//! `CHAIN003-git-dependency-without-rev` — emits for each `git = "..."` dependency
//! in `Cargo.toml` that is not pinned by a `rev = "..."` or `tag = "..."` key.
//!
//! A `branch`-only git dependency is not reproducibly pinned: the branch tip can
//! move at any time, meaning two builds at different times may resolve to different
//! commits.  Only `rev` (an exact commit hash) and `tag` provide stable pins.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::chain_finding;

const RULE_ID: &str = "CHAIN003-git-dependency-without-rev";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/CHAIN003-git-dependency-without-rev.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `CHAIN003` for git dependencies without `rev` or `tag`.
pub struct Chain003GitDependencyWithoutRev;

impl zuit_core::Analyzer for Chain003GitDependencyWithoutRev {
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
                    // Resolve `git`, `rev`, `tag` regardless of whether the value is
                    // an inline table `{ git = "..." }` or a dotted section table.
                    let (has_git, has_rev, has_tag) = if let Some(t) = val.as_inline_table() {
                        (
                            t.get("git").is_some(),
                            t.get("rev").is_some(),
                            t.get("tag").is_some(),
                        )
                    } else if let Some(t) = val.as_table() {
                        (
                            t.get("git").is_some(),
                            t.get("rev").is_some(),
                            t.get("tag").is_some(),
                        )
                    } else {
                        continue; // plain version string — no inline table
                    };

                    if !has_git {
                        continue;
                    }

                    if !has_rev && !has_tag {
                        findings.push(chain_finding(
                            project,
                            &cargo_toml_path,
                            RULE_ID,
                            Severity::Medium,
                            format!(
                                "Git dependency `{name}` has no `rev` or `tag` pin; the branch \
                                 tip may advance between builds, making the build non-reproducible \
                                 and potentially pulling in unreviewed commits."
                            ),
                            Some(format!(
                                "Add `rev = \"<commit-sha>\"` (preferred) or `tag = \"v1.2.3\"` \
                                 to pin `{name}` to a specific commit."
                            )),
                        ));
                    }
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
        let analyzer = Chain003GitDependencyWithoutRev;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    /// Plan test: git without rev → one CHAIN003 Medium.
    #[test]
    fn chain003_git_dep_without_rev_emits_medium() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\nmycrate = { git = \"https://github.com/example/mycrate\" }\n");
        assert_eq!(
            findings.len(),
            1,
            "expected 1 CHAIN003 finding: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Plan test (negative): git with rev → 0 findings.
    #[test]
    fn chain003_git_dep_with_rev_clean() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\nmycrate = { git = \"https://github.com/example/mycrate\", \
             rev = \"abc1234\" }\n");
        assert!(
            findings.is_empty(),
            "git dep with rev should not trigger: {findings:#?}"
        );
    }

    /// git with tag (but no rev) is also acceptable.
    #[test]
    fn chain003_git_dep_with_tag_clean() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\nmycrate = { git = \"https://github.com/example/mycrate\", \
             tag = \"v1.2.3\" }\n");
        assert!(
            findings.is_empty(),
            "git dep with tag should not trigger: {findings:#?}"
        );
    }

    /// git with only branch → CHAIN003 (branch is not a stable pin).
    #[test]
    fn chain003_git_dep_with_branch_only_emits() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\nmycrate = { git = \"https://github.com/example/mycrate\", \
             branch = \"main\" }\n");
        assert_eq!(
            findings.len(),
            1,
            "git with branch-only should trigger CHAIN003: {findings:#?}"
        );
    }

    /// Non-git registry deps are not flagged.
    #[test]
    fn chain003_registry_dep_clean() {
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n\
             [dependencies]\ntokio = { version = \"1\", features = [\"full\"] }\n");
        assert!(
            findings.is_empty(),
            "registry dep must not trigger CHAIN003: {findings:#?}"
        );
    }
}
