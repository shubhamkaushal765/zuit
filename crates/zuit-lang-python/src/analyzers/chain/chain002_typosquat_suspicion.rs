//! `CHAIN002-typosquat-suspicion` — emits when a `pyproject.toml` dependency
//! name is within Damerau-Levenshtein distance `threshold` (default 2) of a
//! name in the bundled top-PyPI list, **excluding exact matches** and the
//! project's own name.
//!
//! Typosquatting attacks register packages with names one or two keystrokes
//! away from popular packages.  Catching these at dependency-declaration time
//! reduces the risk of accidentally depending on a malicious package.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::super::chain::typosquat::{TOP_PYPI, damerau_levenshtein};
use super::chain_finding;

const RULE_ID: &str = "CHAIN002-typosquat-suspicion";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/CHAIN002-typosquat-distance.md",
    cwe: &[],
    owasp: &[],
};

/// Default maximum Damerau-Levenshtein distance to flag as suspicious (inclusive).
pub const DEFAULT_THRESHOLD: usize = 2;

/// Normalises a package name for comparison: lowercase, hyphens → underscores.
fn normalise(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}

/// Collect all dependency names from `[project].dependencies` (PEP 621 style)
/// and `[tool.poetry.dependencies]`.
fn collect_dep_names(doc: &toml_edit::DocumentMut) -> Vec<String> {
    let mut names = Vec::new();

    // PEP 621: [project].dependencies — array of PEP 508 strings like
    // `"requests>=2.0"`.  We strip everything after the first `[><=!; ]`.
    if let Some(deps) = doc
        .get("project")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("dependencies"))
        .and_then(|v| v.as_array())
    {
        for item in deps {
            if let Some(s) = item.as_str() {
                let pkg_name = s
                    .split(['[', ';', '>', '<', '=', '!', ' '])
                    .next()
                    .unwrap_or(s)
                    .trim()
                    .to_string();
                if !pkg_name.is_empty() {
                    names.push(pkg_name);
                }
            }
        }
    }

    // Poetry style: [tool.poetry.dependencies] — table keys are package names.
    if let Some(poetry_deps) = doc
        .get("tool")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("poetry"))
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("dependencies"))
        .and_then(|v| v.as_table())
    {
        for (key, _val) in poetry_deps {
            // Skip the special "python" key used by Poetry to constrain Python version.
            if key != "python" {
                names.push(key.to_string());
            }
        }
    }

    names
}

/// Analyzer that emits `CHAIN002` for suspiciously-named dependencies.
pub struct Chain002TyposquatSuspicion {
    /// Maximum DL distance (inclusive) to flag; configurable, default 2.
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
        let Some(doc) = &manifest.pyproject else {
            return Vec::new();
        };

        let pyproject_path = manifest
            .pyproject_path
            .clone()
            .unwrap_or_else(|| project.root.join("pyproject.toml"));

        // Get the project's own name so we can skip it.
        let own_name: Option<String> = doc
            .get("project")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            .map(normalise);

        let dep_names = collect_dep_names(doc);
        let threshold = self.threshold;
        let mut findings = Vec::new();

        for dep in &dep_names {
            let dep_norm = normalise(dep);

            // Skip the project's own name.
            if let Some(ref own) = own_name
                && &dep_norm == own
            {
                continue;
            }

            for &popular in TOP_PYPI {
                let popular_norm = normalise(popular);
                let d = damerau_levenshtein(&dep_norm, &popular_norm);
                // Exclude exact matches (d == 0); flag distance in [1, threshold].
                if d >= 1 && d <= threshold {
                    findings.push(chain_finding(
                        project,
                        &pyproject_path,
                        RULE_ID,
                        Severity::High,
                        format!(
                            "Dependency `{dep}` is suspiciously similar to popular package \
                             `{popular}` (Damerau-Levenshtein distance {d}); possible typosquatting"
                        ),
                        Some(format!(
                            "Verify that `{dep}` is the package you intended.  \
                             Did you mean `{popular}`?"
                        )),
                    ));
                    break; // one finding per dep (closest match)
                }
            }
        }

        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project, Severity};
    use std::io::Write as _;

    fn run_with_threshold(toml_content: &str, threshold: usize) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
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

    /// Plan test 2a: dep named `requessts` → one CHAIN002 High.
    #[test]
    fn chain002_typosquat_requessts_emits_high() {
        let findings = run("[project]\nname = \"my-pkg\"\ndependencies = [\"requessts>=1.0\"]\n");
        assert_eq!(
            findings.len(),
            1,
            "expected 1 CHAIN002 finding: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Plan test 2b: dep named exactly `requests` → 0 findings (exact match excluded).
    #[test]
    fn chain002_exact_match_clean() {
        let findings = run("[project]\nname = \"my-pkg\"\ndependencies = [\"requests>=2.31\"]\n");
        assert!(
            findings.is_empty(),
            "exact match `requests` must not flag: {findings:#?}"
        );
    }

    /// Plan test 4: name 2 edits away → flagged; 3 edits away → not flagged (threshold=2).
    #[test]
    fn chain002_distance_threshold_at_2_inclusive() {
        // "numpyyy" is distance 2 from "numpy" (2 insertions) → flagged at threshold 2.
        let flagged = run("[project]\nname = \"my-pkg\"\ndependencies = [\"numpyyy\"]\n");
        assert_eq!(
            flagged.len(),
            1,
            "distance-2 dep should be flagged: {flagged:#?}"
        );

        // "numpyyxx" is distance 3 from "numpy" (3 insertions) → not flagged at threshold 2.
        let not_flagged = run("[project]\nname = \"my-pkg\"\ndependencies = [\"numpyyxx\"]\n");
        assert!(
            not_flagged.is_empty(),
            "distance-3 dep must NOT be flagged at threshold=2: {not_flagged:#?}"
        );
    }

    /// Plan test 5: project's own name matches a suspicious name → skip it in deps check.
    ///
    /// If the project is named "requessts" and also lists "requessts" as a dep,
    /// the dep should still be flagged (it's not the same as the project name check —
    /// we skip only the exact project name in deps, but "requessts" IS suspicious
    /// relative to "requests"). HOWEVER if the project name is "requessts" we should
    /// NOT flag the project name itself when it appears as a dep.
    #[test]
    fn chain002_skips_self_name_in_deps() {
        // Project named "requessts". Dep also "requessts". The dep equals own name → skipped.
        let findings =
            run("[project]\nname = \"requessts\"\ndependencies = [\"requessts>=1.0\"]\n");
        // The dep "requessts" == own name "requessts" → skipped; 0 findings.
        assert!(
            findings.is_empty(),
            "own-name dep must be skipped: {findings:#?}"
        );
    }

    /// Extra: poetry-style deps work too.
    #[test]
    fn chain002_poetry_deps_detected() {
        let toml = "[tool.poetry]\nname = \"my-pkg\"\nversion = \"1.0\"\n\
                    [tool.poetry.dependencies]\nnumpy = \"^1.0\"\nnumpyy = \"^1.0\"\n";
        let findings = run(toml);
        // "numpy" → exact match, clean. "numpyy" → distance 1 → flagged.
        assert_eq!(
            findings.len(),
            1,
            "poetry: numpyy should flag: {findings:#?}"
        );
    }

    /// Healthy baseline: all exact matches → zero findings.
    #[test]
    fn chain002_healthy_baseline() {
        let findings = run(
            "[project]\nname = \"my-pkg\"\ndependencies = [\"requests>=2.31\", \"numpy>=1.0\", \"flask>=3.0\"]\n",
        );
        assert!(
            findings.is_empty(),
            "all exact matches → no findings: {findings:#?}"
        );
    }
}
