//! `CHAIN004-unpinned-runtime-dep` — emits when a runtime dependency in
//! `pyproject.toml` has no version constraint (empty string, `"*"`, or
//! completely absent version specifier).
//!
//! Unpinned dependencies allow pip/uv to install any version, which means a
//! future release of a transitive dependency can silently break or compromise
//! a project.  Version constraints like `"^2.31"` or `">=2.0,<3"` are fine;
//! only naked stars or missing versions trigger this rule.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::chain_finding;

const RULE_ID: &str = "CHAIN004-unpinned-runtime-dep";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/CHAIN004-unpinned-runtime-dep.md",
    cwe: &[],
    owasp: &[],
};

/// Returns `true` if the PEP 508 dependency string has no version specifier
/// (i.e. the package name is the entire string, possibly with extras).
///
/// Examples:
/// - `"requests"` → unpinned (true)
/// - `"requests[security]"` → unpinned (true)
/// - `"requests>=2.0"` → pinned (false)
/// - `"requests==2.31.0"` → pinned (false)
fn pep508_is_unpinned(dep: &str) -> bool {
    // Strip environment markers (`;` separator).
    let without_marker = dep.split(';').next().unwrap_or(dep).trim();
    // Strip extras `[...]`.
    let without_extras = if let Some(idx) = without_marker.find('[') {
        let after_bracket = without_marker[idx..]
            .find(']')
            .map_or("", |i| &without_marker[idx + i + 1..]);
        format!("{}{}", &without_marker[..idx], after_bracket)
    } else {
        without_marker.to_string()
    };
    // If no version operator remains, the dep is unpinned.
    !without_extras.contains(['>', '<', '=', '~', '!'])
}

/// Returns `true` if the Poetry version string is unpinned.
///
/// Poetry uses `"*"` explicitly for "any version"; an empty string or missing
/// key is also treated as unpinned.
fn poetry_version_is_unpinned(version_str: &str) -> bool {
    let v = version_str.trim();
    v.is_empty() || v == "*"
}

/// Analyzer that emits `CHAIN004` for unpinned runtime dependencies.
pub struct Chain004UnpinnedRuntimeDep;

impl zuit_core::Analyzer for Chain004UnpinnedRuntimeDep {
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

        let mut findings = Vec::new();

        // ── PEP 621: [project].dependencies ──────────────────────────────────
        if let Some(deps) = doc
            .get("project")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("dependencies"))
            .and_then(|v| v.as_array())
        {
            for item in deps {
                if let Some(dep_str) = item.as_str()
                    && pep508_is_unpinned(dep_str)
                {
                    let pkg_name = dep_str
                        .split(['[', ';', '>', '<', '=', '!', ' '])
                        .next()
                        .unwrap_or(dep_str)
                        .trim();
                    findings.push(chain_finding(
                        project,
                        &pyproject_path,
                        RULE_ID,
                        Severity::Medium,
                        format!(
                            "Runtime dependency `{pkg_name}` has no version constraint; \
                             any version will be installed, which may pull in breaking or \
                             malicious future releases"
                        ),
                        Some(format!(
                            "Pin `{pkg_name}` with a version specifier such as \
                             `{pkg_name}>=<current_version>,<next_major>`."
                        )),
                    ));
                }
            }
        }

        // ── Poetry: [tool.poetry.dependencies] ───────────────────────────────
        if let Some(poetry_deps) = doc
            .get("tool")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("poetry"))
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("dependencies"))
            .and_then(|v| v.as_table())
        {
            for (key, val) in poetry_deps {
                if key == "python" {
                    continue;
                }
                let is_unpinned = if let Some(s) = val.as_str() {
                    poetry_version_is_unpinned(s)
                } else {
                    // Inline table form: {version = "*", optional = true}
                    val.as_inline_table()
                        .and_then(|t| t.get("version"))
                        .and_then(|v| v.as_str())
                        .is_some_and(poetry_version_is_unpinned)
                };

                if is_unpinned {
                    findings.push(chain_finding(
                        project,
                        &pyproject_path,
                        RULE_ID,
                        Severity::Medium,
                        format!(
                            "Runtime dependency `{key}` has no version constraint (`*` or empty); \
                             any version will be installed"
                        ),
                        Some(format!(
                            "Pin `{key}` with a version specifier such as `^<current_version>`."
                        )),
                    ));
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

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Chain004UnpinnedRuntimeDep;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    /// Plan test 7a: `requests = "*"` → one Medium.
    #[test]
    fn chain004_star_pin_emits_medium() {
        let findings = run("[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"*\"\n");
        assert_eq!(
            findings.len(),
            1,
            "expected 1 CHAIN004 finding: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Plan test 7b: `requests = "^2.31"` → 0 findings.
    #[test]
    fn chain004_caret_pin_is_clean() {
        let findings =
            run("[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"^2.31\"\n");
        assert!(
            findings.is_empty(),
            "`^2.31` is a valid constraint → no finding: {findings:#?}"
        );
    }

    #[test]
    fn chain004_pep621_unpinned_dep_emits() {
        // PEP 621 style: bare package name → unpinned.
        let findings =
            run("[project]\nname = \"my-pkg\"\nversion = \"1.0\"\ndependencies = [\"requests\"]\n");
        assert_eq!(findings.len(), 1, "bare name → 1 finding: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn chain004_pep621_pinned_dep_is_clean() {
        let findings = run(
            "[project]\nname = \"my-pkg\"\nversion = \"1.0\"\ndependencies = [\"requests>=2.31\", \"numpy<2\"]\n",
        );
        assert!(
            findings.is_empty(),
            "pinned pep621 deps → no finding: {findings:#?}"
        );
    }

    #[test]
    fn chain004_pep621_range_pinned_is_clean() {
        let findings = run(
            "[project]\nname = \"my-pkg\"\nversion = \"1.0\"\ndependencies = [\"requests>=2.0,<3\"]\n",
        );
        assert!(findings.is_empty(), "range pin → no finding: {findings:#?}");
    }

    #[test]
    fn chain004_poetry_empty_version_emits() {
        let findings = run("[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"\"\n");
        assert_eq!(
            findings.len(),
            1,
            "empty version → 1 finding: {findings:#?}"
        );
    }

    /// Healthy baseline: all deps pinned → 0 findings.
    #[test]
    fn chain004_healthy_baseline() {
        let findings = run("[project]\nname = \"my-pkg\"\nversion = \"1.0\"\n\
             dependencies = [\"requests>=2.31\", \"numpy>=1.24,<2\", \"flask~=3.0\"]\n");
        assert!(
            findings.is_empty(),
            "all pinned → no findings: {findings:#?}"
        );
    }
}
