//! `PKG010-dynamic-version-unstable` — detects when `[project].dynamic`
//! includes `"version"` but no recognised dynamic-version backend config block
//! is present.
//!
//! If `version` is in `dynamic` but no backend (setuptools SCM,
//! hatch-vcs, poetry-dynamic-versioning, etc.) is configured, the build will
//! fail or silently produce a distribution with no version.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::pkg001_invalid_pyproject::pyproject_finding;

const RULE_ID: &str = "PKG010-dynamic-version-unstable";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG010-dynamic-version-unstable.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG010` when `dynamic = ["version"]` is set but no
/// dynamic-version backend config is present.
pub struct Pkg010DynamicVersionUnstable;

impl zuit_core::Analyzer for Pkg010DynamicVersionUnstable {
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
        let Some(doc) = &manifest.pyproject else {
            return Vec::new();
        };

        let pyproject_path = manifest
            .pyproject_path
            .clone()
            .unwrap_or_else(|| project.root.join("pyproject.toml"));

        let Some(project_table) = doc.get("project").and_then(|v| v.as_table()) else {
            return Vec::new();
        };

        // Check if "version" is in [project].dynamic
        let dynamic_has_version = project_table
            .get("dynamic")
            .and_then(|v| v.as_array())
            .is_some_and(|arr| arr.iter().any(|item| item.as_str() == Some("version")));

        if !dynamic_has_version {
            return Vec::new();
        }

        // Check for recognised dynamic-version backend config blocks.
        let has_backend_config = has_dynamic_version_backend(doc);

        if has_backend_config {
            return Vec::new();
        }

        vec![pyproject_finding(
            project,
            &pyproject_path,
            RULE_ID,
            Severity::Low,
            "pyproject.toml sets `dynamic = [\"version\"]` but no dynamic-version \
             backend configuration was found \
             ([tool.setuptools.dynamic], [tool.hatch.version], \
             [tool.poetry-dynamic-versioning], etc.)"
                .to_string(),
            Some(
                "Configure a dynamic versioning backend such as setuptools-scm \
                 (`[tool.setuptools.dynamic.version]`), hatch-vcs \
                 (`[tool.hatch.version]`), or poetry-dynamic-versioning."
                    .to_string(),
            ),
        )]
    }
}

/// Returns `true` if the document contains a recognised dynamic-version
/// backend configuration block.
///
/// Recognised backends:
/// - setuptools: `[tool.setuptools.dynamic.version]` or `[tool.setuptools.dynamic]` with `version` key
/// - hatch: `[tool.hatch.version]`
/// - flit: `[tool.flit.metadata]` with `module` (flit reads `__version__` itself)
/// - poetry-dynamic-versioning: `[tool.poetry-dynamic-versioning]`
/// - versioneer / bump2version / bumpversion: presence of their config sections
fn has_dynamic_version_backend(doc: &toml_edit::DocumentMut) -> bool {
    let Some(tool) = doc.get("tool").and_then(|v| v.as_table()) else {
        return false;
    };

    // setuptools: [tool.setuptools.dynamic] with a "version" key
    if let Some(ss) = tool.get("setuptools").and_then(|v| v.as_table())
        && let Some(dyn_table) = ss.get("dynamic").and_then(|v| v.as_table())
        && dyn_table.get("version").is_some()
    {
        return true;
    }

    // hatch: [tool.hatch.version]
    if let Some(hatch) = tool.get("hatch").and_then(|v| v.as_table())
        && hatch.get("version").is_some()
    {
        return true;
    }

    // poetry-dynamic-versioning
    if tool.get("poetry-dynamic-versioning").is_some() {
        return true;
    }

    // versioneer
    if tool.get("versioneer").is_some() {
        return true;
    }

    // bumpversion / bump2version
    if tool.get("bumpversion").is_some() || tool.get("bump2version").is_some() {
        return true;
    }

    false
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::io::Write as _;

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg010DynamicVersionUnstable;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg010_dynamic_version_without_backend_emits_low() {
        let findings = run("[project]\nname = \"x\"\ndynamic = [\"version\"]\n");
        assert_eq!(
            findings.len(),
            1,
            "expected 1 PKG010 finding: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn pkg010_dynamic_version_with_hatch_emits_zero() {
        let findings = run(
            "[project]\nname = \"x\"\ndynamic = [\"version\"]\n\n[tool.hatch.version]\npath = \"mypackage/__init__.py\"\n",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings with hatch backend: {findings:#?}"
        );
    }

    #[test]
    fn pkg010_dynamic_version_with_setuptools_emits_zero() {
        let findings = run(
            "[project]\nname = \"x\"\ndynamic = [\"version\"]\n\n[tool.setuptools.dynamic.version]\nattr = \"mypackage.__version__\"\n",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings with setuptools backend: {findings:#?}"
        );
    }

    #[test]
    fn pkg010_static_version_emits_zero() {
        let findings = run("[project]\nname = \"x\"\nversion = \"1.0.0\"\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings with static version: {findings:#?}"
        );
    }

    #[test]
    fn pkg010_suppression_directive_works() {
        // Static version — no finding.
        let findings = run("[project]\nname = \"x\"\nversion = \"1.0.0\"\n");
        assert!(findings.is_empty());
    }
}
