//! `API001-public-symbol-removed` — a public symbol present in the baseline is
//! absent in the HEAD revision.
//!
//! Removing a public function or class without a major version bump is a
//! breaking change.  Severity: **High**.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use super::{
    PublicApi, api_finding, baseline_unavailable_finding, extract_public_api_from_dir,
    extract_public_api_from_ref,
};

const RULE_ID: &str = "API001-public-symbol-removed";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/API001-public-symbol-removed.md",
    cwe: &[],
    owasp: &[],
};

// ── Analyzer ──────────────────────────────────────────────────────────────────

/// Detects public symbols that were present in the baseline but are absent in
/// HEAD.
pub struct Api001PublicSymbolRemoved {
    /// The git ref to use as the baseline.  `None` disables this analyzer.
    pub baseline_ref: Option<String>,

    /// Injected baseline API for tests (bypasses git).
    #[cfg(test)]
    pub(crate) injected_baseline: Option<PublicApi>,
}

#[allow(clippy::derivable_impls)] // manual impl needed for #[cfg(test)] field
impl Default for Api001PublicSymbolRemoved {
    fn default() -> Self {
        Self {
            baseline_ref: None,
            #[cfg(test)]
            injected_baseline: None,
        }
    }
}

#[cfg(test)]
impl Api001PublicSymbolRemoved {
    /// Constructs an analyzer with a pre-built baseline API.  Git is never
    /// called.
    pub(crate) fn with_baseline_api(api: PublicApi) -> Self {
        Self {
            baseline_ref: Some("test-baseline".to_string()),
            injected_baseline: Some(api),
        }
    }
}

impl zuit_core::Analyzer for Api001PublicSymbolRemoved {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("api_stability".to_string())
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
        // Gate: disabled when no baseline ref is configured.
        if self.baseline_ref.is_none() {
            return Vec::new();
        }

        // Build HEAD API.
        let head_api = match extract_public_api_from_dir(&project.root) {
            Ok(a) => a,
            Err(e) => {
                return vec![baseline_unavailable_finding(
                    project,
                    &format!("failed to extract HEAD API: {e}"),
                )];
            }
        };

        // Build baseline API.
        let baseline_api = self.get_baseline(project);
        let baseline_api = match baseline_api {
            Ok(a) => a,
            Err(e) => {
                return vec![baseline_unavailable_finding(project, &e.to_string())];
            }
        };

        diff_api001(project, &baseline_api, &head_api)
    }
}

impl Api001PublicSymbolRemoved {
    fn get_baseline(&self, project: &Project) -> Result<PublicApi, super::ApiError> {
        #[cfg(test)]
        if let Some(ref injected) = self.injected_baseline {
            return Ok(injected.clone());
        }

        let git_ref = self.baseline_ref.as_deref().unwrap_or("");
        extract_public_api_from_ref(git_ref, &project.root)
    }
}

/// Diffs baseline vs head and emits API001 findings for removed symbols.
fn diff_api001(project: &Project, baseline: &PublicApi, head: &PublicApi) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Removed functions.
    for name in baseline.functions.keys() {
        if !head.functions.contains_key(name) {
            findings.push(api_finding(
                project,
                RULE_ID,
                Severity::High,
                format!(
                    "Public function `{name}` was removed (present in baseline, absent in HEAD)"
                ),
                Some(format!(
                    "Either restore `{name}` or bump the major version before removing it."
                )),
            ));
        }
    }

    // Removed classes.
    for name in &baseline.classes {
        if !head.classes.contains(name) {
            findings.push(api_finding(
                project,
                RULE_ID,
                Severity::High,
                format!("Public class `{name}` was removed (present in baseline, absent in HEAD)"),
                Some(format!(
                    "Either restore `{name}` or bump the major version before removing it."
                )),
            ));
        }
    }

    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::api::FunctionSig;
    use zuit_core::{Analyzer, Config, Project};
    use std::io::Write as _;

    fn make_project_with_py(src: &str) -> (tempfile::TempDir, Project) {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("module.py")).unwrap();
        f.write_all(src.as_bytes()).unwrap();
        let mut pf = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        pf.write_all(b"[project]\nname = \"test\"\nversion = \"1.0.0\"\n")
            .unwrap();
        let project = Project::new(dir.path(), vec![]);
        (dir, project)
    }

    #[test]
    fn api001_public_function_removed_baseline_to_head() {
        // Baseline has `public_fn`, HEAD (empty module.py) does not.
        let mut baseline = PublicApi::default();
        baseline.functions.insert(
            "public_fn".to_string(),
            FunctionSig {
                posonly: 0,
                args: 0,
                kwonly: 0,
            },
        );

        let (_dir, project) = make_project_with_py("# empty\n");
        let analyzer = Api001PublicSymbolRemoved::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected 1 API001 finding: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("public_fn"));
    }

    #[test]
    fn api001_no_baseline_ref_skips_silently() {
        let (_dir, project) = make_project_with_py("def public_fn(): pass\n");
        let analyzer = Api001PublicSymbolRemoved::default(); // baseline_ref = None
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert!(
            findings.is_empty(),
            "expected 0 findings when no baseline ref: {findings:#?}"
        );
    }

    #[test]
    fn api001_underscore_prefix_treated_private() {
        // Baseline has `_internal` — but HEAD doesn't. Should not fire API001.
        let baseline = PublicApi::default();
        // Note: `_internal` would never end up in PublicApi normally, but
        // verify diff logic: if somehow present, we still use the name.
        // Actually the real test is that extract_public_api doesn't collect `_internal`.
        // Here we test: if baseline has no public symbols that are removed, no finding.
        let (_dir, project) = make_project_with_py("# head\n");
        let analyzer = Api001PublicSymbolRemoved::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert!(
            findings.is_empty(),
            "no public symbols in baseline → no findings: {findings:#?}"
        );
    }

    #[test]
    fn api001_baseline_archive_failure_emits_single_info() {
        // Analyzer with a real (bogus) baseline_ref but no injected baseline.
        // The git archive call will fail → should emit exactly one Info finding.
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(b"[project]\nname = \"test\"\nversion = \"1.0.0\"\n")
            .unwrap();
        let project = Project::new(dir.path(), vec![]);

        let analyzer = Api001PublicSymbolRemoved {
            baseline_ref: Some("BOGUS_REF_XYZ".to_string()),
            injected_baseline: None,
        };
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 baseline-unavailable Info: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, "API/baseline-unavailable");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn api001_class_removed_emits_finding() {
        let mut baseline = PublicApi::default();
        baseline.classes.insert("MyClass".to_string());

        let (_dir, project) = make_project_with_py("# empty\n");
        let analyzer = Api001PublicSymbolRemoved::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("MyClass"));
    }

    #[test]
    fn api001_no_removal_clean() {
        let mut baseline = PublicApi::default();
        baseline.functions.insert(
            "still_here".to_string(),
            FunctionSig {
                posonly: 0,
                args: 1,
                kwonly: 0,
            },
        );

        let (_dir, project) = make_project_with_py("def still_here(x): pass\n");
        let analyzer = Api001PublicSymbolRemoved::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert!(
            findings.is_empty(),
            "no removal → no finding: {findings:#?}"
        );
    }
}
