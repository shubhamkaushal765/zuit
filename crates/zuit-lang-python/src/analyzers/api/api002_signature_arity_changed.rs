//! `API002-signature-arity-changed` — a public function's argument count
//! differs between baseline and HEAD.
//!
//! Changing the arity of a public function without a major version bump is a
//! breaking change for callers using positional arguments.  Severity:
//! **Medium**.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use super::{
    PublicApi, api_finding, baseline_unavailable_finding, extract_public_api_from_dir,
    extract_public_api_from_ref,
};

const RULE_ID: &str = "API002-signature-arity-changed";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/API002-signature-arity-changed.md",
    cwe: &[],
    owasp: &[],
};

// ── Analyzer ──────────────────────────────────────────────────────────────────

/// Detects public functions whose total argument count changed between the
/// baseline and HEAD.
pub struct Api002SignatureArityChanged {
    /// The git ref to use as the baseline.  `None` disables this analyzer.
    pub baseline_ref: Option<String>,

    /// Injected baseline API for tests (bypasses git).
    #[cfg(test)]
    pub(crate) injected_baseline: Option<PublicApi>,
}

#[allow(clippy::derivable_impls)] // manual impl needed for #[cfg(test)] field
impl Default for Api002SignatureArityChanged {
    fn default() -> Self {
        Self {
            baseline_ref: None,
            #[cfg(test)]
            injected_baseline: None,
        }
    }
}

#[cfg(test)]
impl Api002SignatureArityChanged {
    /// Constructs an analyzer with a pre-built baseline API.  Git is never
    /// called.
    pub(crate) fn with_baseline_api(api: PublicApi) -> Self {
        Self {
            baseline_ref: Some("test-baseline".to_string()),
            injected_baseline: Some(api),
        }
    }
}

impl zuit_core::Analyzer for Api002SignatureArityChanged {
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
        if self.baseline_ref.is_none() {
            return Vec::new();
        }

        let head_api = match extract_public_api_from_dir(&project.root) {
            Ok(a) => a,
            Err(e) => {
                return vec![baseline_unavailable_finding(
                    project,
                    &format!("failed to extract HEAD API: {e}"),
                )];
            }
        };

        let baseline_api = self.get_baseline(project);
        let baseline_api = match baseline_api {
            Ok(a) => a,
            Err(e) => {
                return vec![baseline_unavailable_finding(project, &e.to_string())];
            }
        };

        diff_api002(project, &baseline_api, &head_api)
    }
}

impl Api002SignatureArityChanged {
    fn get_baseline(&self, project: &Project) -> Result<PublicApi, super::ApiError> {
        #[cfg(test)]
        if let Some(ref injected) = self.injected_baseline {
            return Ok(injected.clone());
        }

        let git_ref = self.baseline_ref.as_deref().unwrap_or("");
        extract_public_api_from_ref(git_ref, &project.root)
    }
}

/// Diffs baseline vs head and emits API002 findings for arity changes.
fn diff_api002(project: &Project, baseline: &PublicApi, head: &PublicApi) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (name, base_sig) in &baseline.functions {
        if let Some(head_sig) = head.functions.get(name) {
            let base_arity = base_sig.total_arity();
            let head_arity = head_sig.total_arity();
            if base_arity != head_arity {
                findings.push(api_finding(
                    project,
                    RULE_ID,
                    Severity::Medium,
                    format!(
                        "Public function `{name}` arity changed: \
                         baseline had {base_arity} parameter(s), HEAD has {head_arity}"
                    ),
                    Some(format!(
                        "Changing `{name}`'s signature is a breaking change for positional \
                         callers.  Consider bumping the major version."
                    )),
                ));
            }
        }
        // Note: if the function was *removed*, that's API001's job, not ours.
    }

    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::api::{FunctionSig, PublicApi};
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
    fn api002_arity_change() {
        // Baseline: def f(a, b) — 2 args; HEAD: def f(a) — 1 arg.
        let mut baseline = PublicApi::default();
        baseline.functions.insert(
            "f".to_string(),
            FunctionSig {
                posonly: 0,
                args: 2,
                kwonly: 0,
            },
        );

        let (_dir, project) = make_project_with_py("def f(a): pass\n");
        let analyzer = Api002SignatureArityChanged::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected 1 API002 finding: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains('f'));
        assert!(findings[0].message.contains('2'));
        assert!(findings[0].message.contains('1'));
    }

    #[test]
    fn api002_no_change_clean() {
        let mut baseline = PublicApi::default();
        baseline.functions.insert(
            "f".to_string(),
            FunctionSig {
                posonly: 0,
                args: 2,
                kwonly: 0,
            },
        );

        let (_dir, project) = make_project_with_py("def f(a, b): pass\n");
        let analyzer = Api002SignatureArityChanged::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert!(
            findings.is_empty(),
            "no arity change → no finding: {findings:#?}"
        );
    }

    #[test]
    fn api002_no_baseline_ref_skips_silently() {
        let (_dir, project) = make_project_with_py("def f(a, b): pass\n");
        let analyzer = Api002SignatureArityChanged::default();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert!(
            findings.is_empty(),
            "no baseline_ref → 0 findings: {findings:#?}"
        );
    }
}
