//! `API003-semver-alignment` — `pyproject.toml` version bump does not match
//! the breaking-change signal from API001/API002.
//!
//! Two cases are detected:
//!
//! 1. **Major bump without breaking change** — version went from `1.x` to
//!    `2.0` (or any `N.x` → `(N+1).0`) but no API001 or API002 findings were
//!    emitted.
//! 2. **Breaking change without major bump** — API001 or API002 findings exist
//!    but the version bump is patch or minor only.
//!
//! Severity: **Low** (informational alignment check).
//!
//! ## Pre-1.0 carve-out
//!
//! Packages with a baseline version `< 1.0.0` are exempt from this rule because
//! semver allows arbitrary breaking changes below `1.0`.  See
//! `docs/rules/API003-semver-alignment.md` for details.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use super::{
    PublicApi, api_finding, baseline_unavailable_finding, extract_public_api_from_dir,
    extract_public_api_from_ref,
};

const RULE_ID: &str = "API003-semver-alignment";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/API003-semver-alignment.md",
    cwe: &[],
    owasp: &[],
};

// ── Semver helpers ────────────────────────────────────────────────────────────

/// Parses a version string into `(major, minor, patch)`.  Returns `None` for
/// anything that isn't `MAJOR[.MINOR[.PATCH]]`.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim();
    let parts: Vec<&str> = v.split('.').collect();
    let major = parts.first()?.parse::<u64>().ok()?;
    let minor = parts
        .get(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let patch = parts
        .get(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// Returns `true` if the version transition represents a major bump.
fn is_major_bump(from: (u64, u64, u64), to: (u64, u64, u64)) -> bool {
    to.0 > from.0
}

/// Returns `true` if the version transition is only a patch or minor bump
/// (no change to the major component).
fn is_patch_or_minor_bump(from: (u64, u64, u64), to: (u64, u64, u64)) -> bool {
    to.0 == from.0 && (to.1 > from.1 || (to.1 == from.1 && to.2 > from.2))
}

// ── Analyzer ──────────────────────────────────────────────────────────────────

/// Checks that the semver major version bump aligns with the presence or
/// absence of breaking API changes.
pub struct Api003SemverAlignment {
    /// The git ref to use as the baseline.  `None` disables this analyzer.
    pub baseline_ref: Option<String>,

    /// Injected baseline API for tests (bypasses git).
    #[cfg(test)]
    pub(crate) injected_baseline: Option<PublicApi>,
}

#[allow(clippy::derivable_impls)] // manual impl needed for #[cfg(test)] field
impl Default for Api003SemverAlignment {
    fn default() -> Self {
        Self {
            baseline_ref: None,
            #[cfg(test)]
            injected_baseline: None,
        }
    }
}

#[cfg(test)]
impl Api003SemverAlignment {
    /// Constructs an analyzer with a pre-built baseline API.  Git is never
    /// called.
    pub(crate) fn with_baseline_api(api: PublicApi) -> Self {
        Self {
            baseline_ref: Some("test-baseline".to_string()),
            injected_baseline: Some(api),
        }
    }
}

impl zuit_core::Analyzer for Api003SemverAlignment {
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

        diff_api003(project, &baseline_api, &head_api)
    }
}

impl Api003SemverAlignment {
    fn get_baseline(&self, project: &Project) -> Result<PublicApi, super::ApiError> {
        #[cfg(test)]
        if let Some(ref injected) = self.injected_baseline {
            return Ok(injected.clone());
        }

        let git_ref = self.baseline_ref.as_deref().unwrap_or("");
        extract_public_api_from_ref(git_ref, &project.root)
    }
}

/// Core diff logic for API003.
fn diff_api003(project: &Project, baseline: &PublicApi, head: &PublicApi) -> Vec<Finding> {
    // Parse versions; if either is missing or unparseable, skip the rule.
    let Some(base_ver_str) = &baseline.version else {
        return Vec::new();
    };
    let Some(head_ver_str) = &head.version else {
        return Vec::new();
    };

    let Some(base_ver) = parse_version(base_ver_str) else {
        return Vec::new();
    };
    let Some(head_ver) = parse_version(head_ver_str) else {
        return Vec::new();
    };

    // Pre-1.0 carve-out: baseline version < 1.0 → skip.
    if base_ver.0 == 0 {
        return Vec::new();
    }

    // Detect breaking changes (same logic as API001/API002 diff).
    let has_breaking = has_breaking_changes(baseline, head);

    let mut findings = Vec::new();

    // Case 1: major bump but no breaking changes.
    if is_major_bump(base_ver, head_ver) && !has_breaking {
        findings.push(api_finding(
            project,
            RULE_ID,
            Severity::Low,
            format!(
                "Version bumped from {base_ver_str} to {head_ver_str} (major bump) \
                 but no public API removals or arity changes were detected. \
                 A major bump implies breaking changes — was this intentional?"
            ),
            Some(
                "If there are no breaking changes, consider a minor or patch bump instead."
                    .to_string(),
            ),
        ));
    }

    // Case 2: breaking changes but only patch/minor bump.
    if has_breaking && is_patch_or_minor_bump(base_ver, head_ver) {
        findings.push(api_finding(
            project,
            RULE_ID,
            Severity::Low,
            format!(
                "Breaking API changes detected but version only bumped from {base_ver_str} \
                 to {head_ver_str} (patch/minor bump). Consider a major version bump."
            ),
            Some(
                "Breaking changes (removed symbols or arity changes) require a major version bump \
                 per semver."
                    .to_string(),
            ),
        ));
    }

    findings
}

/// Returns `true` if there are any API001 or API002 changes between baseline
/// and head.
fn has_breaking_changes(baseline: &PublicApi, head: &PublicApi) -> bool {
    // API001: any removed public function or class.
    for name in baseline.functions.keys() {
        if !head.functions.contains_key(name) {
            return true;
        }
    }
    for name in &baseline.classes {
        if !head.classes.contains(name) {
            return true;
        }
    }
    // API002: any arity change.
    for (name, base_sig) in &baseline.functions {
        if let Some(head_sig) = head.functions.get(name)
            && base_sig.total_arity() != head_sig.total_arity()
        {
            return true;
        }
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::api::{FunctionSig, PublicApi};
    use std::io::Write as _;
    use zuit_core::{Analyzer, Config, Project};

    fn make_project_with_version(py_src: &str, version: &str) -> (tempfile::TempDir, Project) {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("module.py")).unwrap();
        f.write_all(py_src.as_bytes()).unwrap();
        let mut pf = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        pf.write_all(format!("[project]\nname = \"test\"\nversion = \"{version}\"\n").as_bytes())
            .unwrap();
        let project = Project::new(dir.path(), vec![]);
        (dir, project)
    }

    fn make_baseline(version: &str, fn_name: &str, args: usize) -> PublicApi {
        let mut baseline = PublicApi {
            version: Some(version.to_string()),
            ..Default::default()
        };
        baseline.functions.insert(
            fn_name.to_string(),
            FunctionSig {
                posonly: 0,
                args,
                kwonly: 0,
            },
        );
        baseline
    }

    #[test]
    fn api003_major_bump_no_breaking_change() {
        // Baseline: version 1.2.3, function `f(a, b)` present.
        // HEAD: version 2.0.0, function `f(a, b)` still present — no breaking change.
        let baseline = make_baseline("1.2.3", "f", 2);

        // HEAD keeps `f` with same arity, but version is 2.0.0.
        let (_dir, project) = make_project_with_version("def f(a, b): pass\n", "2.0.0");
        let analyzer = Api003SemverAlignment::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(findings.len(), 1, "expected 1 API003 Low: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].message.contains("major bump"));
    }

    #[test]
    fn api003_breaking_change_without_major_bump() {
        // Baseline: version 1.0.0, function `f(a, b)`.
        // HEAD: version 1.1.0, function `f(a)` — arity changed (breaking).
        let baseline = make_baseline("1.0.0", "f", 2);

        let (_dir, project) = make_project_with_version("def f(a): pass\n", "1.1.0");
        let analyzer = Api003SemverAlignment::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(findings.len(), 1, "expected 1 API003 Low: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].message.contains("patch/minor bump"));
    }

    #[test]
    fn api003_pre_one_exempt() {
        // Baseline 0.9.0 → HEAD 0.10.0 with removal: exempt because < 1.0.
        let baseline = make_baseline("0.9.0", "removed_fn", 0);

        let (_dir, project) = make_project_with_version("# empty\n", "0.10.0");
        let analyzer = Api003SemverAlignment::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert!(
            findings.is_empty(),
            "pre-1.0 packages are exempt: {findings:#?}"
        );
    }

    #[test]
    fn api003_no_baseline_ref_skips_silently() {
        let (_dir, project) = make_project_with_version("def f(): pass\n", "2.0.0");
        let analyzer = Api003SemverAlignment::default();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert!(
            findings.is_empty(),
            "no baseline_ref → 0 findings: {findings:#?}"
        );
    }

    #[test]
    fn api003_aligned_major_bump_with_breaking_change_clean() {
        // Baseline: 1.0.0, f(a, b). HEAD: 2.0.0, f(a). Breaking change + major bump = aligned.
        let baseline = make_baseline("1.0.0", "f", 2);

        let (_dir, project) = make_project_with_version("def f(a): pass\n", "2.0.0");
        let analyzer = Api003SemverAlignment::with_baseline_api(baseline);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert!(
            findings.is_empty(),
            "major bump + breaking change = aligned: {findings:#?}"
        );
    }
}
