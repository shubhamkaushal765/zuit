//! `CHAIN002-typosquat-suspicion` — flags dependency names that are suspiciously
//! close to well-known npm package names.
//!
//! A common supply-chain attack vector is "typosquatting": publishing a package
//! whose name is one or two keystrokes away from a popular package, hoping that
//! developers will mistype the name and install the malicious version instead.
//!
//! This analyzer uses Damerau-Levenshtein distance (see [`super::typosquat`]) to
//! compare each dependency name against a bundled snapshot of popular npm packages.
//! Exact matches are excluded; only near-matches within the threshold are flagged.
//!
//! The project's own `name` field is also excluded to avoid self-flagging packages
//! that legitimately share a namespace with popular libraries (e.g. `axios-helper`).

use std::path::Path;

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

use super::typosquat::is_typosquat_of;

/// Rule ID for the typosquat-suspicion check.
const RULE_ID: &str = "CHAIN002-typosquat-suspicion";

/// Damerau-Levenshtein distance threshold used for typosquat detection.
const THRESHOLD: usize = 2;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/CHAIN002-typosquat-suspicion.md",
    cwe: &["CWE-1357"],
    owasp: &[],
};

/// Zero-width location anchored at `package.json` line 1, column 1.
fn pkg_json_location(root: &Path) -> Location {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Location {
        file: root.join("package.json"),
        span: zero,
        start: LineCol::new(1, 1),
        end: LineCol::new(1, 1),
    }
}

/// Scan a dependency map and collect findings for any typosquat candidates.
///
/// `project_name` is the package's own `name` field; it is excluded from
/// comparisons to prevent self-flagging.
fn scan_deps(
    root: &Path,
    deps: &serde_json::Map<String, serde_json::Value>,
    project_name: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    for dep_name in deps.keys() {
        // Never flag the project's own name.
        if project_name.is_some_and(|n| n == dep_name.as_str()) {
            continue;
        }

        if let Some(target) = is_typosquat_of(dep_name, THRESHOLD) {
            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Custom("supply_chain".to_string()),
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                message: format!(
                    "Dependency `{dep_name}` looks like a typosquat of `{target}` \
                     (Damerau-Levenshtein distance ≤ {THRESHOLD}). Verify this is \
                     the intended package and not a malicious lookalike."
                ),
                location: pkg_json_location(root),
                suggestion: Some(format!(
                    "If you meant `{target}`, correct the dependency name. \
                     If `{dep_name}` is intentional, add an inline comment or \
                     exception in `zuit.toml` to suppress this finding."
                )),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }
    }
}

/// Analyzer that emits `CHAIN002-typosquat-suspicion` for dependency names
/// that closely resemble well-known npm packages.
pub struct Chain002TyposquatSuspicionAnalyzer;

impl Analyzer for Chain002TyposquatSuspicionAnalyzer {
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

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
        vec![]
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let manifest = crate::manifest::get_or_load(&project.root);
        let Some(pkg) = manifest.package_json.as_ref() else {
            return vec![];
        };

        // Extract the project's own name to skip self-comparison.
        let project_name = pkg.get("name").and_then(|v| v.as_str());

        let mut findings = Vec::new();

        if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) {
            scan_deps(&project.root, deps, project_name, &mut findings);
        }
        if let Some(dev_deps) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
            scan_deps(&project.root, dev_deps, project_name, &mut findings);
        }

        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use zuit_core::{Config, Project};

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).expect("invariant: temp dir is writable");
    }

    fn run(dir: &Path) -> Vec<Finding> {
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let project = Project::new(dir.to_path_buf(), vec![]);
        Chain002TyposquatSuspicionAnalyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn typosquat_lodahs_emits_high() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        // "lodahs" is a transposition of "lodash" (distance 1).
        write(
            dir.path(),
            "package.json",
            r#"{"name":"my-app","dependencies":{"lodahs":"^4.0.0"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "expected 1 finding; got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(findings[0].message.contains("lodahs"));
        assert!(findings[0].message.contains("lodash"));
    }

    #[test]
    fn exact_match_react_clean() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"my-app","dependencies":{"react":"^18.0.0"}}"#,
        );
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "exact match must not flag; got: {findings:#?}"
        );
    }

    #[test]
    fn distance_three_clean() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        // "loXYZh" is 3 substitutions away from "lodash" → distance 3 > threshold 2.
        write(
            dir.path(),
            "package.json",
            r#"{"name":"my-app","dependencies":{"loXYZh":"1.0.0"}}"#,
        );
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "distance-3 name must not be flagged; got: {findings:#?}"
        );
    }

    #[test]
    fn skips_project_own_name() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        // The project's own name is "axios-helper" — must not self-flag even if
        // it looks similar to "axios".  "axios" is 7 chars; "axios-helper" differs
        // by 7 chars so it would not normally flag at threshold 2 anyway, so use
        // a more direct scenario: project name equals a dep name and is 1 edit away.
        // We set the project name to "axios" itself (exact match excluded by rule).
        // Better: project name is "react" and there are no deps → 0 findings.
        write(
            dir.path(),
            "package.json",
            r#"{"name":"lodahs","dependencies":{}}"#,
        );
        // "lodahs" in the project's own name field should not generate a finding
        // because we only check dep names, not the project's own name.
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "project own name must not self-flag; got: {findings:#?}"
        );
    }

    #[test]
    fn skips_project_own_name_when_also_in_deps() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        // If the project's own name happens to be a typosquat candidate and is
        // also listed as a dependency (unusual but possible in monorepos), we skip.
        write(
            dir.path(),
            "package.json",
            r#"{"name":"lodahs","dependencies":{"lodahs":"*"}}"#,
        );
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "own name in deps must be skipped; got: {findings:#?}"
        );
    }

    #[test]
    fn distance_two_inclusive_flagged() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        // "lodaXY" → "lodash": 2 substitutions (X→s, Y→h) → distance exactly 2.
        write(
            dir.path(),
            "package.json",
            r#"{"name":"my-app","dependencies":{"lodaXY":"1.0.0"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "distance-2 must be flagged at threshold 2; got: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn no_package_json_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        let findings = run(dir.path());
        assert!(findings.is_empty(), "no package.json → 0 findings");
    }

    #[test]
    fn cwe_is_populated() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"my-app","dependencies":{"lodahs":"^4.0.0"}}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.contains(&"CWE-1357".to_string()),
            "CWE-1357 must be present; got: {:?}",
            findings[0].cwe
        );
    }
}
