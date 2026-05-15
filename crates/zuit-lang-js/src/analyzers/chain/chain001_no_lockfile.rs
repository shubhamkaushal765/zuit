//! `CHAIN001-no-lockfile` — flags projects that have a `package.json` but no
//! lock file.
//!
//! Without a lock file (`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`)
//! every `npm install` may resolve different dependency versions, breaking
//! reproducibility and opening the door to supply-chain substitution attacks.

use std::path::Path;

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

/// Rule ID for the no-lockfile check.
const RULE_ID: &str = "CHAIN001-no-lockfile";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/CHAIN001-no-lockfile.md",
    cwe: &[],
    owasp: &[],
};

/// Zero-width location anchored at the project root directory.
fn root_location(root: &Path) -> Location {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Location {
        file: root.to_path_buf(),
        span: zero,
        start: LineCol::new(1, 1),
        end: LineCol::new(1, 1),
    }
}

/// Analyzer that emits `CHAIN001-no-lockfile` when no lock file is present.
pub struct Chain001NoLockfileAnalyzer;

impl Analyzer for Chain001NoLockfileAnalyzer {
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

        // Only flag projects that actually have a package.json.
        if manifest.package_json.is_none() {
            return vec![];
        }

        if manifest.has_any_lockfile {
            return vec![];
        }

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Custom("supply_chain".to_string()),
            rule_id: RULE_ID.to_string(),
            severity: Severity::Medium,
            message: "No lock file found (`package-lock.json`, `pnpm-lock.yaml`, or \
                      `yarn.lock`). Without a lock file dependency versions are \
                      non-reproducible and vulnerable to substitution attacks."
                .to_string(),
            location: root_location(&project.root),
            suggestion: Some(
                "Run `npm install` (or `pnpm install` / `yarn`) to generate a lock file \
                 and commit it to version control."
                    .to_string(),
            ),
            references: vec![],
            cwe: META.cwe_vec(),
            owasp: META.owasp_vec(),
        }]
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
        Chain001NoLockfileAnalyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn no_lockfile_emits_medium() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"my-pkg","version":"1.0.0"}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "expected 1 finding; got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn with_package_lock_json_clean() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "package.json", r#"{"name":"my-pkg"}"#);
        write(dir.path(), "package-lock.json", r#"{"lockfileVersion":3}"#);
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "lock file present → 0 findings; got: {findings:#?}"
        );
    }

    #[test]
    fn with_pnpm_lockfile_clean() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "package.json", r#"{"name":"my-pkg"}"#);
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: 9\n");
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "pnpm lock → 0 findings; got: {findings:#?}"
        );
    }

    #[test]
    fn with_yarn_lock_clean() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "package.json", r#"{"name":"my-pkg"}"#);
        write(dir.path(), "yarn.lock", "# yarn lockfile v1\n");
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "yarn lock → 0 findings; got: {findings:#?}"
        );
    }

    #[test]
    fn no_package_json_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        // No package.json at all — not a JS project, do not flag.
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "no package.json → 0 findings; got: {findings:#?}"
        );
    }

    #[test]
    fn finding_message_mentions_lockfile() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "package.json", r#"{"name":"x"}"#);
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("lock file"),
            "message should mention 'lock file': {}",
            findings[0].message
        );
    }
}
