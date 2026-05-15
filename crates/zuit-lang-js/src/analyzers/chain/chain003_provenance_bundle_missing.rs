//! `CHAIN003-provenance-bundle-missing` — flags projects that ship a `dist/`
//! directory without a provenance attestation file.
//!
//! npm provenance (via Sigstore) allows consumers to verify that a published
//! package was built from a specific source commit. The attestation is typically
//! published as a `.sigstore` or `.sigstore.json` companion file alongside the
//! bundle. When a `dist/` directory exists but no such file is present, consumers
//! cannot verify supply-chain integrity of the published artefact.
//!
//! # Scope
//!
//! This analyzer only checks for the *presence* of a provenance file, not its
//! *validity* (network-free by design — see `.agent/JS_PLAN.md` §9). A future
//! phase may add offline signature verification using the bundled Sigstore roots.
//!
//! Only the immediate children of `dist/` are inspected (v1 behaviour). Recursive
//! search is deferred.

use std::path::Path;

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

/// Rule ID for the provenance-bundle-missing check.
const RULE_ID: &str = "CHAIN003-provenance-bundle-missing";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/CHAIN003-provenance-bundle-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Zero-width location anchored at the project root directory.
///
/// CHAIN003 is a filesystem-presence rule; no single file is the authoritative
/// location, so we point at the root.
fn root_location(root: &Path) -> Location {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Location {
        file: root.to_path_buf(),
        span: zero,
        start: LineCol::new(1, 1),
        end: LineCol::new(1, 1),
    }
}

/// Returns `true` if `path`'s file name ends with `.sigstore` or `.sigstore.json`.
fn is_sigstore_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name.ends_with(".sigstore") || name.ends_with(".sigstore.json"))
}

/// Core logic — unit-testable without a real project.
///
/// Returns one finding if `dist_dir` exists and contains no sigstore file among
/// its immediate children.  Returns an empty vec otherwise.
pub(crate) fn evaluate(root: &Path, dist_dir: &Path) -> Vec<Finding> {
    if !dist_dir.is_dir() {
        return vec![];
    }

    let has_sigstore = std::fs::read_dir(dist_dir).ok().is_some_and(|mut entries| {
        entries.any(|entry| {
            entry
                .as_ref()
                .map(|e| is_sigstore_file(&e.path()))
                .unwrap_or(false)
        })
    });

    if has_sigstore {
        return vec![];
    }

    vec![Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Custom("supply_chain".to_string()),
        rule_id: RULE_ID.to_string(),
        severity: Severity::Low,
        message: "A `dist/` directory was found but no Sigstore provenance file \
                  (`.sigstore` or `.sigstore.json`) is present as a sibling. \
                  Consumers cannot verify the supply-chain integrity of this bundle."
            .to_string(),
        location: root_location(root),
        suggestion: Some(
            "Publish with npm provenance enabled (`npm publish --provenance`) to \
             generate a Sigstore attestation alongside the bundle."
                .to_string(),
        ),
        references: vec![],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    }]
}

/// Analyzer that emits `CHAIN003-provenance-bundle-missing` when a `dist/`
/// directory exists but contains no Sigstore provenance attestation.
pub struct Chain003ProvenanceBundleMissingAnalyzer;

impl Analyzer for Chain003ProvenanceBundleMissingAnalyzer {
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
        let dist_dir = project.root.join("dist");
        evaluate(&project.root, &dist_dir)
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
        Chain003ProvenanceBundleMissingAnalyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn no_dist_folder_clean() {
        let dir = TempDir::new().expect("tempdir");
        // No dist/ directory at all.
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "no dist/ → 0 findings; got: {findings:#?}"
        );
    }

    #[test]
    fn dist_without_sigstore_emits_low() {
        let dir = TempDir::new().expect("tempdir");
        let dist = dir.path().join("dist");
        std::fs::create_dir(&dist).expect("create dist/");
        write(&dist, "index.js", "module.exports = {};");
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "dist/ without sigstore → 1 finding; got: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn dist_with_sigstore_extension_clean() {
        let dir = TempDir::new().expect("tempdir");
        let dist = dir.path().join("dist");
        std::fs::create_dir(&dist).expect("create dist/");
        write(&dist, "index.js", "module.exports = {};");
        write(
            &dist,
            "index.js.sigstore",
            r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json"}"#,
        );
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "dist/ with .sigstore → 0 findings; got: {findings:#?}"
        );
    }

    #[test]
    fn dist_with_sigstore_json_extension_clean() {
        let dir = TempDir::new().expect("tempdir");
        let dist = dir.path().join("dist");
        std::fs::create_dir(&dist).expect("create dist/");
        write(&dist, "index.js", "module.exports = {};");
        write(&dist, "bundle.sigstore.json", "{}");
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "dist/ with .sigstore.json → 0 findings; got: {findings:#?}"
        );
    }

    #[test]
    fn empty_dist_dir_emits_low() {
        let dir = TempDir::new().expect("tempdir");
        let dist = dir.path().join("dist");
        std::fs::create_dir(&dist).expect("create dist/");
        // dist/ exists but is completely empty.
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "empty dist/ with no sigstore → 1 finding; got: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn finding_message_mentions_sigstore() {
        let dir = TempDir::new().expect("tempdir");
        let dist = dir.path().join("dist");
        std::fs::create_dir(&dist).expect("create dist/");
        write(&dist, "index.js", "");
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("sigstore") || findings[0].message.contains("Sigstore"),
            "message must mention sigstore: {}",
            findings[0].message
        );
    }

    #[test]
    fn is_sigstore_file_helper() {
        use std::path::PathBuf;
        assert!(is_sigstore_file(&PathBuf::from("foo.sigstore")));
        assert!(is_sigstore_file(&PathBuf::from("bar.sigstore.json")));
        assert!(!is_sigstore_file(&PathBuf::from("index.js")));
        assert!(!is_sigstore_file(&PathBuf::from("sigstore")));
    }
}
