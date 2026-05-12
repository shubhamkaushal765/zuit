//! `CHAIN003-sigstore-bundle-missing` — emits when a `dist/` artifact (`.whl`
//! or `.tar.gz`) lacks a companion `.sigstore` bundle file.
//!
//! Sigstore bundles allow consumers to verify that an artifact was produced in
//! a trusted CI environment.  Their absence does not mean the artifact is
//! malicious, but it does mean consumers cannot perform provenance verification.
//!
//! **Note:** this rule performs presence-only checks.  It does **not** verify
//! or parse the sigstore bundle contents.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

use crate::manifest::manifest_for;

const RULE_ID: &str = "CHAIN003-sigstore-bundle-missing";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/CHAIN003-sigstore-bundle-missing.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `CHAIN003` for each `dist/` artifact without a
/// `.sigstore` companion.
pub struct Chain003SigstoreBundleMissing;

impl zuit_core::Analyzer for Chain003SigstoreBundleMissing {
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

        // Only fire when pyproject.toml is present (i.e. it's a Python project root).
        if manifest.pyproject_path.is_none() {
            return Vec::new();
        }

        let dist_dir = project.root.join("dist");
        let Ok(entries) = std::fs::read_dir(&dist_dir) else {
            // No dist/ directory — nothing to check.
            return Vec::new();
        };

        let mut findings = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            let is_whl = std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("whl"));
            // `.tar.gz` has a compound extension; check the full name.
            let is_sdist = name.to_lowercase().ends_with(".tar.gz");
            let is_artifact = is_whl || is_sdist;

            if !is_artifact {
                continue;
            }

            // Check for companion `.sigstore` file.
            let sigstore_path = dist_dir.join(format!("{name}.sigstore"));
            if sigstore_path.exists() {
                continue;
            }

            // Relative path for the finding location.
            let rel = path
                .strip_prefix(&project.root)
                .unwrap_or(&path)
                .to_path_buf();

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Custom("supply_chain".to_string()),
                rule_id: RULE_ID.to_string(),
                severity: Severity::Low,
                message: format!(
                    "Distribution artifact `{name}` in dist/ has no `.sigstore` \
                     companion bundle; consumers cannot verify provenance"
                ),
                location: Location {
                    file: rel,
                    span: Span::new(ByteOffset(0), ByteOffset(0)),
                    start: LineCol::new(1, 1),
                    end: LineCol::new(1, 1),
                },
                suggestion: Some(
                    "Sign the artifact with `sigstore sign dist/<artifact>` as part of your \
                     release CI pipeline."
                        .to_string(),
                ),
                references: vec!["https://www.sigstore.dev/".to_string()],
                cwe: vec![],
                owasp: vec![],
            });
        }

        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::io::Write as _;

    fn setup(dir: &tempfile::TempDir) {
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(b"[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\n")
            .unwrap();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
    }

    fn run(root: &std::path::Path) -> Vec<Finding> {
        crate::manifest::clear_cache();
        let project = Project::new(root, vec![]);
        let analyzer = Chain003SigstoreBundleMissing;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    /// Plan test 6a: whl + sigstore companion → 0 findings.
    #[test]
    fn chain003_sigstore_present_clean() {
        let dir = tempfile::TempDir::new().unwrap();
        setup(&dir);
        let whl = "foo-1.0-py3-none-any.whl";
        std::fs::write(dir.path().join("dist").join(whl), b"PK..").unwrap();
        std::fs::write(
            dir.path().join("dist").join(format!("{whl}.sigstore")),
            b"{}",
        )
        .unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "sigstore present → no finding: {findings:#?}"
        );
    }

    /// Plan test 6b: whl without companion → one Low finding.
    #[test]
    fn chain003_sigstore_missing_emits_low() {
        let dir = tempfile::TempDir::new().unwrap();
        setup(&dir);
        let whl = "foo-1.0-py3-none-any.whl";
        std::fs::write(dir.path().join("dist").join(whl), b"PK..").unwrap();
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "missing sigstore → 1 finding: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn chain003_sdist_without_sigstore_emits_low() {
        let dir = tempfile::TempDir::new().unwrap();
        setup(&dir);
        std::fs::write(dir.path().join("dist").join("foo-1.0.tar.gz"), b"tar").unwrap();
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "tar.gz without sigstore: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn chain003_no_dist_dir_is_silent() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(b"[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\n")
            .unwrap();
        // No dist/ directory created.
        let findings = run(dir.path());
        assert!(findings.is_empty(), "no dist/ → no finding: {findings:#?}");
    }

    #[test]
    fn chain003_no_pyproject_is_silent() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
        std::fs::write(
            dir.path().join("dist").join("foo-1.0-py3-none-any.whl"),
            b"PK..",
        )
        .unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "no pyproject.toml → silent: {findings:#?}"
        );
    }

    /// Healthy baseline: both whl and tar.gz have sigstore bundles → 0 findings.
    #[test]
    fn chain003_healthy_baseline() {
        let dir = tempfile::TempDir::new().unwrap();
        setup(&dir);
        for artifact in &["foo-1.0-py3-none-any.whl", "foo-1.0.tar.gz"] {
            std::fs::write(dir.path().join("dist").join(artifact), b"data").unwrap();
            std::fs::write(
                dir.path().join("dist").join(format!("{artifact}.sigstore")),
                b"{}",
            )
            .unwrap();
        }
        let findings = run(dir.path());
        assert!(findings.is_empty());
    }
}
