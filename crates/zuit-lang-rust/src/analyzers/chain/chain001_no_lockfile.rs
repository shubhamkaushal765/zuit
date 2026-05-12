//! `CHAIN001-no-lockfile` — emits when a binary Rust crate has no `Cargo.lock`.
//!
//! For **binary crates** (anything with `[[bin]]` OR a `src/main.rs` file),
//! a missing `Cargo.lock` means dependency versions are not reproducibly pinned,
//! making builds non-deterministic and potentially pulling in future vulnerable
//! or malicious releases of transitive dependencies.
//!
//! Library crates conventionally do **not** check in `Cargo.lock` (Cargo docs
//! recommend this), so the rule is silent for pure library crates.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::chain_finding;

const RULE_ID: &str = "CHAIN001-no-lockfile";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/CHAIN001-no-lockfile.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `CHAIN001` when a binary crate has no `Cargo.lock`.
pub struct Chain001NoLockfile;

impl zuit_core::Analyzer for Chain001NoLockfile {
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

        // Only fire when Cargo.toml is present.
        let Some(ref cargo_toml_path) = manifest.cargo_toml_path else {
            return Vec::new();
        };

        // Only fire for binary crates.
        if !is_binary_crate(&manifest, &project.root) {
            return Vec::new();
        }

        // If Cargo.lock exists, no finding.
        if manifest.cargo_lock_path.is_some() {
            return Vec::new();
        }

        vec![chain_finding(
            project,
            cargo_toml_path,
            RULE_ID,
            Severity::Medium,
            "Binary crate has no `Cargo.lock`; dependency versions are not reproducibly \
             pinned. Builds may differ across machines or over time, and future yanked or \
             malicious dependency releases could silently affect the build."
                .to_string(),
            Some(
                "Run `cargo build` (or `cargo generate-lockfile`) once to create `Cargo.lock`, \
                 then commit it to version control."
                    .to_string(),
            ),
        )]
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns `true` if the crate appears to be a binary (application) crate.
///
/// Heuristic: `[[bin]]` table is present in `Cargo.toml`, OR `src/main.rs`
/// exists relative to the project root.
fn is_binary_crate(manifest: &crate::manifest::RustManifest, root: &std::path::Path) -> bool {
    // Check src/main.rs first (fastest).
    if root.join("src/main.rs").exists() {
        return true;
    }

    // Check [[bin]] table in Cargo.toml.
    if let Some(doc) = &manifest.cargo_toml
        && doc.get("bin").is_some()
    {
        return true;
    }

    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};

    fn run(root: &std::path::Path) -> Vec<Finding> {
        crate::manifest::clear_cache();
        let project = Project::new(root, vec![]);
        let analyzer = Chain001NoLockfile;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    /// Plan test: binary crate, no Cargo.lock → one CHAIN001 Medium.
    #[test]
    fn chain001_binary_no_lockfile_emits_medium() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            b"[package]\nname = \"my-bin\"\nversion = \"1.0.0\"\n\
              [[bin]]\nname = \"my-bin\"\npath = \"src/main.rs\"\n",
        )
        .unwrap();
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 CHAIN001 finding: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Plan test (negative): library crate, no Cargo.lock → 0 findings.
    #[test]
    fn chain001_lib_crate_no_lockfile_silent() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            b"[package]\nname = \"my-lib\"\nversion = \"1.0.0\"\n\
              [lib]\nname = \"my_lib\"\n",
        )
        .unwrap();
        // No src/main.rs, no [[bin]]
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "lib crate without lockfile must not trigger: {findings:#?}"
        );
    }

    /// Plan test (negative): binary crate with Cargo.lock → 0 findings.
    #[test]
    fn chain001_binary_with_lockfile_silent() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            b"[package]\nname = \"my-bin\"\nversion = \"1.0.0\"\n\
              [[bin]]\nname = \"my-bin\"\npath = \"src/main.rs\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), b"# generated by cargo\n").unwrap();
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "binary with Cargo.lock must not trigger: {findings:#?}"
        );
    }

    /// src/main.rs also signals binary.
    #[test]
    fn chain001_src_main_rs_signals_binary() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            b"[package]\nname = \"my-app\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/main.rs"), b"fn main() {}\n").unwrap();
        // No Cargo.lock
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "src/main.rs should signal binary: {findings:#?}"
        );
    }
}
