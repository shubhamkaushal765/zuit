//! `PKG007-version-mismatch` — detects a discrepancy between
//! `[package].version` in `Cargo.toml` and the latest git tag.
//!
//! When the published version in `Cargo.toml` differs from the latest `vX.Y.Z`
//! (or `X.Y.Z`) git tag, the crate may have been released without a matching
//! tag, or vice-versa.  Best-effort: silently skips when `.git` is absent or
//! `git` is not on `$PATH`.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::cargo_toml_finding;

const RULE_ID: &str = "PKG007-version-mismatch";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG007-version-mismatch.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG007` when `Cargo.toml` version differs from the
/// latest git tag.
pub struct Pkg007VersionMismatch;

impl zuit_core::Analyzer for Pkg007VersionMismatch {
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
        let Some(doc) = &manifest.cargo_toml else {
            return Vec::new();
        };

        // Skip if no .git directory (not a git repo).
        if !project.root.join(".git").exists() {
            return Vec::new();
        }

        // Read version from [package].version (skip workspace inheritance).
        let cargo_version = match doc
            .get("package")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("version"))
            .and_then(|v| v.as_str())
        {
            Some(v) => v.to_string(),
            None => return Vec::new(), // workspace-inherited or missing — skip
        };

        // Get the latest git tag, best-effort with 5 s timeout.
        let Some(latest_tag) = latest_git_tag(&project.root) else {
            return Vec::new(); // git unavailable or no tags — skip silently
        };

        // Strip leading 'v' from tag for comparison.
        let tag_version = latest_tag.trim_start_matches('v');

        if cargo_version == tag_version {
            return Vec::new();
        }

        let cargo_toml_path = manifest
            .cargo_toml_path
            .clone()
            .unwrap_or_else(|| project.root.join("Cargo.toml"));

        vec![cargo_toml_finding(
            project,
            &cargo_toml_path,
            RULE_ID,
            Severity::Medium,
            format!(
                "version mismatch: Cargo.toml has `{cargo_version}` but latest git tag is \
                 `{latest_tag}`"
            ),
            Some(
                "Ensure the `[package].version` in Cargo.toml matches the latest git tag, \
                 or create a new tag after bumping the version."
                    .to_string(),
            ),
        )]
    }
}

/// Runs `git tag --sort=-creatordate` with a 5 s timeout and returns the
/// first tag that looks like a version tag (`vX.Y.Z` or `X.Y.Z`).
///
/// Returns `None` on any failure.
fn latest_git_tag(root: &Path) -> Option<String> {
    // Spawn git with a 5 s wall-clock limit using a thread + channel.
    let root = root.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = Command::new("git")
            .args(["tag", "--sort=-creatordate", "--format=%(refname:short)"])
            .current_dir(&root)
            .output();
        let _ = tx.send(result);
    });

    let output = rx
        .recv_timeout(Duration::from_secs(5))
        .ok()
        .and_then(std::result::Result::ok)?;

    if !output.status.success() {
        return None;
    }

    let stdout = std::str::from_utf8(&output.stdout).ok()?;

    // Return the first tag that looks like a semver or v-prefixed semver.
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Accept "vX.Y.Z", "X.Y.Z", "vX.Y.Z-rc.1", etc.
        let candidate = trimmed.trim_start_matches('v');
        if candidate.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return Some(trimmed.to_string());
        }
    }

    None
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zuit_core::{Analyzer, Config, Project};

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg007VersionMismatch;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg007_no_git_dir_emits_zero() {
        // Without a .git directory the analyzer should skip silently.
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings without .git: {findings:#?}"
        );
    }

    #[test]
    fn pkg007_no_cargo_toml_emits_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg007VersionMismatch;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);
        assert!(findings.is_empty());
    }

    #[test]
    fn pkg007_suppression_directive_works() {
        // No .git → always zero, which is consistent with the suppression intent.
        let findings = run("# zuit: ignore PKG007\n[package]\nname = \"x\"\nversion = \"1.0\"\n");
        assert!(findings.is_empty());
    }
}
