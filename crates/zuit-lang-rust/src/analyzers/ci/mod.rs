//! CI — CI/CD & Release hygiene rule family for Rust crates.
//!
//! All rules are `AnalyzerKind::ProjectLevel` with
//! `Dimension::Custom("ci_release")`.  They inspect the project root
//! filesystem for CI configuration files.  No network calls are made.
//!
//! ## Rules
//!
//! | Rule ID | Name | Severity |
//! |---------|------|----------|
//! | `CI001` | no-ci-config | Medium |
//! | `CI002` | no-msrv-test-job | Low |
//! | `CI003` | no-windows-job | Low |
//! | `CI004` | no-cargo-deny-job | Low |
//! | `CI005` | no-dependabot | Low |

pub mod ci001_no_ci_config;
pub mod ci002_no_msrv_test_job;
pub mod ci003_no_windows_job;
pub mod ci004_no_cargo_deny_job;
pub mod ci005_no_dependabot;

pub use ci001_no_ci_config::Ci001NoCiConfig;
pub use ci002_no_msrv_test_job::Ci002NoMsrvTestJob;
pub use ci003_no_windows_job::Ci003NoWindowsJob;
pub use ci004_no_cargo_deny_job::Ci004NoCargoDenyJob;
pub use ci005_no_dependabot::Ci005NoDependabot;

use std::path::Path;

use zuit_core::{
    AnalyzerId, Dimension, Finding, Location, Project, Severity,
    span::{ByteOffset, LineCol, Span},
};

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Builds a project-level [`Finding`] for the `ci_release` dimension,
/// anchored to the project root directory.
pub(crate) fn ci_finding(
    _project: &Project,
    rule_id: &'static str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let file = std::path::PathBuf::from(".");

    Finding {
        analyzer: AnalyzerId::new(rule_id),
        dimension: Dimension::Custom("ci_release".to_string()),
        rule_id: rule_id.to_string(),
        severity,
        message,
        location: Location {
            file,
            span: Span::new(ByteOffset(0), ByteOffset(0)),
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion,
        references: vec!["https://doc.rust-lang.org/cargo/reference/publishing.html".to_string()],
        cwe: vec![],
        owasp: vec![],
    }
}

/// Returns all `.github/workflows/*.{yml,yaml}` file paths found in `project_root`.
pub(crate) fn find_workflow_files(project_root: &Path) -> Vec<std::path::PathBuf> {
    let workflows_dir = project_root.join(".github").join("workflows");
    if !workflows_dir.is_dir() {
        return vec![];
    }
    let Ok(entries) = std::fs::read_dir(&workflows_dir) else {
        return vec![];
    };
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if path.is_file() && (ext == "yml" || ext == "yaml") {
                Some(path)
            } else {
                None
            }
        })
        .collect()
}

/// Returns `true` if any CI configuration exists in `project_root`.
///
/// Checks:
/// - `.github/workflows/*.{yml,yaml}`
/// - `.gitlab-ci.yml`
/// - `.circleci/config.yml`
pub(crate) fn has_ci_config(project_root: &Path) -> bool {
    if !find_workflow_files(project_root).is_empty() {
        return true;
    }
    if project_root.join(".gitlab-ci.yml").exists() {
        return true;
    }
    if project_root.join(".circleci").join("config.yml").exists() {
        return true;
    }
    false
}

/// Reads all workflow file contents into a single concatenated string for
/// substring scanning.
pub(crate) fn read_workflow_contents(project_root: &Path) -> String {
    find_workflow_files(project_root)
        .into_iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect::<Vec<_>>()
        .join("\n")
}
