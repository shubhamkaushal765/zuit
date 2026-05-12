//! CHAIN — Supply Chain rule family for Rust crates.
//!
//! All rules in this family are `AnalyzerKind::ProjectLevel` with
//! `Dimension::Custom("supply_chain")`.  They operate on local filesystem
//! signals only; no network calls are made.
//!
//! ## Rules
//!
//! | Rule ID | Name | Severity |
//! |---------|------|----------|
//! | `CHAIN001` | no-lockfile | Medium |
//! | `CHAIN002` | typosquat-suspicion | High |
//! | `CHAIN003` | git-dependency-without-rev | Medium |
//! | `CHAIN004` | path-dependency-in-published-crate | Medium |

pub mod chain001_no_lockfile;
pub mod chain002_typosquat_suspicion;
pub mod chain003_git_dependency_without_rev;
pub mod chain004_path_dependency_in_published_crate;
pub(crate) mod typosquat;

pub use chain001_no_lockfile::Chain001NoLockfile;
pub use chain002_typosquat_suspicion::Chain002TyposquatSuspicion;
pub use chain003_git_dependency_without_rev::Chain003GitDependencyWithoutRev;
pub use chain004_path_dependency_in_published_crate::Chain004PathDependencyInPublishedCrate;

use std::path::Path;

use zuit_core::{
    AnalyzerId, Dimension, Finding, Location, Project, Severity,
    span::{ByteOffset, LineCol, Span},
};

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Builds a project-level [`Finding`] anchored to `Cargo.toml` (or a
/// synthetic path when the file is absent) for the `supply_chain` dimension.
pub(crate) fn chain_finding(
    project: &Project,
    cargo_toml_path: &Path,
    rule_id: &'static str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let relative = cargo_toml_path
        .strip_prefix(&project.root)
        .unwrap_or(cargo_toml_path)
        .to_path_buf();

    Finding {
        analyzer: AnalyzerId::new(rule_id),
        dimension: Dimension::Custom("supply_chain".to_string()),
        rule_id: rule_id.to_string(),
        severity,
        message,
        location: Location {
            file: relative,
            span: Span::new(ByteOffset(0), ByteOffset(0)),
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion,
        references: vec![
            "https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html".to_string(),
        ],
        cwe: vec![],
        owasp: vec![],
    }
}
