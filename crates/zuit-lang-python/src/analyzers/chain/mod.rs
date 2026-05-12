//! CHAIN — Supply Chain rule family.
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
//! | `CHAIN003` | sigstore-bundle-missing | Low |
//! | `CHAIN004` | unpinned-runtime-dep | Medium |

pub mod chain001_no_lockfile;
pub mod chain002_typosquat_suspicion;
pub mod chain003_sigstore_bundle_missing;
pub mod chain004_unpinned_runtime_dep;
pub(crate) mod typosquat;

use zuit_core::{
    AnalyzerId, Dimension, Finding, Location, Project, Severity,
    span::{ByteOffset, LineCol, Span},
};

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Builds a project-level [`Finding`] anchored to `pyproject.toml` (or a
/// synthetic path) for the `supply_chain` dimension.
pub(crate) fn chain_finding(
    project: &Project,
    pyproject_path: &std::path::Path,
    rule_id: &'static str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let relative = pyproject_path
        .strip_prefix(&project.root)
        .unwrap_or(pyproject_path)
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
        references: vec!["https://docs.pypi.org/".to_string()],
        cwe: vec![],
        owasp: vec![],
    }
}
