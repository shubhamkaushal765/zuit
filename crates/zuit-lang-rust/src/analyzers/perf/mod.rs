//! PERF — Performance heuristics rule family for Rust crates.
//!
//! All rules use `Dimension::Custom("performance")`.
//! `PERF001` is `AnalyzerKind::ProjectLevel`; `PERF002`, `PERF003`, and
//! `PERF010` are `AnalyzerKind::FileLevel`.
//!
//! ## Rules
//!
//! | Rule ID | Name | Severity | Kind |
//! |---------|------|----------|------|
//! | `PERF001` | heavy-default-features | Medium | ProjectLevel |
//! | `PERF002` | clone-in-iter-chain | Medium | FileLevel |
//! | `PERF003` | arc-mutex-density | Low | ProjectLevel |
//! | `PERF010` | allocation-in-loop | Low | FileLevel |

pub mod perf001_heavy_default_features;
pub mod perf002_clone_in_iter_chain;
pub mod perf003_arc_mutex_density;
pub mod perf010_allocation_in_loop;

pub use perf001_heavy_default_features::Perf001HeavyDefaultFeatures;
pub use perf002_clone_in_iter_chain::Perf002CloneInIterChain;
pub use perf003_arc_mutex_density::Perf003ArcMutexDensity;
pub use perf010_allocation_in_loop::Perf010AllocationInLoop;

use std::path::Path;

use zuit_core::{
    AnalyzerId, Dimension, Finding, Location, Project, Severity,
    span::{ByteOffset, LineCol, Span},
};

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Builds a project-level [`Finding`] anchored to `Cargo.toml` for the
/// `performance` dimension.
pub(crate) fn perf_finding(
    project: &Project,
    file: &Path,
    rule_id: &'static str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let relative = file
        .strip_prefix(&project.root)
        .unwrap_or(file)
        .to_path_buf();

    Finding {
        analyzer: AnalyzerId::new(rule_id),
        dimension: Dimension::Custom("performance".to_string()),
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
        references: vec!["https://nnethercote.github.io/perf-book/".to_string()],
        cwe: vec![],
        owasp: vec![],
    }
}
