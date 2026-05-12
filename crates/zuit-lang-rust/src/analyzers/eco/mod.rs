//! ECO — Ecosystem Compatibility rule family for Rust crates.
//!
//! All rules use `Dimension::Custom("ecosystem")` and are
//! `AnalyzerKind::ProjectLevel` (except `ECO003` which is `FileLevel`).
//!
//! ## Rules
//!
//! | Rule ID | Name | Severity | Kind |
//! |---------|------|----------|------|
//! | `ECO001` | no-no-std-feature | Low | ProjectLevel |
//! | `ECO002` | async-runtime-coupling | Low | ProjectLevel |
//! | `ECO003` | send-sync-violations-on-pub-types | Low | FileLevel |
//! | `ECO004` | feature-graph-fragmented | Low | ProjectLevel |

pub mod eco001_no_no_std_feature;
pub mod eco002_async_runtime_coupling;
pub mod eco003_send_sync_violations;
pub mod eco004_feature_graph_fragmented;

pub use eco001_no_no_std_feature::Eco001NoNoStdFeature;
pub use eco002_async_runtime_coupling::Eco002AsyncRuntimeCoupling;
pub use eco003_send_sync_violations::Eco003SendSyncViolations;
pub use eco004_feature_graph_fragmented::Eco004FeatureGraphFragmented;

use std::path::Path;

use zuit_core::{
    AnalyzerId, Dimension, Finding, Location, Project, Severity,
    span::{ByteOffset, LineCol, Span},
};

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Builds a project-level [`Finding`] anchored to `Cargo.toml` for the
/// `ecosystem` dimension.
pub(crate) fn eco_finding(
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
        dimension: Dimension::Custom("ecosystem".to_string()),
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
        references: vec!["https://doc.rust-lang.org/cargo/reference/features.html".to_string()],
        cwe: vec![],
        owasp: vec![],
    }
}
