//! History store, HTTP server, and daemon for `zuit show`.
#![warn(missing_docs)]

pub mod analytics;
pub mod assets;
pub mod daemon;
pub mod error;
pub mod hash;
pub mod history;
pub mod router;
pub mod server;

pub use analytics::{
    DeltaVsPrevious, FileCount, HeatmapEntry, ProjectSummary, RuleCount, ScanAnalytics, ScanDiff,
    TrendPoint, compute_heatmap, compute_project_summary, compute_scan_analytics,
    compute_scan_diff, compute_trends, score_to_grade,
};
pub use error::HistoryError;
pub use history::{ConfigId, HistoryStore, ProjectId, ProjectMeta, ScanId, ScanIndexEntry};
pub use server::{ServerHandle, start, start_with_listener};
