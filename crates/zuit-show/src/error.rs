//! Error types for the `zuit-show` crate.

use std::path::PathBuf;

/// Failure modes for [`crate::history::HistoryStore`] operations.
#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    /// IO error reading or writing a file under `~/.zuit`.
    #[error("io error at {path}: {source}")]
    Io {
        /// The file or directory that was being touched.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// JSON serialization or deserialization error.
    #[error("json error at {path}: {source}")]
    Json {
        /// File the JSON came from / was being written to.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: serde_json::Error,
    },
    /// The supplied scan or project ID does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The user's HOME directory is not set or unreadable.
    #[error("could not determine home directory")]
    NoHome,
}
