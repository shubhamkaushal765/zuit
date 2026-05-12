//! Error types for the Python language frontend.
//!
//! [`PythonError`] is the unified error type returned by operations in this crate.

use thiserror::Error;

/// Errors that can occur during Python analysis.
///
/// The two "expected" variants ([`PythonError::BinaryNotFound`], [`PythonError::Json`])
/// are handled gracefully by the analyzer: `BinaryNotFound` emits an
/// informational finding; `Json` is returned to the caller.  Only
/// [`PythonError::Spawn`] represents a system-level failure.
#[derive(Debug, Error)]
pub enum PythonError {
    /// The external tool binary was not found on `$PATH`.
    #[error("binary not found on PATH")]
    BinaryNotFound,

    /// The operating system could not spawn the external process.
    #[error("failed to spawn process: {0}")]
    Spawn(#[from] std::io::Error),

    /// The JSON output from the external tool could not be parsed.
    #[error("failed to parse JSON output: {0}")]
    Json(#[from] serde_json::Error),
}
