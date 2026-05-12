//! Error types for the JavaScript / TypeScript language frontend.
//!
//! [`JsError`] mirrors the per-crate error pattern: a single enum covering
//! binary-not-found, spawn failures, and JSON parse errors.
//! `BinaryNotFound` is handled by emitting an informational finding rather
//! than propagating; `Json` is returned to callers; `Spawn` represents an
//! OS-level failure.

use thiserror::Error;

/// Errors that can occur during JS / TS analysis.
#[derive(Debug, Error)]
pub enum JsError {
    /// An external tool binary was not found on `$PATH`.
    #[error("{0} binary not found on PATH")]
    BinaryNotFound(&'static str),

    /// Failed to spawn an external tool process.
    #[error("failed to spawn {tool}: {source}")]
    Spawn {
        /// The name of the tool that failed to spawn.
        tool: &'static str,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse a tool's JSON output.
    #[error("failed to parse JSON output: {0}")]
    Json(#[from] serde_json::Error),

    /// I/O error reading project metadata files (`package.json`, lockfiles).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
