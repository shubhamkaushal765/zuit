//! Error types for the Rust language frontend external-tool adapters.
//!
//! [`RustError`] is the unified error type returned by operations in this crate
//! that call external tools or parse their JSON output.

use thiserror::Error;

/// Errors that can occur during Rust analysis or external-tool invocation.
///
/// The two "expected" variants ([`RustError::BinaryNotFound`], [`RustError::Json`])
/// are handled gracefully by adapters: `BinaryNotFound` emits an informational
/// finding; `Json` is returned to the caller.  Only [`RustError::Spawn`]
/// represents a system-level failure.
#[derive(Debug, Error)]
pub enum RustError {
    /// A required binary was not found on `$PATH`.
    #[error("required binary not found on PATH: {0}")]
    BinaryNotFound(String),

    /// The operating system could not spawn the subprocess.
    #[error("failed to spawn subprocess: {0}")]
    Spawn(#[from] std::io::Error),

    /// The JSON output from an external tool could not be parsed.
    #[error("failed to parse JSON output: {0}")]
    Json(#[from] serde_json::Error),
}
