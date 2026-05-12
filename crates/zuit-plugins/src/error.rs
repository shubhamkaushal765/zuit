//! Error type for the zuit plugin loader.

use thiserror::Error;

/// Errors that can arise while loading, installing, or running a plugin.
#[derive(Debug, Error)]
pub enum PluginError {
    /// Filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Plugin manifest validation failed (semantic error after TOML parse).
    #[error("manifest validation failed: {0}")]
    Manifest(String),

    /// Plugin manifest TOML deserialization failed.
    #[error("manifest TOML parse failed: {0}")]
    Toml(#[from] toml::de::Error),

    /// A plugin with the requested name is already installed.
    #[error("plugin '{0}' is already installed")]
    AlreadyInstalled(String),

    /// No plugin with the requested name is installed.
    #[error("plugin '{0}' is not installed")]
    NotFound(String),

    /// The `git` subprocess failed.
    #[error("git {stage} failed: {message}")]
    Git {
        /// Which git subcommand failed (e.g. "clone", "rev-parse", "pull").
        stage: &'static str,
        /// Stderr (or other diagnostic) captured from git.
        message: String,
    },

    /// Local-path install rejected (e.g. path does not exist or is not a directory).
    #[error("local path: {0}")]
    LocalPath(String),

    /// JSON serialization or deserialization failed (used by the source sidecar).
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Failed to acquire the install lock.
    #[error("lock: {0}")]
    Lock(String),

    /// A required environment variable (`HOME` or `ZUIT_HOME`) is not set.
    #[error("environment: {0}")]
    Env(String),
}
