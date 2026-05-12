//! Error types for zuit-core: [`ParseError`], [`EngineError`], and [`ConfigError`].
//!
//! Every public error implements [`std::error::Error`] via [`thiserror`] and
//! provides a human-readable `Display` message aimed at CLI consumers.

use std::path::PathBuf;

use crate::span::Span;

/// An error produced during source-file parsing by a language frontend.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The file contains a syntax error at the given location.
    #[error("syntax error in {file}: {message}")]
    Syntax {
        /// Path of the file that could not be parsed.
        file: PathBuf,
        /// Human-readable description of the syntax error.
        message: String,
        /// Byte span of the offending token, if the frontend provides one.
        span: Option<Span>,
    },

    /// The file's bytes are not valid UTF-8.
    #[error("file not utf-8: {0}")]
    Encoding(PathBuf),

    /// An internal error inside the frontend (e.g., unexpected AST shape).
    #[error("internal frontend error: {0}")]
    Internal(String),
}

/// An error produced during a configuration file load.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The TOML file could not be read from disk.
    #[error("io error reading config: {0}")]
    Io(#[from] std::io::Error),

    /// The TOML content is syntactically invalid.
    #[error("config parse error: {0}")]
    Parse(String),

    /// The TOML structure is valid but contains unrecognised or invalid fields.
    #[error("config validation error: {0}")]
    Validation(String),
}

/// Top-level error returned by [`crate::engine::Engine::analyze_path`].
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// A file could not be parsed.
    #[error(transparent)]
    Parse(#[from] ParseError),

    /// The configuration file could not be loaded.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// An I/O error occurred during file walking or reading.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parse_error_syntax_display() {
        let err = ParseError::Syntax {
            file: PathBuf::from("src/lib.rs"),
            message: "unexpected token `}`".to_string(),
            span: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("src/lib.rs"));
        assert!(msg.contains("unexpected token"));
    }

    #[test]
    fn parse_error_encoding_display() {
        let err = ParseError::Encoding(PathBuf::from("bad.rs"));
        assert!(err.to_string().contains("bad.rs"));
    }

    #[test]
    fn parse_error_internal_display() {
        let err = ParseError::Internal("oops".to_string());
        assert!(err.to_string().contains("oops"));
    }

    #[test]
    fn engine_error_from_io() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = EngineError::Io(io);
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn engine_error_from_parse() {
        let pe = ParseError::Internal("bad".to_string());
        let ee: EngineError = pe.into();
        assert!(ee.to_string().contains("bad"));
    }

    #[test]
    fn config_error_from_io() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let ce: ConfigError = io.into();
        assert!(ce.to_string().contains("denied"));
    }
}
