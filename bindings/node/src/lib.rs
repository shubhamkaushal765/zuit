//! napi-rs bindings for the `zuit` static analysis engine.
//!
//! Exposes two functions to Node.js:
//! - `analyze(path: string) -> string` — analyse a path and return findings as JSON.
//! - `version() -> string` — return the package version from Cargo metadata.
//!
//! # Example (Node.js)
//!
//! ```js
//! const { analyze, version } = require('zuit');
//! const report = JSON.parse(analyze('/path/to/project'));
//! console.log(version());
//! ```
#![warn(missing_docs)]
// napi-rs requires unsafe code in the generated FFI glue.
// The binding itself contains no `unsafe {}` blocks.
#![allow(unsafe_code)]

use std::path::Path;

use napi_derive::napi;

/// Analyse all source files under `path` and return a JSON string.
///
/// The JSON object matches the `zuit_core::Report` schema.
///
/// # Errors
///
/// Returns an error string if the engine fails or the result cannot be
/// serialised.
#[napi]
pub fn analyze(path: String) -> napi::Result<String> {
    // Build a minimal registry with an empty set of languages.
    // For v1 this returns an empty report (no registered language frontends).
    // A full registry wired to zuit-cli will be added in a future version.
    let registry = zuit_core::Registry::new();
    let engine = zuit_core::Engine::new(registry);
    let config = zuit_core::Config::default();

    let report = engine
        .analyze_path(Path::new(&path), &config)
        .map_err(|e| napi::Error::from_reason(format!("analysis failed: {e}")))?;

    serde_json::to_string(&report)
        .map_err(|e| napi::Error::from_reason(format!("serialisation failed: {e}")))
}

/// Return the zuit package version string.
#[napi]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
