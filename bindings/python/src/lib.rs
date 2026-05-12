//! PyO3 bindings for the `zuit` static analysis engine.
//!
//! Exposes two functions to Python:
//! - `analyze(path: str) -> str` — analyse a path and return findings as JSON.
//! - `version() -> str` — return the package version from Cargo metadata.
//!
//! # Example (Python)
//!
//! ```python
//! import zuit
//! json_str = zuit.analyze("/path/to/project")
//! print(zuit.version())
//! ```
#![warn(missing_docs)]
// PyO3's `#[pymodule]` and `#[pyfunction]` macros expand to unsafe code
// internally.  The binding crate itself contains no `unsafe {}` blocks.
#![allow(unsafe_code)]

use std::path::Path;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Analyse all source files under `path` and return a JSON string.
///
/// The JSON object matches the `zuit_core::Report` schema.
///
/// # Errors
///
/// Raises `ValueError` if the engine fails or the result cannot be serialised.
#[pyfunction]
fn analyze(path: &str) -> PyResult<String> {
    // Build a minimal registry with all built-in languages and analyzers.
    // NOTE: Because this binding is out-of-workspace and cannot depend on
    // `zuit-cli` (which owns `build_registry`), we use a bare `Registry`.
    // For v1 this returns findings from whatever languages zuit-core knows
    // about natively.  A richer registry can be wired in a future version.
    let registry = zuit_core::Registry::new();
    let engine = zuit_core::Engine::new(registry);
    let config = zuit_core::Config::default();

    let report = engine
        .analyze_path(Path::new(path), &config)
        .map_err(|e| PyValueError::new_err(format!("analysis failed: {e}")))?;

    serde_json::to_string(&report)
        .map_err(|e| PyValueError::new_err(format!("serialisation failed: {e}")))
}

/// Return the zuit package version string.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The `zuit` Python module.
#[pymodule]
fn zuit(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
