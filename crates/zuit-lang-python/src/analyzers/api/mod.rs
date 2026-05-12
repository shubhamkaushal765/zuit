//! API Stability rule family — `API001`, `API002`, `API003`.
//!
//! All three rules are `AnalyzerKind::ProjectLevel` with
//! `Dimension::Custom("api_stability")`.
//!
//! ## Activation gate
//!
//! The family is **disabled by default**.  It activates only when a baseline
//! ref is configured.  Each analyzer holds an `Option<String> baseline_ref`
//! field (default `None`).  When `None` the analyzer returns `Vec::new()`
//! silently.
//!
//! Wiring `[python.api] baseline_ref` from the global `Config` is deferred to
//! a later config-validation phase.
//!
//! ## Baseline extraction
//!
//! Production code calls `extract_public_api_from_ref`, which shells out to
//! `git archive <ref> | tar -x -C <tempdir>` and then walks the extracted
//! directory.  In tests, `#[cfg(test)]`-gated constructors accept a
//! `PublicApi` value directly, bypassing git entirely.

pub mod api001_public_symbol_removed;
pub mod api002_signature_arity_changed;
pub mod api003_semver_alignment;
pub mod ref_archive;
pub mod symbols;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;

use zuit_core::{
    AnalyzerId, Dimension, Finding, Location, Project, Severity,
    span::{ByteOffset, LineCol, Span},
};

// ── Public API snapshot ───────────────────────────────────────────────────────

/// Signature of a single public function: parameter counts broken out by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FunctionSig {
    /// Number of positional-only parameters (`/` syntax).
    pub posonly: usize,
    /// Number of regular positional-or-keyword parameters.
    pub args: usize,
    /// Number of keyword-only parameters (after `*` or `*args`).
    pub kwonly: usize,
}

impl FunctionSig {
    /// Total arity for API002 comparison purposes.
    pub(crate) fn total_arity(&self) -> usize {
        self.posonly + self.args + self.kwonly
    }
}

/// A snapshot of a project's public API surface at one git ref.
#[derive(Debug, Clone, Default)]
pub(crate) struct PublicApi {
    /// Public top-level functions, keyed by name.
    pub functions: BTreeMap<String, FunctionSig>,
    /// Public top-level class names.
    pub classes: BTreeSet<String>,
    /// Version string from `[project].version` in `pyproject.toml`, if present.
    pub version: Option<String>,
}

// ── ApiError ──────────────────────────────────────────────────────────────────

/// Errors that can occur while extracting a `PublicApi` snapshot.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    /// A subprocess (git archive / tar) failed to spawn or run.
    #[error("subprocess error: {0}")]
    Spawn(#[from] io::Error),
    /// `pyproject.toml` could not be parsed as TOML.
    #[error("TOML parse error: {0}")]
    Toml(String),
    /// A `.py` file could not be parsed as Python.
    #[error("Python parse error: {0}")]
    #[allow(dead_code)]
    Parse(String),
}

// ── Directory-level extractor ─────────────────────────────────────────────────

/// Extracts a [`PublicApi`] snapshot from a project directory.
///
/// Walks all `.py` files under `root` (skipping `tests/` directories and
/// `conftest.py` files), parses each via `rustpython-parser`, and accumulates
/// top-level public symbols.  Also reads `<root>/pyproject.toml` for the
/// version string.
///
/// # Errors
///
/// Returns `ApiError::Toml` if `pyproject.toml` exists but is malformed TOML.
/// Individual `.py` parse errors are silently skipped (best-effort).
pub(crate) fn extract_public_api_from_dir(root: &Path) -> Result<PublicApi, ApiError> {
    use rustpython_parser::Parse;
    use rustpython_parser::ast::ModModule;

    let mut api = PublicApi::default();

    // Read version from pyproject.toml.
    let pyproject = root.join("pyproject.toml");
    if pyproject.exists() {
        let content = std::fs::read_to_string(&pyproject).map_err(ApiError::Spawn)?;
        let doc: toml_edit::DocumentMut = content
            .parse()
            .map_err(|e: toml_edit::TomlError| ApiError::Toml(e.to_string()))?;
        if let Some(version) = doc
            .get("project")
            .and_then(|p| p.get("version"))
            .and_then(|v| v.as_str())
        {
            api.version = Some(version.to_string());
        }
    }

    // Walk .py files.
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        // Skip tests/ directories and conftest.py.
        let rel = path.strip_prefix(root).unwrap_or(path);
        let rel_str = rel.to_string_lossy();
        if rel_str.starts_with("tests/") || rel_str.starts_with("test/") {
            continue;
        }
        if path.file_name().is_some_and(|n| n == "conftest.py") {
            continue;
        }
        if path.extension().is_none_or(|e| e != "py") {
            continue;
        }

        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };
        let file_name = path.to_string_lossy().into_owned();
        let Ok(module) = ModModule::parse(&source, &file_name) else {
            continue;
        };
        symbols::collect_public_api(&module, &mut api);
    }

    Ok(api)
}

/// Extracts a [`PublicApi`] snapshot by running `git archive <ref>` and
/// extracting into a temporary directory.
///
/// # Errors
///
/// Returns `ApiError::Spawn` when the git subprocess fails.
pub(crate) fn extract_public_api_from_ref(
    git_ref: &str,
    project_root: &Path,
) -> Result<PublicApi, ApiError> {
    let tmp = ref_archive::extract_ref_to_tempdir(git_ref, project_root)?;
    extract_public_api_from_dir(tmp.path())
}

// ── Shared finding builder ────────────────────────────────────────────────────

/// Builds an API-stability [`Finding`] anchored to the project root.
pub(crate) fn api_finding(
    project: &Project,
    rule_id: &'static str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let file = {
        let pp = project.root.join("pyproject.toml");
        if pp.exists() {
            pp.strip_prefix(&project.root).unwrap_or(&pp).to_path_buf()
        } else {
            std::path::PathBuf::from(".")
        }
    };

    Finding {
        analyzer: AnalyzerId::new(rule_id),
        dimension: Dimension::Custom("api_stability".to_string()),
        rule_id: rule_id.to_string(),
        severity,
        message,
        location: Location {
            file,
            span: Span::new(ByteOffset(0), ByteOffset(0)),
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion,
        references: vec![],
        cwe: vec![],
        owasp: vec![],
    }
}

/// Builds the `API/baseline-unavailable` Info finding emitted when git archive
/// extraction fails.
pub(crate) fn baseline_unavailable_finding(project: &Project, reason: &str) -> Finding {
    api_finding(
        project,
        "API/baseline-unavailable",
        Severity::Info,
        format!(
            "Baseline API snapshot could not be extracted; API001–API003 checks are skipped. \
             Reason: {reason}"
        ),
        Some(
            "Ensure the configured `baseline_ref` is a valid git ref reachable from this \
             repository."
                .to_string(),
        ),
    )
}
