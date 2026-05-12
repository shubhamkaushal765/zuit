//! Python language frontend for zuit, backed by `rustpython-parser`.
//!
//! This crate provides:
//! - [`PythonLanguage`]: implements [`zuit_core::Language`], parsing `.py` files
//!   into a [`zuit_core::ParsedFile`] with a fully-populated [`zuit_core::SemanticIndex`].
//! - [`try_python_ast`]: typed accessor to downcast the native AST from a [`zuit_core::ParsedFile`].
//! - [`register`]: convenience function to register the frontend and all Python-only
//!   analyzers into a [`zuit_core::Registry`].
//!
//! The native AST type (`PythonAst`) is `pub(crate)` only; external code should
//! use [`try_python_ast`] which returns a reference to the inner
//! [`rustpython_parser::ast::ModModule`].
#![warn(missing_docs)]

pub mod analyzers;
pub(crate) mod complexity;
pub mod error;
pub(crate) mod index;
pub(crate) mod manifest;
pub(crate) mod parse;

use analyzers::{api, chain, external, health, perf, pkg};
use zuit_core::{ParsedFile, Registry};

pub use parse::PythonLanguage;

/// Returns a reference to the parsed `ModModule` AST stored inside `parsed`,
/// or `None` if `parsed` was not produced by [`PythonLanguage`].
///
/// This is the public typed escape hatch for Python-specific analyzers that
/// need access to the native `rustpython-parser` AST beyond what the
/// [`zuit_core::SemanticIndex`] exposes.
#[must_use]
pub fn try_python_ast(parsed: &ParsedFile) -> Option<&rustpython_parser::ast::ModModule> {
    parsed.native::<parse::PythonAst>().map(|a| &a.module)
}

/// Registers the Python language frontend and all Python-specific analyzers
/// into `registry`.
///
/// Call this once during application start-up (e.g. in `Registry::builtin()`).
pub fn register(registry: &mut Registry) {
    registry.add_language(Box::new(PythonLanguage));

    // File-level analyzers
    registry.add_analyzer(Box::new(analyzers::eval_sink::EvalSinkAnalyzer));

    // PKG — Packaging & Distribution (project-level)
    registry.add_analyzer(Box::new(
        pkg::pkg001_invalid_pyproject::Pkg001InvalidPyproject,
    ));
    registry.add_analyzer(Box::new(
        pkg::pkg002_metadata_incomplete::Pkg002MetadataIncomplete,
    ));
    registry.add_analyzer(Box::new(
        pkg::pkg003_legacy_build_backend::Pkg003LegacyBuildBackend,
    ));
    registry.add_analyzer(Box::new(
        pkg::pkg004_license_not_declared::Pkg004LicenseNotDeclared,
    ));
    registry.add_analyzer(Box::new(
        pkg::pkg005_python_version_unconstrained::Pkg005PythonVersionUnconstrained,
    ));
    registry.add_analyzer(Box::new(pkg::pkg006_readme_missing::Pkg006ReadmeMissing));
    registry.add_analyzer(Box::new(
        pkg::pkg007_version_mismatch::Pkg007VersionMismatch,
    ));
    registry.add_analyzer(Box::new(
        pkg::pkg008_entry_points_malformed::Pkg008EntryPointsMalformed,
    ));
    registry.add_analyzer(Box::new(
        pkg::pkg009_classifiers_missing::Pkg009ClassifiersMissing,
    ));
    registry.add_analyzer(Box::new(
        pkg::pkg010_dynamic_version_unstable::Pkg010DynamicVersionUnstable,
    ));

    // CHAIN — Supply Chain (project-level)
    registry.add_analyzer(Box::new(chain::chain001_no_lockfile::Chain001NoLockfile));
    registry.add_analyzer(Box::new(
        chain::chain002_typosquat_suspicion::Chain002TyposquatSuspicion::default(),
    ));
    registry.add_analyzer(Box::new(
        chain::chain003_sigstore_bundle_missing::Chain003SigstoreBundleMissing,
    ));
    registry.add_analyzer(Box::new(
        chain::chain004_unpinned_runtime_dep::Chain004UnpinnedRuntimeDep,
    ));

    // External-tool adapters
    registry.add_analyzer(Box::new(external::ruff::RuffAnalyzer));
    registry.add_analyzer(Box::new(external::bandit::BanditAnalyzer));
    registry.add_analyzer(Box::new(external::mypy::MypyAnalyzer));
    registry.add_analyzer(Box::new(external::radon::RadonAnalyzer));

    // PERF — Performance heuristics (file-level + project-level)
    registry.add_analyzer(Box::new(perf::perf001_heavy_import::Perf001HeavyImport));
    registry.add_analyzer(Box::new(perf::perf002_wheel_size::Perf002WheelSize));
    registry.add_analyzer(Box::new(
        perf::perf003_import_side_effect::Perf003ImportSideEffect,
    ));

    // HEALTH — Project Health (project-level)
    registry.add_analyzer(Box::new(
        health::health001_single_author::Health001SingleAuthor::default(),
    ));
    registry.add_analyzer(Box::new(
        health::health002_stale_release::Health002StaleRelease::default(),
    ));
    registry.add_analyzer(Box::new(
        health::health003_low_bus_factor::Health003LowBusFactor::default(),
    ));
    registry.add_analyzer(Box::new(
        health::health004_commit_stale::Health004CommitStale::default(),
    ));
    registry.add_analyzer(Box::new(
        health::health005_changelog_missing::Health005ChangelogMissing,
    ));

    // API — API Stability (project-level, disabled by default until baseline_ref configured)
    registry.add_analyzer(Box::new(
        api::api001_public_symbol_removed::Api001PublicSymbolRemoved::default(),
    ));
    registry.add_analyzer(Box::new(
        api::api002_signature_arity_changed::Api002SignatureArityChanged::default(),
    ));
    registry.add_analyzer(Box::new(
        api::api003_semver_alignment::Api003SemverAlignment::default(),
    ));
}
