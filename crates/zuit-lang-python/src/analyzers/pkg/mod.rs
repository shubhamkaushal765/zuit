//! PKG — Packaging & Distribution rule family.
//!
//! All rules in this family are `AnalyzerKind::ProjectLevel` and use
//! `Dimension::Custom("packaging")`.  They read `pyproject.toml` via the shared
//! `PythonManifest` cache (see `crate::manifest`) so that the file is parsed at
//! most once per project per engine run.

pub mod pkg001_invalid_pyproject;
pub mod pkg002_metadata_incomplete;
pub mod pkg003_legacy_build_backend;
pub mod pkg004_license_not_declared;
pub mod pkg005_python_version_unconstrained;
pub mod pkg006_readme_missing;
pub mod pkg007_version_mismatch;
pub mod pkg008_entry_points_malformed;
pub mod pkg009_classifiers_missing;
pub mod pkg010_dynamic_version_unstable;
