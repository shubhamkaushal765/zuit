//! PKG — Packaging & Distribution rule family for Rust crates.
//!
//! All rules in this family are `AnalyzerKind::ProjectLevel` and use
//! `Dimension::Custom("packaging")`.  They read `Cargo.toml` via the shared
//! `RustManifest` (see `crate::manifest`) cache so that the file is parsed at most
//! once per project per engine run.

pub mod pkg001_invalid_cargo_toml;
pub mod pkg002_license_not_declared;
pub mod pkg003_description_missing;
pub mod pkg004_repository_missing;
pub mod pkg005_rust_version_unconstrained;
pub mod pkg006_readme_missing;
pub mod pkg007_version_mismatch;
pub mod pkg008_keywords_categories_missing;
pub mod pkg009_default_features_bloat;
pub mod pkg010_workspace_inheritance_broken;

pub use pkg001_invalid_cargo_toml::Pkg001InvalidCargoToml;
pub use pkg002_license_not_declared::Pkg002LicenseNotDeclared;
pub use pkg003_description_missing::Pkg003DescriptionMissing;
pub use pkg004_repository_missing::Pkg004RepositoryMissing;
pub use pkg005_rust_version_unconstrained::Pkg005RustVersionUnconstrained;
pub use pkg006_readme_missing::Pkg006ReadmeMissing;
pub use pkg007_version_mismatch::Pkg007VersionMismatch;
pub use pkg008_keywords_categories_missing::Pkg008KeywordsCategoriesMissing;
pub use pkg009_default_features_bloat::Pkg009DefaultFeaturesBloat;
pub use pkg010_workspace_inheritance_broken::Pkg010WorkspaceInheritanceBroken;

use std::path::{Path, PathBuf};

use zuit_core::{
    AnalyzerId, Dimension, Finding, Location, Project, Severity,
    span::{ByteOffset, LineCol, Span},
};

/// Strips the project root from `path`, preferring the canonicalized root.
///
/// `manifest_for` canonicalizes its cache key (resolving symlinks like macOS
/// `/var/folders` → `/private/var/folders`), so paths derived from the manifest
/// may not share `project.root`'s prefix verbatim. This helper tries the
/// canonical root first, then falls back to the as-given root, then to the
/// absolute path.
pub(super) fn relative_to_root(project: &Project, path: &Path) -> PathBuf {
    let canonical_root = project
        .root
        .canonicalize()
        .unwrap_or_else(|_| project.root.clone());
    path.strip_prefix(&canonical_root)
        .or_else(|_| path.strip_prefix(&project.root))
        .unwrap_or(path)
        .to_path_buf()
}

/// Builds a `Finding` anchored to `Cargo.toml` (or a synthetic path when the
/// file is absent), at byte offset 0.
///
/// This mirrors `pyproject_finding` from the Python PKG family.
pub(super) fn cargo_toml_finding(
    project: &Project,
    cargo_toml_path: &Path,
    rule_id: &'static str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let relative = relative_to_root(project, cargo_toml_path);

    Finding {
        analyzer: AnalyzerId::new(rule_id),
        dimension: Dimension::Custom("packaging".to_string()),
        rule_id: rule_id.to_string(),
        severity,
        message,
        location: Location {
            file: relative,
            span: Span::new(ByteOffset(0), ByteOffset(0)),
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion,
        references: vec!["https://doc.rust-lang.org/cargo/reference/manifest.html".to_string()],
        cwe: vec![],
        owasp: vec![],
    }
}
