//! Package-metadata analyzers (`PKG` family).
//!
//! All rules in this module operate at `AnalyzerKind::ProjectLevel` and
//! consume `package.json` via the [`crate::manifest`] cache. They emit
//! findings against `package.json` at the project root using a zero-width
//! span at line 1, column 1 (JSON has no native comment syntax for inline
//! suppression).

mod pkg001_install_script_present;
mod pkg002_missing_types;
mod pkg003_dual_package_hazard;
mod pkg004_unpinned_deps;
mod pkg005_engines_missing;

pub use pkg001_install_script_present::Pkg001InstallScriptAnalyzer;
pub use pkg002_missing_types::Pkg002MissingTypesAnalyzer;
pub use pkg003_dual_package_hazard::Pkg003DualPackageHazardAnalyzer;
pub use pkg004_unpinned_deps::Pkg004UnpinnedDepsAnalyzer;
pub use pkg005_engines_missing::Pkg005EnginesMissingAnalyzer;
