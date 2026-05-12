//! Supply-chain analyzers (`CHAIN` family).
//!
//! All rules in this module operate at `AnalyzerKind::ProjectLevel` with
//! `SupportedLanguages::All`.  They read `package.json`, `package-lock.json`,
//! and the project filesystem — no subprocess or network call is ever made.
//!
//! | Rule ID | Signal source | Severity |
//! |---|---|---|
//! | `CHAIN001-no-lockfile` | `has_any_lockfile` flag on [`crate::manifest::JsManifest`] | Medium |
//! | `CHAIN002-typosquat-suspicion` | Damerau-Levenshtein against [`typosquat::TOP_NPM_NAMES`] | High |
//! | `CHAIN003-provenance-bundle-missing` | `dist/` presence + absence of `.sigstore` | Low |
//! | `CHAIN004-unmaintained-transitive` | `package-lock.json` v3 `packages[*].time` field | Medium |

pub mod typosquat;

mod chain001_no_lockfile;
mod chain002_typosquat_suspicion;
mod chain003_provenance_bundle_missing;
mod chain004_unmaintained_transitive;

pub use chain001_no_lockfile::Chain001NoLockfileAnalyzer;
pub use chain002_typosquat_suspicion::Chain002TyposquatSuspicionAnalyzer;
pub use chain003_provenance_bundle_missing::Chain003ProvenanceBundleMissingAnalyzer;
pub use chain004_unmaintained_transitive::Chain004UnmaintainedTransitiveAnalyzer;
