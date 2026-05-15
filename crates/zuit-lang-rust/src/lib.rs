//! Rust language frontend for the `zuit` static analysis workspace.
//!
//! This crate wires together:
//! - [`RustLanguage`]: a [`zuit_core::Language`] implementation that parses
//!   Rust source files with `syn` and populates a [`zuit_core::SemanticIndex`].
//! - [`analyzers::unsafe_block::UnsafeBlockAnalyzer`]: the `SEC101-rust-unsafe`
//!   language-specific analyzer.
//!
//! # Usage
//!
//! Register both the language frontend and the analyzer in one call:
//!
//! ```rust
//! let mut registry = zuit_core::Registry::new();
//! zuit_lang_rust::register(&mut registry);
//! ```
//!
//! # Native-AST escape hatch
//!
//! Language-specific analyzers in this crate access the pre-extracted AST data
//! via `try_rust_ast`, which performs the typed downcast from the type-erased
//! [`zuit_core::ParsedFile::native`].
#![warn(missing_docs)]

pub mod analyzers;
mod complexity;
pub mod error;
mod index;
pub(crate) mod manifest;
mod parse;
mod span_util;

pub use error::RustError;

use std::sync::Arc;

use zuit_core::{Language, LanguageId, ParseError, ParsedFile, Registry, SourceFile};

use parse::RustAst;

/// The Rust language frontend backed by `syn`.
///
/// Registered file extensions: `.rs`.
pub struct RustLanguage;

impl Language for RustLanguage {
    fn id(&self) -> LanguageId {
        LanguageId("rust")
    }

    fn extensions(&self) -> &[&'static str] {
        &["rs"]
    }

    fn parse(&self, source: Arc<SourceFile>) -> Result<ParsedFile, ParseError> {
        parse::parse(source)
    }
}

/// Registers [`RustLanguage`] and all language-specific analyzers into the
/// given [`Registry`].
///
/// Registered analyzers:
/// - `SEC101-rust-unsafe` — unsafe construct inventory
/// - `SOUND001`–`SOUND006` — unsafe soundness sub-rules
/// - `PKG001`–`PKG010` — Cargo.toml metadata rules
/// - `HEALTH001`–`HEALTH005` — project health rules
/// - `CHAIN001`–`CHAIN004` — supply chain rules
/// - `PERF001`–`PERF003` — performance heuristics
/// - `ECO001`–`ECO004` — ecosystem compatibility rules
/// - `CI001`–`CI005` — CI/CD & release hygiene rules
/// - `CargoAuditAnalyzer` — `cargo audit` external-tool adapter
/// - `CargoClippyAnalyzer` — `cargo clippy` external-tool adapter
/// - `CargoGeigerAnalyzer` — `cargo geiger` external-tool adapter
/// - `CargoDenyAnalyzer` — `cargo deny` external-tool adapter
///
/// Call this once when building the registry before handing it to the engine.
pub fn register(registry: &mut Registry) {
    registry.add_language(Box::new(RustLanguage));

    // SEC family
    registry.add_analyzer(Box::new(analyzers::unsafe_block::UnsafeBlockAnalyzer));

    // MAINT family
    registry.add_analyzer(Box::new(analyzers::empty_block::EmptyBlockAnalyzer));
    registry.add_analyzer(Box::new(
        analyzers::active_debug_code::ActiveDebugCodeAnalyzer,
    ));

    // SOUND family
    registry.add_analyzer(Box::new(
        analyzers::sound::Sound001UnsafeBlockMissingSafetyComment,
    ));
    registry.add_analyzer(Box::new(analyzers::sound::Sound002UnsafeInPubApiSignature));
    registry.add_analyzer(Box::new(analyzers::sound::Sound003TransmuteUsage));
    registry.add_analyzer(Box::new(analyzers::sound::Sound004RawPointerInPubApi));
    registry.add_analyzer(Box::new(analyzers::sound::Sound005UnsafeAndParsingCombo));
    registry.add_analyzer(Box::new(analyzers::sound::Sound006FfiWithoutSafetyDoc));

    // PKG family
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg001InvalidCargoToml));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg002LicenseNotDeclared));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg003DescriptionMissing));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg004RepositoryMissing));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg005RustVersionUnconstrained));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg006ReadmeMissing));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg007VersionMismatch));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg008KeywordsCategoriesMissing));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg009DefaultFeaturesBloat));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg010WorkspaceInheritanceBroken));

    // HEALTH family
    registry.add_analyzer(Box::new(analyzers::health::Health001SingleAuthor::default()));
    registry.add_analyzer(Box::new(analyzers::health::Health002StaleRelease::default()));
    registry.add_analyzer(Box::new(analyzers::health::Health003LowBusFactor::default()));
    registry.add_analyzer(Box::new(analyzers::health::Health004CommitStale::default()));
    registry.add_analyzer(Box::new(analyzers::health::Health005ChangelogMissing));

    // CHAIN family
    registry.add_analyzer(Box::new(analyzers::chain::Chain001NoLockfile));
    registry.add_analyzer(Box::new(
        analyzers::chain::Chain002TyposquatSuspicion::default(),
    ));
    registry.add_analyzer(Box::new(analyzers::chain::Chain003GitDependencyWithoutRev));
    registry.add_analyzer(Box::new(
        analyzers::chain::Chain004PathDependencyInPublishedCrate,
    ));

    // PERF family
    registry.add_analyzer(Box::new(analyzers::perf::Perf001HeavyDefaultFeatures));
    registry.add_analyzer(Box::new(analyzers::perf::Perf002CloneInIterChain));
    registry.add_analyzer(Box::new(analyzers::perf::Perf003ArcMutexDensity));

    // ECO family
    registry.add_analyzer(Box::new(analyzers::eco::Eco001NoNoStdFeature));
    registry.add_analyzer(Box::new(analyzers::eco::Eco002AsyncRuntimeCoupling));
    registry.add_analyzer(Box::new(analyzers::eco::Eco003SendSyncViolations));
    registry.add_analyzer(Box::new(analyzers::eco::Eco004FeatureGraphFragmented));

    // CI family
    registry.add_analyzer(Box::new(analyzers::ci::Ci001NoCiConfig));
    registry.add_analyzer(Box::new(analyzers::ci::Ci002NoMsrvTestJob));
    registry.add_analyzer(Box::new(analyzers::ci::Ci003NoWindowsJob));
    registry.add_analyzer(Box::new(analyzers::ci::Ci004NoCargoDenyJob));
    registry.add_analyzer(Box::new(analyzers::ci::Ci005NoDependabot));

    // External tool family
    registry.add_analyzer(Box::new(
        analyzers::external::cargo_audit::CargoAuditAnalyzer,
    ));
    registry.add_analyzer(Box::new(
        analyzers::external::cargo_clippy::CargoClippyAnalyzer,
    ));
    registry.add_analyzer(Box::new(
        analyzers::external::cargo_geiger::CargoGeigerAnalyzer,
    ));
    registry.add_analyzer(Box::new(analyzers::external::cargo_deny::CargoDenyAnalyzer));
}

/// Returns a reference to the pre-extracted [`RustAst`] data from a
/// [`ParsedFile`] that was produced by [`RustLanguage`].
///
/// Returns `None` if `parsed` was not produced by the Rust frontend.
///
/// This is the typed escape hatch for language-specific analyzers in this crate.
/// Cross-language analyzers cannot call this because `RustAst` is `pub(crate)`.
#[must_use]
pub(crate) fn try_rust_ast(parsed: &ParsedFile) -> Option<&RustAst> {
    parsed.native::<RustAst>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::LanguageId;

    fn make_source(code: &str) -> Arc<SourceFile> {
        Arc::new(SourceFile::new("test.rs", code.as_bytes().to_vec()))
    }

    #[test]
    fn rust_language_id() {
        assert_eq!(RustLanguage.id(), LanguageId("rust"));
    }

    #[test]
    fn rust_language_extensions() {
        assert!(RustLanguage.extensions().contains(&"rs"));
    }

    #[test]
    fn parse_valid_source() {
        let src = make_source("fn main() {}");
        let result = RustLanguage.parse(src);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_invalid_returns_syntax_error() {
        let src = make_source("fn x(");
        let result = RustLanguage.parse(src);
        assert!(matches!(result, Err(zuit_core::ParseError::Syntax { .. })));
    }

    #[test]
    fn try_rust_ast_returns_some_for_rust_parsed() {
        let src = make_source("fn greet() {}");
        let parsed = RustLanguage.parse(src).unwrap();
        let ast = try_rust_ast(&parsed);
        assert!(ast.is_some());
    }

    #[test]
    fn register_adds_language_and_analyzer() {
        let mut registry = Registry::new();
        register(&mut registry);
        assert_eq!(registry.language_count(), 1);
        // 1 (SEC101) + 1 (MAINT013) + 6 SOUND + 10 PKG + 5 HEALTH + 4 CHAIN
        // + 3 PERF + 4 ECO + 5 CI + 4 external = 43 total.
        assert_eq!(registry.analyzer_count(), 44);
    }
}
