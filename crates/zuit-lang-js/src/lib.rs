//! JavaScript/TypeScript language frontend for the `zuit` static-analysis
//! workspace, backed by `oxc_parser`.
//!
//! # Native-AST escape hatch
//!
//! `oxc_parser`'s AST is allocated in a bump arena (`oxc_allocator::Allocator`)
//! and every node borrows from it. Storing the AST alongside the arena would
//! require a self-referential type (`self_cell` / `ouroboros`). We side-step
//! this by extracting every piece of information needed by JS-specific analyzers
//! into a `JsAst` value (see `native_ast.rs`) during [`Language::parse`] —
//! before the arena is dropped. The result is a plain, heap-allocated struct
//! that is `Send + Sync` without any `unsafe` code. Language-specific
//! analyzers access it via the crate-internal `try_js_ast` helper.
//!
//! # File extensions
//!
//! Registered for `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts`, `.tsx`.
//! `oxc_span::SourceType::from_path` auto-selects the appropriate parser
//! flags (TypeScript, JSX, module-vs-script).
#![warn(missing_docs)]

pub mod analyzers;
mod complexity;
pub mod error;
mod index;
pub mod manifest;
pub(crate) mod native_ast;
mod parse;

use std::sync::Arc;

use zuit_core::{Language, LanguageId, ParseError, ParsedFile, Registry, SourceFile};

use native_ast::JsAst;

/// The JavaScript / TypeScript language frontend.
///
/// Registered file extensions: `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`,
/// `.cts`, `.tsx`. Source-type detection is delegated to
/// [`oxc_span::SourceType::from_path`].
pub struct JsLanguage;

impl Language for JsLanguage {
    fn id(&self) -> LanguageId {
        LanguageId("javascript")
    }

    fn extensions(&self) -> &[&'static str] {
        &["js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx"]
    }

    fn parse(&self, source: Arc<SourceFile>) -> Result<ParsedFile, ParseError> {
        parse::parse(source)
    }
}

/// Returns a reference to the pre-extracted [`JsAst`] data from a
/// [`ParsedFile`] that was produced by [`JsLanguage`].
///
/// Returns `None` if `parsed` was not produced by the JS/TS frontend.
///
/// This is the typed escape hatch for language-specific analyzers in this crate.
/// Cross-language analyzers cannot call this because [`JsAst`] is `pub(crate)`.
#[must_use]
pub(crate) fn try_js_ast(parsed: &ParsedFile) -> Option<&JsAst> {
    parsed.native::<JsAst>()
}

/// Registers the JS/TS language frontend and all JS/TS-specific analyzers
/// into `registry`.
///
/// Analyzers registered:
/// - [`analyzers::eval_sink::JsEvalSinkAnalyzer`] (`SEC002-eval-sink`)
/// - [`analyzers::pkg::Pkg001InstallScriptAnalyzer`] (`PKG001-install-script-present`)
/// - [`analyzers::pkg::Pkg002MissingTypesAnalyzer`] (`PKG002-missing-types`)
/// - [`analyzers::pkg::Pkg003DualPackageHazardAnalyzer`] (`PKG003-dual-package-hazard`)
/// - [`analyzers::pkg::Pkg004UnpinnedDepsAnalyzer`] (`PKG004-unpinned-deps`)
/// - [`analyzers::pkg::Pkg005EnginesMissingAnalyzer`] (`PKG005-engines-missing`)
/// - [`analyzers::external::eslint::EslintAnalyzer`] (`JS/eslint-*`)
/// - [`analyzers::external::tsc::TscAnalyzer`] (`JS/tsc-*`)
/// - [`analyzers::health::Health001SingleAuthorAnalyzer`] (`HEALTH001-single-author`)
/// - [`analyzers::health::Health002StaleReleaseAnalyzer`] (`HEALTH002-stale-release`)
/// - [`analyzers::health::Health003LowBusFactorAnalyzer`] (`HEALTH003-low-bus-factor`)
/// - [`analyzers::health::Health004CommitStaleAnalyzer`] (`HEALTH004-commit-stale`)
/// - [`analyzers::health::Health005ChangelogMissingAnalyzer`] (`HEALTH005-changelog-missing`)
/// - [`analyzers::chain::Chain001NoLockfileAnalyzer`] (`CHAIN001-no-lockfile`)
/// - [`analyzers::chain::Chain002TyposquatSuspicionAnalyzer`] (`CHAIN002-typosquat-suspicion`)
/// - [`analyzers::chain::Chain003ProvenanceBundleMissingAnalyzer`] (`CHAIN003-provenance-bundle-missing`)
/// - [`analyzers::chain::Chain004UnmaintainedTransitiveAnalyzer`] (`CHAIN004-unmaintained-transitive`)
/// - [`analyzers::perf::Perf001BundleSizeAnalyzer`] (`PERF001-bundle-size`)
/// - [`analyzers::perf::Perf002HeavyImportAnalyzer`] (`PERF002-heavy-import`)
/// - [`analyzers::perf::Perf003ImportSideEffectAnalyzer`] (`PERF003-import-side-effect`)
/// - [`analyzers::external::npm_audit::NpmAuditAnalyzer`] (`JS/npm-audit-*`)
/// - [`analyzers::external::dependency_cruiser::DependencyCruiserAnalyzer`] (`JS/dependency-cruiser-*`)
pub fn register(registry: &mut Registry) {
    registry.add_language(Box::new(JsLanguage));
    registry.add_analyzer(Box::new(analyzers::eval_sink::JsEvalSinkAnalyzer));
    registry.add_analyzer(Box::new(analyzers::empty_block::JsEmptyBlockAnalyzer));
    registry.add_analyzer(Box::new(
        analyzers::active_debug_code::JsActiveDebugCodeAnalyzer,
    ));
    registry.add_analyzer(Box::new(
        analyzers::bind_all_interfaces::JsBindAllInterfacesAnalyzer,
    ));
    registry.add_analyzer(Box::new(
        analyzers::hardcoded_security_constant::JsHardcodedSecurityConstantAnalyzer,
    ));
    registry.add_analyzer(Box::new(analyzers::log_injection::JsLogInjectionAnalyzer));
    registry.add_analyzer(Box::new(
        analyzers::missing_default_case::JsMissingDefaultCaseAnalyzer,
    ));
    registry.add_analyzer(Box::new(
        analyzers::infinite_loop_no_exit::JsInfiniteLoopNoExitAnalyzer,
    ));
    registry.add_analyzer(Box::new(analyzers::dead_store::JsDeadStoreAnalyzer));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg001InstallScriptAnalyzer));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg002MissingTypesAnalyzer));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg003DualPackageHazardAnalyzer));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg004UnpinnedDepsAnalyzer));
    registry.add_analyzer(Box::new(analyzers::pkg::Pkg005EnginesMissingAnalyzer));
    registry.add_analyzer(Box::new(analyzers::external::eslint::EslintAnalyzer));
    registry.add_analyzer(Box::new(analyzers::external::tsc::TscAnalyzer));
    registry.add_analyzer(Box::new(analyzers::health::Health001SingleAuthorAnalyzer));
    registry.add_analyzer(Box::new(analyzers::health::Health002StaleReleaseAnalyzer));
    registry.add_analyzer(Box::new(analyzers::health::Health003LowBusFactorAnalyzer));
    registry.add_analyzer(Box::new(analyzers::health::Health004CommitStaleAnalyzer));
    registry.add_analyzer(Box::new(
        analyzers::health::Health005ChangelogMissingAnalyzer,
    ));
    registry.add_analyzer(Box::new(analyzers::chain::Chain001NoLockfileAnalyzer));
    registry.add_analyzer(Box::new(
        analyzers::chain::Chain002TyposquatSuspicionAnalyzer,
    ));
    registry.add_analyzer(Box::new(
        analyzers::chain::Chain003ProvenanceBundleMissingAnalyzer,
    ));
    registry.add_analyzer(Box::new(
        analyzers::chain::Chain004UnmaintainedTransitiveAnalyzer,
    ));
    registry.add_analyzer(Box::new(analyzers::perf::Perf001BundleSizeAnalyzer));
    registry.add_analyzer(Box::new(analyzers::perf::Perf002HeavyImportAnalyzer));
    registry.add_analyzer(Box::new(analyzers::perf::Perf003ImportSideEffectAnalyzer));
    registry.add_analyzer(Box::new(analyzers::external::npm_audit::NpmAuditAnalyzer));
    registry.add_analyzer(Box::new(
        analyzers::external::dependency_cruiser::DependencyCruiserAnalyzer,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source(path: &str, code: &str) -> Arc<SourceFile> {
        Arc::new(SourceFile::new(path, code.as_bytes().to_vec()))
    }

    #[test]
    fn js_language_id() {
        assert_eq!(JsLanguage.id(), LanguageId("javascript"));
    }

    #[test]
    fn js_language_extensions_cover_ts_and_js() {
        let exts = JsLanguage.extensions();
        for needed in ["js", "ts", "jsx", "tsx", "mjs", "cjs", "mts", "cts"] {
            assert!(exts.contains(&needed), "missing extension {needed}");
        }
    }

    #[test]
    fn parse_valid_js() {
        let result = JsLanguage.parse(make_source("a.js", "function f() { return 1; }"));
        assert!(result.is_ok());
    }

    #[test]
    fn parse_valid_ts() {
        let result = JsLanguage.parse(make_source(
            "a.ts",
            "export function f(x: number): number { return x; }",
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn register_adds_one_language() {
        let mut registry = Registry::new();
        register(&mut registry);
        assert_eq!(registry.language_count(), 1);
    }

    #[test]
    fn register_adds_analyzer() {
        let mut registry = Registry::new();
        register(&mut registry);
        assert_eq!(registry.analyzer_count(), 30);
    }

    #[test]
    fn try_js_ast_returns_some_for_js_parsed() {
        let source = make_source("a.js", "const x = 1;");
        let parsed = JsLanguage.parse(source).expect("parse failed");
        assert!(try_js_ast(&parsed).is_some());
    }
}
