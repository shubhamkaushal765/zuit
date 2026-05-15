//! Cross-language static analysis rules for zuit.
//!
//! This crate provides the built-in cross-language analyzers:
//!
//! | Rule ID | Analyzer | Dimension |
//! |---|---|---|
//! | `MAINT001-cyclomatic` | [`CyclomaticAnalyzer`] | Maintainability |
//! | `MAINT002-cognitive` | [`CognitiveAnalyzer`] | Maintainability |
//! | `MAINT003-fn-length` | [`FnLengthAnalyzer`] | Maintainability |
//! | `MAINT004-file-length` | [`FileLengthAnalyzer`] | Maintainability |
//! | `MAINT005-deep-nesting` | [`DeepNestingAnalyzer`] | Maintainability |
//! | `MAINT006-too-many-params` | [`TooManyParamsAnalyzer`] | Maintainability |
//! | `MAINT007-return-complexity` | [`ReturnComplexityAnalyzer`] | Maintainability |
//! | `MAINT008-large-impl-block` | [`LargeImplBlockAnalyzer`] | Maintainability |
//! | `MAINT014-commented-out-code` | [`CommentedCodeAnalyzer`] | Maintainability |
//! | `DOC001-public-api-undoc` | [`PublicApiUndocAnalyzer`] | Documentation |
//! | `DOC002-todo-fixme` | [`TodoFixmeAnalyzer`] | Documentation |
//! | `DOC003-empty-doc` | [`EmptyDocAnalyzer`] | Documentation |
//! | `DOC004-stale-doc` | [`StaleDocAnalyzer`] | Documentation |
//! | `SEC001-hardcoded-secret` | [`HardcodedSecretAnalyzer`] | Security |
//! | `SEC003-shell-injection` | [`ShellInjectionAnalyzer`] | Security |
//! | `SEC004-weak-crypto` | [`WeakCryptoAnalyzer`] | Security |
//! | `SEC005-insecure-deser` | [`InsecureDeserAnalyzer`] | Security |
//! | `SEC006-sql-injection` | [`SqlInjectionAnalyzer`] | Security |
//! | `SEC007-path-traversal` | [`PathTraversalAnalyzer`] | Security |
//! | `SEC008-csrf-missing` | [`CsrfMissingAnalyzer`] | Security |
//! | `SEC009-open-redirect` | [`OpenRedirectAnalyzer`] | Security |
//! | `SEC010-ssrf` | [`SsrfAnalyzer`] | Security |
//! | `SEC011-cors-permissive` | [`CorsPermissiveAnalyzer`] | Security |
//! | `DEP001-vulnerable-deps` | [`VulnerableDepsAnalyzer`] | Security |
//! | `CPLX001-fan-out` | [`FanOutAnalyzer`] | Complexity |
//! | `CPLX002-cyclic-deps` | [`CyclicDepsAnalyzer`] | Complexity |
//! | `CPLX003-duplicate-code` | [`DuplicateCodeAnalyzer`] | Complexity |
//! | `TEST001-test-ratio` | [`TestRatioAnalyzer`] | `TestSmell` |
//! | `TEST002-no-asserts` | [`NoAssertsAnalyzer`] | `TestSmell` |
//! | `TEST003-skipped` | [`SkippedAnalyzer`] | `TestSmell` |
//! | `TEST004-flaky-time` | [`FlakyTimeAnalyzer`] | `TestSmell` |
//! | `TEST005-assert-count` | [`AssertCountAnalyzer`] | `TestSmell` |
//! | `TEST006-shared-mutable-state` | [`SharedMutableStateAnalyzer`] | `TestSmell` |
//!
//! All analyzers consume only the [`zuit_core::SemanticIndex`] — they
//! never call [`zuit_core::ParsedFile::native`].  This is the load-bearing
//! rule that keeps adding a new language a one-crate change.
//!
//! [`CyclicDepsAnalyzer`], [`TestRatioAnalyzer`], [`DuplicateCodeAnalyzer`],
//! and [`VulnerableDepsAnalyzer`] are *project-level* — they return `vec![]`
//! from `analyze_file` and do their work inside `analyze_project`, which the
//! engine calls once per run with all parsed files.
//!
//! # Usage
//!
//! Register all built-in analyzers at once:
//!
//! ```rust
//! let mut registry = zuit_core::Registry::new();
//! for analyzer in zuit_analyzers::builtin() {
//!     registry.add_analyzer(analyzer);
//! }
//! ```
#![warn(missing_docs)]

pub mod assert_count;
pub mod cognitive;
pub mod commented_code;
pub mod cors_permissive;
pub mod csrf_missing;
pub mod cyclic_deps;
pub mod cyclomatic;
pub mod deep_nesting;
pub mod duplicate_code;
pub mod empty_doc;
pub mod fan_out;
pub mod file_length;
pub mod flaky_time;
pub mod fn_length;
pub mod hardcoded_secret;
pub mod insecure_deser;
pub mod large_impl_block;
pub mod no_asserts;
pub mod open_redirect;
pub mod path_traversal;
pub mod public_api_undoc;
pub mod return_complexity;
pub mod shared_mutable_state;
pub mod shell_injection;
pub mod skipped;
pub mod sql_injection;
pub mod ssrf;
pub mod stale_doc;
pub mod test_ratio;
pub mod todo_fixme;
pub mod too_many_params;
pub mod vulnerable_deps;
pub mod weak_crypto;

pub use assert_count::AssertCountAnalyzer;
pub use cognitive::CognitiveAnalyzer;
pub use commented_code::CommentedCodeAnalyzer;
pub use cors_permissive::CorsPermissiveAnalyzer;
pub use csrf_missing::CsrfMissingAnalyzer;
pub use cyclic_deps::CyclicDepsAnalyzer;
pub use cyclomatic::CyclomaticAnalyzer;
pub use deep_nesting::DeepNestingAnalyzer;
pub use duplicate_code::DuplicateCodeAnalyzer;
pub use empty_doc::EmptyDocAnalyzer;
pub use fan_out::FanOutAnalyzer;
pub use file_length::FileLengthAnalyzer;
pub use flaky_time::FlakyTimeAnalyzer;
pub use fn_length::FnLengthAnalyzer;
pub use hardcoded_secret::HardcodedSecretAnalyzer;
pub use insecure_deser::InsecureDeserAnalyzer;
pub use large_impl_block::LargeImplBlockAnalyzer;
pub use no_asserts::NoAssertsAnalyzer;
pub use open_redirect::OpenRedirectAnalyzer;
pub use path_traversal::PathTraversalAnalyzer;
pub use public_api_undoc::PublicApiUndocAnalyzer;
pub use return_complexity::ReturnComplexityAnalyzer;
pub use shared_mutable_state::SharedMutableStateAnalyzer;
pub use shell_injection::ShellInjectionAnalyzer;
pub use skipped::SkippedAnalyzer;
pub use sql_injection::SqlInjectionAnalyzer;
pub use ssrf::SsrfAnalyzer;
pub use stale_doc::StaleDocAnalyzer;
pub use test_ratio::TestRatioAnalyzer;
pub use todo_fixme::TodoFixmeAnalyzer;
pub use too_many_params::TooManyParamsAnalyzer;
pub use vulnerable_deps::VulnerableDepsAnalyzer;
pub use weak_crypto::WeakCryptoAnalyzer;

/// Returns all built-in cross-language analyzers in stable order.
///
/// Order is grouped by dimension and stable across releases so that downstream
/// reports (and `zuit list analyzers`) render the same listing every run:
///
/// 1. Maintainability: [`CyclomaticAnalyzer`], [`CognitiveAnalyzer`],
///    [`FnLengthAnalyzer`], [`FileLengthAnalyzer`], [`DeepNestingAnalyzer`],
///    [`TooManyParamsAnalyzer`], [`ReturnComplexityAnalyzer`],
///    [`LargeImplBlockAnalyzer`], [`CommentedCodeAnalyzer`].
/// 2. Documentation: [`PublicApiUndocAnalyzer`], [`TodoFixmeAnalyzer`],
///    [`EmptyDocAnalyzer`], [`StaleDocAnalyzer`].
/// 3. Security: [`HardcodedSecretAnalyzer`], [`ShellInjectionAnalyzer`],
///    [`WeakCryptoAnalyzer`], [`InsecureDeserAnalyzer`], [`SqlInjectionAnalyzer`],
///    [`PathTraversalAnalyzer`], [`CsrfMissingAnalyzer`],
///    [`OpenRedirectAnalyzer`], [`SsrfAnalyzer`], [`CorsPermissiveAnalyzer`],
///    [`VulnerableDepsAnalyzer`].
/// 4. Complexity: [`FanOutAnalyzer`], [`CyclicDepsAnalyzer`],
///    [`DuplicateCodeAnalyzer`].
/// 5. `TestSmell`: [`TestRatioAnalyzer`], [`NoAssertsAnalyzer`],
///    [`SkippedAnalyzer`], [`FlakyTimeAnalyzer`], [`AssertCountAnalyzer`],
///    [`SharedMutableStateAnalyzer`].
#[must_use]
pub fn builtin() -> Vec<Box<dyn zuit_core::Analyzer>> {
    vec![
        Box::new(CyclomaticAnalyzer),
        Box::new(CognitiveAnalyzer),
        Box::new(FnLengthAnalyzer),
        Box::new(FileLengthAnalyzer),
        Box::new(DeepNestingAnalyzer),
        Box::new(TooManyParamsAnalyzer::new()),
        Box::new(ReturnComplexityAnalyzer),
        Box::new(LargeImplBlockAnalyzer),
        Box::new(CommentedCodeAnalyzer),
        Box::new(PublicApiUndocAnalyzer),
        Box::new(TodoFixmeAnalyzer),
        Box::new(EmptyDocAnalyzer),
        Box::new(StaleDocAnalyzer),
        Box::new(HardcodedSecretAnalyzer),
        Box::new(ShellInjectionAnalyzer),
        Box::new(WeakCryptoAnalyzer),
        Box::new(InsecureDeserAnalyzer),
        Box::new(SqlInjectionAnalyzer),
        Box::new(PathTraversalAnalyzer),
        Box::new(CsrfMissingAnalyzer),
        Box::new(OpenRedirectAnalyzer),
        Box::new(SsrfAnalyzer),
        Box::new(CorsPermissiveAnalyzer),
        Box::new(VulnerableDepsAnalyzer),
        Box::new(FanOutAnalyzer),
        Box::new(CyclicDepsAnalyzer),
        Box::new(DuplicateCodeAnalyzer),
        Box::new(TestRatioAnalyzer),
        Box::new(NoAssertsAnalyzer),
        Box::new(SkippedAnalyzer),
        Box::new(FlakyTimeAnalyzer),
        Box::new(AssertCountAnalyzer),
        Box::new(SharedMutableStateAnalyzer),
    ]
}
