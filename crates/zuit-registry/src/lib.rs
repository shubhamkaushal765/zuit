//! Built-in [`Registry`] constructor shared between `zuit-cli` and `zuit-lsp`.
//!
//! **Spec note:** `ARCH_SPEC` §5.8 shows `Registry::builtin()` living in
//! `zuit-core`.  In practice, placing it there would force `zuit-core` to
//! depend on every language and analyzer crate, breaking the two-axis extensibility
//! invariant.  Instead, `build_registry` lives here — this crate is the only one
//! that is *allowed* to depend on all language and analyzer crates, and both the
//! CLI binary and the LSP server depend on this crate rather than duplicating the
//! wiring.
//!
//! To add a new language or analyzer: add the crate as a dependency of
//! `zuit-registry` and extend [`build_registry`].
#![warn(missing_docs)]

use zuit_core::Registry;

/// Creates a fully-populated [`Registry`] containing all built-in language
/// frontends and cross-language analyzers.
///
/// Language frontends registered:
/// - Rust (`zuit_lang_rust`)
/// - Python (`zuit_lang_python`)
/// - JavaScript / TypeScript (`zuit_lang_js`) — covers `.js`, `.mjs`,
///   `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts`, `.tsx`.
///
/// Analyzers registered (via language `register` helpers):
/// - `SEC101-rust-unsafe` (Rust-only, via `zuit_lang_rust::register`)
/// - `SEC002-eval-sink` (Python, via `zuit_lang_python::register`)
/// - `SEC002-eval-sink` (JS/TS, via `zuit_lang_js::register`)
///
/// Cross-language analyzers from `zuit_analyzers::builtin()`
/// (26 rules covering all five v1 dimensions):
/// - Maintainability: `MAINT001-cyclomatic`, `MAINT002-cognitive`,
///   `MAINT003-fn-length`, `MAINT004-file-length`, `MAINT005-deep-nesting`,
///   `MAINT006-too-many-params`, `MAINT007-return-complexity`,
///   `MAINT008-large-impl-block`
/// - Documentation: `DOC001-public-api-undoc`, `DOC002-todo-fixme`,
///   `DOC003-empty-doc`
/// - Security: `SEC001-hardcoded-secret`, `SEC003-shell-injection`,
///   `SEC004-weak-crypto`, `SEC005-insecure-deser`, `SEC006-sql-injection`,
///   `SEC007-path-traversal`, `DEP001-vulnerable-deps` (project-level)
/// - Complexity: `CPLX001-fan-out`, `CPLX002-cyclic-deps` (project-level),
///   `CPLX003-duplicate-code` (project-level)
/// - `TestSmell`: `TEST001-test-ratio` (project-level), `TEST002-no-asserts`,
///   `TEST003-skipped`, `TEST004-flaky-time`, `TEST005-assert-count`
#[must_use]
pub fn build_registry() -> Registry {
    #[allow(unused_mut)]
    let mut registry = Registry::new();

    // Register language frontends and their language-specific analyzers.
    #[cfg(feature = "lang-rust")]
    zuit_lang_rust::register(&mut registry);
    #[cfg(feature = "lang-python")]
    zuit_lang_python::register(&mut registry);
    #[cfg(feature = "lang-js")]
    zuit_lang_js::register(&mut registry);
    // Register all cross-language analyzers.
    #[cfg(feature = "rules-v1")]
    for analyzer in zuit_analyzers::builtin() {
        registry.add_analyzer(analyzer);
    }

    // Register user-installed plugins discovered from the plugins directory.
    #[cfg(feature = "plugins")]
    for analyzer in zuit_plugins::discover_user_plugins() {
        registry.add_analyzer(analyzer);
    }

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Under default features all three language frontends must be present.
    #[cfg(all(
        feature = "lang-rust",
        feature = "lang-python",
        feature = "lang-js",
        feature = "rules-v1"
    ))]
    #[test]
    fn default_features_register_all_languages() {
        let registry = build_registry();
        assert_eq!(
            registry.language_count(),
            3,
            "expected 3 language frontends (rust, python, js)"
        );
        assert!(
            registry.analyzer_count() > 0,
            "expected at least one analyzer under default features"
        );
    }

    /// When no language or rules features are enabled the registry must be empty.
    #[cfg(all(
        not(feature = "lang-rust"),
        not(feature = "lang-python"),
        not(feature = "lang-js"),
        not(feature = "rules-v1")
    ))]
    #[test]
    fn empty_registry_when_no_features() {
        let registry = build_registry();
        assert_eq!(
            registry.language_count(),
            0,
            "expected 0 language frontends when no features are enabled"
        );
        assert_eq!(
            registry.analyzer_count(),
            0,
            "expected 0 analyzers when no features are enabled"
        );
    }

    /// When only the `lang-rust` feature is enabled exactly one language is registered.
    #[cfg(all(
        feature = "lang-rust",
        not(feature = "lang-python"),
        not(feature = "lang-js")
    ))]
    #[test]
    fn only_rust_when_only_rust_feature() {
        let registry = build_registry();
        assert_eq!(
            registry.language_count(),
            1,
            "expected exactly 1 language frontend when only lang-rust is enabled"
        );
    }

    /// When the `plugins` feature is enabled, user-installed plugins are discovered
    /// and added to the registry.
    #[cfg(all(feature = "plugins", feature = "lang-rust", feature = "rules-v1"))]
    #[test]
    fn build_registry_includes_user_plugins() {
        use std::path::PathBuf;

        let tempdir = tempfile::tempdir().unwrap();
        let plugins_dir = tempdir.path();

        // Path to the echo-plugin fixture shipped with zuit-plugins crate.
        let fixture = {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.pop(); // up from zuit-registry
            p.push("zuit-plugins/tests/fixtures/echo-plugin");
            p
        };

        // Install the fixture plugin into the temporary plugins directory.
        let _installed = zuit_plugins::install_local_in(plugins_dir, &fixture, None)
            .expect("install fixture plugin");

        // Build a registry using the temporary plugins directory.
        let mut registry = zuit_core::Registry::new();

        // Re-do language + rules registration as in build_registry.
        #[cfg(feature = "lang-rust")]
        zuit_lang_rust::register(&mut registry);
        #[cfg(feature = "rules-v1")]
        for analyzer in zuit_analyzers::builtin() {
            registry.add_analyzer(analyzer);
        }

        // Discover and add plugins from the temporary directory.
        for analyzer in zuit_plugins::discover_user_plugins_in(plugins_dir) {
            registry.add_analyzer(analyzer);
        }

        // Assert that at least one analyzer with id starting 'plugin/' was registered.
        assert!(
            registry
                .analyzers()
                .any(|a| a.id().0.starts_with("plugin/")),
            "expected at least one analyzer with id starting 'plugin/'"
        );
    }
}
