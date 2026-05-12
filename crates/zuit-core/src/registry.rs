//! [`Registry`]: the collection of registered [`Language`] frontends and
//! [`Analyzer`] implementations available to the [`crate::engine::Engine`].
//!
//! `Registry::new()` creates an empty registry.  The CLI crate populates a
//! `builtin` registry by calling `add_language` and `add_analyzer` for each
//! crate it depends on.  (Note: `Registry::builtin()` is intentionally absent
//! from this crate — see the "Spec deviations" section of the implementation
//! plan for the rationale.)

use crate::analyzer::Analyzer;
use crate::id::LanguageId;
use crate::language::Language;

/// Holds all registered language frontends and analyzers.
///
/// The engine queries the registry to determine which language to use for a
/// given file extension, and which analyzers to run against each language.
pub struct Registry {
    languages: Vec<Box<dyn Language>>,
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl Registry {
    /// Creates an empty registry with no registered languages or analyzers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            languages: Vec::new(),
            analyzers: Vec::new(),
        }
    }

    /// Registers a language frontend.
    ///
    /// If a language with the same [`LanguageId`] is already registered, the
    /// new one is appended and will shadow the old one in
    /// [`language_for_extension`](Self::language_for_extension) lookups.
    pub fn add_language(&mut self, lang: Box<dyn Language>) {
        self.languages.push(lang);
    }

    /// Registers an analyzer.
    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        self.analyzers.push(analyzer);
    }

    /// Returns a reference to the language frontend that claims the given file
    /// extension, or `None` if no registered language handles it.
    ///
    /// When multiple languages claim the same extension, the **last-registered**
    /// one wins, allowing downstream code to override built-in frontends.
    #[must_use]
    pub fn language_for_extension(&self, ext: &str) -> Option<&dyn Language> {
        self.languages
            .iter()
            .rev()
            .find(|lang| lang.extensions().contains(&ext))
            .map(std::convert::AsRef::as_ref)
    }

    /// Returns an iterator over all registered language frontends.
    pub fn languages(&self) -> impl Iterator<Item = &dyn Language> {
        self.languages.iter().map(std::convert::AsRef::as_ref)
    }

    /// Returns an iterator over all registered analyzers.
    pub fn analyzers(&self) -> impl Iterator<Item = &dyn Analyzer> {
        self.analyzers.iter().map(std::convert::AsRef::as_ref)
    }

    /// Returns the total number of registered languages.
    #[must_use]
    pub fn language_count(&self) -> usize {
        self.languages.len()
    }

    /// Returns the total number of registered analyzers.
    #[must_use]
    pub fn analyzer_count(&self) -> usize {
        self.analyzers.len()
    }

    /// Returns the [`LanguageId`]s of all registered languages.
    #[must_use]
    pub fn language_ids(&self) -> Vec<LanguageId> {
        self.languages.iter().map(|l| l.id()).collect()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("language_count", &self.languages.len())
            .field("analyzer_count", &self.analyzers.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::LanguageId;
    use crate::language::tests::MockLanguage;

    fn make_lang(id: &'static str, exts: &'static [&'static str]) -> Box<dyn Language> {
        Box::new(MockLanguage {
            id: LanguageId(id),
            exts,
        })
    }

    #[test]
    fn empty_registry_has_no_languages() {
        let r = Registry::new();
        assert_eq!(r.language_count(), 0);
        assert_eq!(r.analyzer_count(), 0);
    }

    #[test]
    fn add_language_increments_count() {
        let mut r = Registry::new();
        r.add_language(make_lang("rust", &["rs"]));
        assert_eq!(r.language_count(), 1);
    }

    #[test]
    fn language_for_extension_found() {
        let mut r = Registry::new();
        r.add_language(make_lang("rust", &["rs"]));
        let lang = r.language_for_extension("rs").unwrap();
        assert_eq!(lang.id(), LanguageId("rust"));
    }

    #[test]
    fn language_for_extension_not_found() {
        let r = Registry::new();
        assert!(r.language_for_extension("rs").is_none());
    }

    #[test]
    fn last_registered_wins_on_extension_clash() {
        let mut r = Registry::new();
        r.add_language(make_lang("first", &["ts"]));
        r.add_language(make_lang("second", &["ts"]));
        let lang = r.language_for_extension("ts").unwrap();
        assert_eq!(lang.id(), LanguageId("second"));
    }

    #[test]
    fn language_ids_returns_all() {
        let mut r = Registry::new();
        r.add_language(make_lang("rust", &["rs"]));
        r.add_language(make_lang("python", &["py"]));
        let ids = r.language_ids();
        assert!(ids.contains(&LanguageId("rust")));
        assert!(ids.contains(&LanguageId("python")));
    }

    #[test]
    fn default_creates_empty_registry() {
        let r = Registry::default();
        assert_eq!(r.language_count(), 0);
    }
}
