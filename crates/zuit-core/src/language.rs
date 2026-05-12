//! The [`Language`] trait, which every language frontend must implement.
//!
//! A `Language` converts a [`SourceFile`] into a [`ParsedFile`] that contains
//! a populated [`crate::index::SemanticIndex`] and a type-erased native AST.

use std::sync::Arc;

use crate::error::ParseError;
use crate::id::LanguageId;
use crate::parsed::ParsedFile;
use crate::source::SourceFile;

/// A language frontend: accepts raw source and produces a [`ParsedFile`].
///
/// Implementors live in the `zuit-lang-*` crates. The core crate never
/// depends on any concrete `Language` implementation; the `Registry` holds
/// them as `Box<dyn Language>`.
pub trait Language: Send + Sync {
    /// Returns the stable identifier for this language (e.g. `LanguageId("rust")`).
    fn id(&self) -> LanguageId;

    /// Returns the file extensions (without the leading `.`) handled by this
    /// frontend (e.g. `&["rs"]` for Rust, `&["py"]` for Python).
    fn extensions(&self) -> &[&'static str];

    /// Parses `source` and returns a fully-populated [`ParsedFile`].
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] on syntax errors, encoding problems, or internal
    /// frontend failures.
    fn parse(&self, source: Arc<SourceFile>) -> Result<ParsedFile, ParseError>;
}

#[cfg(test)]
pub(crate) mod tests {
    use std::any::Any;

    use super::*;
    use crate::index::SemanticIndex;
    use crate::parsed::NativeAst;

    /// A trivial native AST used by [`MockLanguage`].
    pub(crate) struct MockNativeAst;

    impl NativeAst for MockNativeAst {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A do-nothing language frontend for use in engine and registry tests.
    ///
    /// Parses any input successfully and returns an empty `SemanticIndex`.
    pub(crate) struct MockLanguage {
        /// Language identifier returned by this mock.
        pub id: LanguageId,
        /// File extensions claimed by this mock.
        pub exts: &'static [&'static str],
    }

    impl Language for MockLanguage {
        fn id(&self) -> LanguageId {
            self.id
        }

        fn extensions(&self) -> &[&'static str] {
            self.exts
        }

        fn parse(&self, source: Arc<SourceFile>) -> Result<ParsedFile, ParseError> {
            Ok(ParsedFile::new(
                self.id,
                source,
                SemanticIndex::new(),
                Box::new(MockNativeAst),
            ))
        }
    }

    #[test]
    fn mock_language_parses_successfully() {
        let lang = MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        };
        let source = Arc::new(SourceFile::new("test.mock", b"anything".to_vec()));
        let parsed = lang.parse(source).unwrap();
        assert_eq!(parsed.language(), LanguageId("mock"));
    }

    #[test]
    fn mock_language_extension() {
        let lang = MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock", "mck"],
        };
        assert_eq!(lang.extensions(), &["mock", "mck"]);
    }
}
