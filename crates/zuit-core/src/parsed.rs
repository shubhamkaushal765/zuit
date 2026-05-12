//! [`ParsedFile`]: the output of a language frontend parse, holding the
//! native AST behind a type-erased boundary.
//!
//! The [`NativeAst`] trait lets language-specific analyzers downcast to their
//! concrete AST type while keeping cross-language analyzers completely isolated
//! from any language crate (enforced by the dependency graph, not visibility
//! modifiers).

use std::any::Any;
use std::sync::Arc;

use crate::id::LanguageId;
use crate::index::SemanticIndex;
use crate::source::SourceFile;

/// Marker trait for native AST types produced by language frontends.
///
/// Implementors must be `Any + Send + Sync + 'static` so that:
/// - `Any` enables the typed downcast via [`ParsedFile::native`].
/// - `Send + Sync` lets [`ParsedFile`] values be passed across `rayon` worker
///   threads without additional synchronisation.
pub trait NativeAst: Any + Send + Sync + 'static {
    /// Returns `self` as `&dyn Any`, enabling the downcast in
    /// [`ParsedFile::native`].
    fn as_any(&self) -> &dyn Any;
}

/// The output of a successful parse by a [`crate::language::Language`] frontend.
///
/// Holds the source file, the pre-populated [`SemanticIndex`], and the native
/// AST behind a type-erased [`NativeAst`] interface.  Cross-language analyzers
/// only call [`ParsedFile::index`]; language-specific analyzers additionally
/// call [`ParsedFile::native`] to access language-specific nodes.
pub struct ParsedFile {
    language: LanguageId,
    source: Arc<SourceFile>,
    /// Populated by the frontend at parse time; consumed by analyzers.
    pub(crate) index: SemanticIndex,
    native: Box<dyn NativeAst>,
}

impl ParsedFile {
    /// Creates a `ParsedFile` from its components.
    ///
    /// Callers are language frontends; nothing else should construct this type
    /// directly.
    #[must_use]
    pub fn new(
        language: LanguageId,
        source: Arc<SourceFile>,
        index: SemanticIndex,
        native: Box<dyn NativeAst>,
    ) -> Self {
        Self {
            language,
            source,
            index,
            native,
        }
    }

    /// Returns the identifier of the language that parsed this file.
    #[must_use]
    pub fn language(&self) -> LanguageId {
        self.language
    }

    /// Returns a reference to the underlying source file.
    #[must_use]
    pub fn source(&self) -> &SourceFile {
        &self.source
    }

    /// Returns a reference to the pre-populated [`SemanticIndex`].
    #[must_use]
    pub fn index(&self) -> &SemanticIndex {
        &self.index
    }

    /// Attempts to downcast the native AST to a concrete type `T`.
    ///
    /// Returns `Some(&T)` when the stored AST is of type `T`, or `None`
    /// when it is not (e.g. when a cross-language analyzer accidentally calls
    /// this — the concrete type is simply not in scope so the downcast never
    /// succeeds).
    #[must_use]
    pub fn native<T: NativeAst>(&self) -> Option<&T> {
        self.native.as_any().downcast_ref::<T>()
    }
}

impl std::fmt::Debug for ParsedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedFile")
            .field("language", &self.language)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::LanguageId;
    use crate::index::SemanticIndex;
    use crate::source::SourceFile;

    /// A minimal concrete AST used only in tests.
    struct FakeAst {
        pub tag: u32,
    }

    impl NativeAst for FakeAst {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A second, distinct AST type to verify that wrong-type downcast returns `None`.
    struct OtherAst;

    impl NativeAst for OtherAst {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    fn make_parsed(tag: u32) -> ParsedFile {
        let source = Arc::new(SourceFile::new("test.rs", b"fn main() {}".to_vec()));
        ParsedFile::new(
            LanguageId("rust"),
            source,
            SemanticIndex::new(),
            Box::new(FakeAst { tag }),
        )
    }

    #[test]
    fn native_roundtrip_correct_type() {
        let pf = make_parsed(42);
        let ast = pf.native::<FakeAst>().unwrap();
        assert_eq!(ast.tag, 42);
    }

    #[test]
    fn native_returns_none_for_wrong_type() {
        let pf = make_parsed(1);
        assert!(pf.native::<OtherAst>().is_none());
    }

    #[test]
    fn language_accessor() {
        let pf = make_parsed(0);
        assert_eq!(pf.language(), LanguageId("rust"));
    }

    #[test]
    fn index_is_accessible() {
        let pf = make_parsed(0);
        assert!(pf.index().functions.is_empty());
    }
}
