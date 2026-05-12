//! `rustpython-parser`-backed implementation of [`zuit_core::Language`]
//! for Python source files.
//!
//! The module owns:
//! - [`PythonLanguage`] — the public `Language` implementor.
//! - [`PythonAst`] — the `pub(crate)` wrapper around [`ModModule`] that
//!   implements [`zuit_core::NativeAst`].

use std::any::Any;
use std::sync::Arc;

use rustpython_parser::Parse;
use rustpython_parser::ast::ModModule;

use zuit_core::{LanguageId, NativeAst, ParseError, ParsedFile, SourceFile};

use crate::index;

/// The Python language frontend.
///
/// Registered by [`crate::register`]. Handles files with the `.py` extension
/// and uses `rustpython-parser` for the actual parse.
pub struct PythonLanguage;

/// Opaque wrapper around a `rustpython-parser` module AST.
///
/// This type is `pub(crate)` so that language-specific analyzers in this crate
/// can downcast to it via [`zuit_core::ParsedFile::native`], while
/// cross-language analyzers (which do not depend on this crate) cannot.
pub(crate) struct PythonAst {
    /// The parsed module.
    pub(crate) module: ModModule,
}

impl NativeAst for PythonAst {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl zuit_core::Language for PythonLanguage {
    fn id(&self) -> LanguageId {
        LanguageId("python")
    }

    fn extensions(&self) -> &[&'static str] {
        &["py"]
    }

    /// Parses `source` as a Python module.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Syntax`] when the source contains a syntax error,
    /// with the byte offset of the first problematic token (when available).
    /// Returns [`ParseError::Encoding`] when the source bytes are not valid
    /// UTF-8 (rare in practice since `rustpython-parser` works on `&str`).
    fn parse(&self, source: Arc<SourceFile>) -> Result<ParsedFile, ParseError> {
        // Ensure source is valid UTF-8 — `SourceFile::as_str()` panics on bad
        // UTF-8, so we guard here and turn it into the proper error variant.
        let text = std::str::from_utf8(source.bytes())
            .map_err(|_| ParseError::Encoding(source.path.clone()))?;

        // Parse using the `Parse` trait on `ModModule` (preferred over the
        // deprecated `parse_program` function).
        let file_name = source.path.to_string_lossy().into_owned();
        let module = ModModule::parse(text, &file_name).map_err(|e| {
            // `rustpython_parser::ParseError` carries an `offset: TextSize`
            // (a `u32` byte offset) and a `source_path: String`.
            let offset = e.offset.to_u32();
            let span = zuit_core::Span::new(
                zuit_core::ByteOffset(offset),
                zuit_core::ByteOffset(offset),
            );
            ParseError::Syntax {
                file: source.path.clone(),
                message: e.error.to_string(),
                span: Some(span),
            }
        })?;

        let semantic_index = index::build_index(&module, &source);

        Ok(ParsedFile::new(
            LanguageId("python"),
            source,
            semantic_index,
            Box::new(PythonAst { module }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::Language;

    fn make_source(path: &str, content: &str) -> Arc<SourceFile> {
        Arc::new(SourceFile::new(path, content.as_bytes().to_vec()))
    }

    #[test]
    fn parse_valid_python() {
        let lang = PythonLanguage;
        let src = make_source("hello.py", "def hello():\n    return 42\n");
        let result = lang.parse(src);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let pf = result.unwrap();
        assert_eq!(pf.language(), LanguageId("python"));
    }

    #[test]
    fn parse_empty_source() {
        let lang = PythonLanguage;
        let src = make_source("empty.py", "");
        let result = lang.parse(src);
        assert!(result.is_ok(), "empty source should parse fine");
    }

    #[test]
    fn parse_syntax_error_returns_parse_error_syntax() {
        let lang = PythonLanguage;
        let src = make_source("bad.py", "def (:\n    pass\n");
        let result = lang.parse(src);
        assert!(result.is_err(), "expected Err for invalid syntax");
        match result.unwrap_err() {
            ParseError::Syntax { .. } => {}
            other => panic!("expected ParseError::Syntax, got {other:?}"),
        }
    }

    #[test]
    fn parse_stores_native_ast() {
        use crate::parse::PythonAst;
        let lang = PythonLanguage;
        let src = make_source("mod.py", "x = 1\n");
        let pf = lang.parse(src).unwrap();
        assert!(
            pf.native::<PythonAst>().is_some(),
            "native downcast should succeed"
        );
    }

    #[test]
    fn id_and_extensions() {
        let lang = PythonLanguage;
        assert_eq!(lang.id(), LanguageId("python"));
        assert!(lang.extensions().contains(&"py"));
    }

    #[test]
    fn try_python_ast_accessor() {
        let lang = PythonLanguage;
        let src = make_source("mod.py", "pass\n");
        let pf = lang.parse(src).unwrap();
        let ast = crate::try_python_ast(&pf);
        assert!(ast.is_some(), "try_python_ast should return Some");
    }
}
