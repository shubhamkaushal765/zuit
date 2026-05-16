//! Core traits, types, semantic index, engine, and registry for the zuit
//! static analysis workspace.
//!
//! Every other crate in the workspace depends on this crate.  Language frontends
//! implement [`language::Language`]; analyzers implement [`analyzer::Analyzer`].
//! The [`engine::Engine`] orchestrates the full pipeline and returns a
//! [`engine::Report`].
//!
//! # Key modules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`id`] | [`id::LanguageId`], [`id::AnalyzerId`] |
//! | [`span`] | [`span::ByteOffset`], [`span::Span`], [`span::LineCol`], [`span::Location`] |
//! | [`source`] | [`source::SourceFile`] with lazy line index |
//! | [`index`] | [`index::SemanticIndex`] and all its constituent types |
//! | [`parsed`] | [`parsed::ParsedFile`], [`parsed::NativeAst`] |
//! | [`language`] | [`language::Language`] trait |
//! | [`analyzer`] | [`analyzer::Analyzer`], [`analyzer::Dimension`], [`analyzer::Severity`] |
//! | [`finding`] | [`finding::Finding`] |
//! | [`score`] | [`score::Score`], [`score::aggregate_dimension_score`] |
//! | [`error`] | [`error::ParseError`], [`error::EngineError`], [`error::ConfigError`] |
//! | [`config`] | [`config::Config`] |
//! | [`registry`] | [`registry::Registry`] |
//! | [`engine`] | [`engine::Engine`], [`engine::Report`], [`engine::RunStats`] |
//! | [`external`] | [`external::Outcome`], [`external::run_with_limits`], [`external::build_line_starts`], [`external::compute_span`] |
//! | [`walk`] | [`walk::walk_files`] |
#![warn(missing_docs)]

pub mod analyzer;
pub mod cache;
pub mod config;
pub mod engine;
pub mod error;
// `external` is reached via the full module path; not re-exported at crate root because it is subprocess infrastructure rather than core domain.
pub mod external;
pub mod finding;
pub mod id;
pub mod index;
pub mod language;
pub mod parsed;
pub mod path;
pub mod registry;
pub mod score;
pub mod source;
pub mod span;
pub mod walk;

// Re-export the most-used public items at the crate root for convenience.
pub use analyzer::{
    AnalysisContext, Analyzer, AnalyzerKind, Dimension, Project, RuleMeta, Severity,
    SupportedLanguages,
};
pub use cache::{
    AnalysisCache, CacheEntry, CacheStore, CacheStoreError, JsonCacheStore, hash_bytes, hash_config,
};
pub use config::Config;
pub use engine::{Engine, Report, RunStats};
pub use error::{ConfigError, EngineError, ParseError};
pub use finding::{Finding, sort_findings};
pub use id::{AnalyzerId, LanguageId};
pub use index::{
    Comment, ComplexityMetrics, DocComment, FunctionKind, FunctionLike, Import, ModuleDecl, NodeId,
    RegexLiteral, SemanticIndex, StringLit, Suppression, TypeDecl, Visibility,
    parse_suppression_directive,
};
pub use language::Language;
pub use parsed::{NativeAst, ParsedFile};
pub use registry::Registry;
pub use score::{Score, aggregate_dimension_score, severity_weight};
pub use source::SourceFile;
pub use span::{ByteOffset, LineCol, Location, Span};
pub use walk::walk_files;
