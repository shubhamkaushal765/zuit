//! Static performance heuristic analyzers for JS/TS packages.
//!
//! | Rule | Kind | Description |
//! |------|------|-------------|
//! | [`PERF001-bundle-size`](perf001_bundle_size) | `ProjectLevel` | `dist/` exceeds 1 MiB |
//! | [`PERF002-heavy-import`](perf002_heavy_import) | `FileLevel` | top-level import of a known-heavy package |
//! | [`PERF003-import-side-effect`](perf003_import_side_effect) | `FileLevel` | top-level bare call expression |

pub mod perf001_bundle_size;
pub mod perf002_heavy_import;
pub mod perf003_import_side_effect;

pub use perf001_bundle_size::Perf001BundleSizeAnalyzer;
pub use perf002_heavy_import::Perf002HeavyImportAnalyzer;
pub use perf003_import_side_effect::Perf003ImportSideEffectAnalyzer;
