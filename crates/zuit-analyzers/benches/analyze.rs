//! Criterion end-to-end benchmark: walk + parse + analyze synthetic Rust fixtures.
//!
//! # Fixture strategy
//!
//! A synthetic directory tree is written to a `tempfile::TempDir` **once** at
//! bench-group setup time, then reused across all iterations.  Only the engine
//! pipeline call is timed.
//!
//! File count and size targets:
//!
//! | Fixture       | Files  | Fns / file | Lines / fn | Total LOC (approx) |
//! |---------------|--------|------------|------------|---------------------|
//! | 50k LOC       | 100    | 30         | ~17        | ~51 000             |
//! | 10k LOC       | 20     | 30         | ~17        | ~10 200             |
//! | 1M LOC cold   | 1 000  | ~60        | ~17        | ~1 020 000          |
//! | 1M LOC warm   | 1 000  | ~60        | ~17        | ~1 020 000 (cached) |
//!
//! Files are spread across 10 subdirectories.  Functions include branches, loops,
//! doc comments, and a TODO comment so that complexity, doc-coverage, and
//! todo/fixme analyzers fire realistically.
//!
//! The full engine (`Engine::analyze_path`) is used, which mirrors the CLI code
//! path: walk → parallel parse → per-file analyzers → project-level analyzers.
//! Only the Rust frontend and cross-language analyzers are registered (no
//! Python/JS), keeping the fixture pure-Rust.
//!
//! Smoke tests live in `crates/zuit-analyzers/src/` `#[cfg(test)]` modules
//! so they run under `cargo test`.
//!
//! # Running
//!
//! ```bash
//! cargo bench -p zuit-analyzers --bench analyze
//! cargo bench -p zuit-analyzers --bench analyze -- --quick
//! # Million-LOC scaling only:
//! cargo bench -p zuit-analyzers --bench analyze million
//! ```

use std::fmt::Write as _;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use tempfile::TempDir;

use zuit_core::cache::{AnalysisCache, CacheStore as _, JsonCacheStore};
use zuit_core::{Config, Engine, Language as _, Registry, SourceFile};
use zuit_lang_rust::RustLanguage;

// ── fixture generator ────────────────────────────────────────────────────────

/// Generates a Rust source file with `n_fns` functions.
///
/// Each function is ~17 lines with doc comments, branches, a loop, and a TODO
/// comment — enough variation to exercise all complexity and doc analyzers.
fn make_file_content(file_idx: usize, n_fns: usize) -> String {
    let mut out = String::with_capacity(n_fns * 360 + 64);
    write!(
        out,
        "//! Module {file_idx}: generated benchmark fixture.\n\n"
    )
    .expect("invariant: writing to String cannot fail");

    for i in 0..n_fns {
        write!(
            out,
            "/// Computes a result for item {i} in module {file_idx}.\n\
             ///\n\
             /// # Arguments\n\
             /// * `value` - the input\n\
             /// * `limit` - upper bound\n\
             pub fn compute_{file_idx}_{i}(value: i64, limit: i64) -> i64 {{\n\
             \x20   if value < 0 {{\n\
             \x20       return 0;\n\
             \x20   }}\n\
             \x20   // TODO: optimise the inner loop for large inputs\n\
             \x20   let mut acc: i64 = 0;\n\
             \x20   for j in 0..value.min(limit) {{\n\
             \x20       if j % 2 == 0 {{\n\
             \x20           acc += j;\n\
             \x20       }} else if j % 3 == 0 {{\n\
             \x20           acc -= j;\n\
             \x20       }} else {{\n\
             \x20           acc ^= j;\n\
             \x20       }}\n\
             \x20   }}\n\
             \x20   if acc > limit {{ acc - limit }}\n\
             \x20   else if acc < 0 {{ -acc }}\n\
             \x20   else {{ acc }}\n\
             }}\n\n",
        )
        .expect("invariant: writing to String cannot fail");
    }
    out
}

/// Build a tempdir with `n_files` Rust source files (`fns_per_file` fns each).
///
/// Files are spread across 10 subdirectories.  Returns `(TempDir, root_path)`;
/// the caller must keep `TempDir` alive for the bench duration.
fn build_fixture(n_files: usize, fns_per_file: usize) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().expect("invariant: OS can create tempdir");
    let root = tmp.path().to_path_buf();

    let files_per_subdir = (n_files / 10).max(1);
    for d in 0..10_usize {
        let subdir = root.join(format!("mod{d:02}"));
        fs::create_dir_all(&subdir).expect("invariant: can create subdir");
        for f in 0..files_per_subdir {
            let file_idx = d * files_per_subdir + f;
            if file_idx >= n_files {
                break;
            }
            let content = make_file_content(file_idx, fns_per_file);
            let path = subdir.join(format!("file{f:03}.rs"));
            fs::write(&path, content).expect("invariant: can write fixture file");
        }
    }

    (tmp, root)
}

/// Build a `Registry` with the Rust frontend and all cross-language analyzers.
fn build_registry() -> Registry {
    let mut registry = Registry::new();
    zuit_lang_rust::register(&mut registry);
    for analyzer in zuit_analyzers::builtin() {
        registry.add_analyzer(analyzer);
    }
    registry
}

// ── benches ──────────────────────────────────────────────────────────────────

/// Full pipeline on ~50k LOC (100 files × 30 fns × ~17 lines ≈ 51k LOC).
fn bench_full_pipeline_50kloc(c: &mut Criterion) {
    let (_tmp, root) = build_fixture(100, 30);
    let engine = Engine::new(build_registry());
    let config = Config::default();

    let mut group = c.benchmark_group("end_to_end");
    group.sample_size(10);

    group.bench_function("full_pipeline_50kloc", |b| {
        b.iter(|| {
            let report = engine
                .analyze_path(black_box(&root), black_box(&config))
                .expect("invariant: engine must not fail on valid fixture");
            black_box(report.stats.files_scanned)
        });
    });

    group.finish();
}

/// Full pipeline on ~10k LOC (20 files × 30 fns × ~17 lines ≈ 10k LOC).
fn bench_full_pipeline_10kloc(c: &mut Criterion) {
    let (_tmp, root) = build_fixture(20, 30);
    let engine = Engine::new(build_registry());
    let config = Config::default();

    let mut group = c.benchmark_group("end_to_end");
    group.sample_size(10);

    group.bench_function("full_pipeline_10kloc", |b| {
        b.iter(|| {
            let report = engine
                .analyze_path(black_box(&root), black_box(&config))
                .expect("invariant: engine must not fail on valid fixture");
            black_box(report.stats.files_scanned)
        });
    });

    group.finish();
}

/// Parse-only on ~50k LOC (no analyzers).
///
/// Pre-reads all bytes outside the measured region so we time only `syn` parsing
/// and semantic index construction, not I/O.
fn bench_parse_only_50kloc(c: &mut Criterion) {
    let (_tmp, root) = build_fixture(100, 30);
    let lang = RustLanguage;
    let config = Config::default();

    let paths = zuit_core::walk_files(&root, &["rs"], &config)
        .expect("invariant: walk succeeds on valid fixture");

    let sources: Vec<Arc<SourceFile>> = paths
        .iter()
        .map(|p| {
            let bytes = fs::read(p).expect("invariant: fixture file is readable");
            Arc::new(SourceFile::new(p.clone(), bytes))
        })
        .collect();

    let mut group = c.benchmark_group("end_to_end");
    group.sample_size(10);

    group.bench_function("parse_only_50kloc", |b| {
        b.iter(|| {
            let count: usize = sources
                .iter()
                .filter_map(|src| lang.parse(black_box(Arc::clone(src))).ok())
                .count();
            black_box(count)
        });
    });

    group.finish();
}

// ── Million-LOC scaling benchmarks ───────────────────────────────────────────
//
// These two variants (cold + warm) form the "Million-LOC scaling" bench
// described in docs/perf.md.
//
// Fixture: 1 000 files × ~60 fns × ~17 lines ≈ 1 020 000 LOC.
//
// * `million_cold`: no cache — measures full parse + analyse time.
// * `million_warm`: cache pre-populated on setup — measures cache-hit path.
//
// Iteration count is held at criterion's floor (`sample_size(10)`) so the
// bench finishes in a few minutes rather than tens of minutes on typical
// hardware.  Criterion rejects values below 10 with a runtime panic.

/// Full pipeline on ~1M LOC (1000 files × 60 fns × ~17 lines), no cache.
///
/// This is the baseline wall-clock number.  Expect p50 ≈ 8–25 s depending on
/// the machine.  See `docs/perf.md §Million-LOC scaling` for sample numbers.
fn bench_million_loc_cold(c: &mut Criterion) {
    let (_tmp, root) = build_fixture(1000, 60);
    let engine = Engine::new(build_registry());
    let config = Config::default();

    let mut group = c.benchmark_group("million_loc");
    group.sample_size(10);

    group.bench_function("cold", |b| {
        b.iter(|| {
            let report = engine
                .analyze_path(black_box(&root), black_box(&config))
                .expect("invariant: engine must not fail on valid fixture");
            black_box(report.stats.files_scanned)
        });
    });

    group.finish();
}

/// Full pipeline on ~1M LOC with cache warm (all files cached from prior run).
///
/// Measures how much time is saved when every file is a cache hit.  Only
/// project-level analyzers and the final sort run on every iteration.
fn bench_million_loc_warm(c: &mut Criterion) {
    let (tmp, root) = build_fixture(1000, 60);
    let engine = Engine::new(build_registry());
    let config = Config::default();

    // Pre-populate the cache with a cold run.
    let cache_dir = tmp.path().join(".bench-cache");
    let store = JsonCacheStore::new(cache_dir);
    {
        let mut cache = AnalysisCache::new();
        engine
            .analyze_path_cached(&root, &config, &mut cache)
            .expect("invariant: cold run for cache population must succeed");
        store
            .save(&cache)
            .expect("invariant: saving bench cache must succeed");
    }

    let mut group = c.benchmark_group("million_loc");
    group.sample_size(10);

    group.bench_function("warm", |b| {
        b.iter(|| {
            let mut cache = store.load().expect("invariant: bench cache must load");
            let report = engine
                .analyze_path_cached(black_box(&root), black_box(&config), &mut cache)
                .expect("invariant: engine must not fail on valid fixture");
            black_box(report.stats.cache_hits)
        });
    });

    group.finish();
}

// ── criterion wiring ─────────────────────────────────────────────────────────

fn configure() -> Criterion {
    Criterion::default().sample_size(10)
}

criterion_group! {
    name   = analyze_benches;
    config = configure();
    targets = bench_full_pipeline_50kloc, bench_full_pipeline_10kloc, bench_parse_only_50kloc,
              bench_million_loc_cold, bench_million_loc_warm
}
criterion_main!(analyze_benches);
