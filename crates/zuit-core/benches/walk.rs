//! Criterion benchmark for `walk_files`.
//!
//! # Fixture strategy
//!
//! The fixture is built **once** in `setup_tree` before any measured iteration:
//! a tempdir containing `.rs` files spread across subdirectories.  Each file
//! contains a minimal `fn placeholder_N() {}` body so they are valid Rust but
//! tiny.  The relevant cost here is filesystem metadata traversal and the
//! lexicographic sort, not I/O volume.
//!
//! The tempdir handle is kept alive for the duration of each bench function and
//! dropped at the end of that function.
//!
//! Smoke tests live in `crates/zuit-core/src/walk.rs` `#[cfg(test)]` so
//! they run under `cargo test`.
//!
//! # Running
//!
//! ```bash
//! cargo bench -p zuit-core --bench walk
//! cargo bench -p zuit-core --bench walk -- --quick
//! ```

use std::fs;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use tempfile::TempDir;

use zuit_core::Config;
use zuit_core::walk::walk_files;

// ── fixture ──────────────────────────────────────────────────────────────────

/// Creates a `TempDir` containing `n_dirs * files_per_dir` `.rs` source files.
///
/// The caller must keep the returned `TempDir` alive for the lifetime of any
/// measurement that uses the path — dropping it earlier would delete the tree.
fn setup_tree(n_dirs: usize, files_per_dir: usize) -> TempDir {
    let tmp = TempDir::new().expect("invariant: OS can create temp dirs");
    let root = tmp.path();
    for d in 0..n_dirs {
        let dir = root.join(format!("sub_{d:03}"));
        fs::create_dir_all(&dir).expect("invariant: OS can create subdirectory");
        for f in 0..files_per_dir {
            let content = format!("/// Placeholder.\npub fn placeholder_{d}_{f}() {{}}\n");
            fs::write(dir.join(format!("file_{f:03}.rs")), content)
                .expect("invariant: OS can write fixture file");
        }
    }
    tmp
}

// ── benches ──────────────────────────────────────────────────────────────────

/// Walk a 500-file tree (10 dirs × 50 files each).
fn bench_walk_500_files(c: &mut Criterion) {
    let tmp = setup_tree(10, 50);
    let root = tmp.path().to_path_buf();
    let config = Config::default();

    c.bench_function("walk_files/500_rs_files", |b| {
        b.iter(|| {
            let paths =
                walk_files(black_box(&root), black_box(&["rs"]), black_box(&config)).unwrap();
            assert!(!paths.is_empty());
            paths
        });
    });

    drop(tmp);
}

/// Walk a 100-file tree (10 dirs × 10 files each) to show scaling.
fn bench_walk_100_files(c: &mut Criterion) {
    let tmp = setup_tree(10, 10);
    let root = tmp.path().to_path_buf();
    let config = Config::default();

    c.bench_function("walk_files/100_rs_files", |b| {
        b.iter(|| {
            let paths =
                walk_files(black_box(&root), black_box(&["rs"]), black_box(&config)).unwrap();
            assert!(!paths.is_empty());
            paths
        });
    });

    drop(tmp);
}

/// Walk a flat directory with no subdirectories (50 files).
fn bench_walk_flat_50_files(c: &mut Criterion) {
    let tmp = setup_tree(1, 50);
    let root = tmp.path().to_path_buf();
    let config = Config::default();

    c.bench_function("walk_files/flat_50_rs_files", |b| {
        b.iter(|| {
            let paths =
                walk_files(black_box(&root), black_box(&["rs"]), black_box(&config)).unwrap();
            assert!(!paths.is_empty());
            paths
        });
    });

    drop(tmp);
}

// ── criterion wiring ─────────────────────────────────────────────────────────

fn configure() -> Criterion {
    // Modest sample size so the bench completes quickly on CI.
    // Increase to 100 (the default) for profiling.
    Criterion::default().sample_size(20)
}

criterion_group! {
    name   = walk_benches;
    config = configure();
    targets = bench_walk_500_files, bench_walk_100_files, bench_walk_flat_50_files
}
criterion_main!(walk_benches);
