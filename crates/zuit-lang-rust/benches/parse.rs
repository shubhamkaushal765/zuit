//! Criterion benchmark for `zuit_lang_rust` Rust parsing via `syn`.
//!
//! # Fixture strategy
//!
//! The source string is generated programmatically by repeating a representative
//! function body N times.  This avoids shipping a large fixture file.  Two sizes
//! are benchmarked:
//!
//! - **5 KLOC** (~100 functions × 15 lines each): warm-path single-file parse.
//! - **10 KLOC** (~200 functions × 15 lines each): shows linear scaling.
//!
//! The source string is built once outside the measured region.  Each criterion
//! iteration creates a fresh `SourceFile` (cheap) and runs the full
//! `syn::parse_file` + index-building path.
//!
//! Smoke tests live in `crates/zuit-lang-rust/src/parse.rs` `#[cfg(test)]`
//! so they run under `cargo test`.
//!
//! # Running
//!
//! ```bash
//! cargo bench -p zuit-lang-rust --bench parse
//! cargo bench -p zuit-lang-rust --bench parse -- --quick
//! ```

use std::fmt::Write as _;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};

use zuit_core::{Language as _, SourceFile};
use zuit_lang_rust::RustLanguage;

// ── fixture generator ────────────────────────────────────────────────────────

/// Generates a valid Rust source string containing `n` functions.
///
/// Each function is ~15 lines with a mix of conditionals, loops, and early
/// returns so that complexity metrics (cyclomatic, cognitive, nesting) are
/// exercised during index building.
fn generate_rust_source(n_functions: usize) -> String {
    let mut out = String::with_capacity(n_functions * 400 + 64);
    out.push_str("//! Generated benchmark fixture.\n\n");

    for i in 0..n_functions {
        // Representative function: branches, a loop, early return, doc comment.
        write!(
            out,
            "/// Computes a value for item {i}.\n\
             ///\n\
             /// # Arguments\n\
             /// * `input` - the input value\n\
             /// * `threshold` - upper bound\n\
             pub fn compute_{i}(input: i64, threshold: i64) -> i64 {{\n\
             \x20   if input < 0 {{\n\
             \x20       return -input;\n\
             \x20   }}\n\
             \x20   let mut acc: i64 = 0;\n\
             \x20   for j in 0..input {{\n\
             \x20       if j % 2 == 0 {{\n\
             \x20           acc += j;\n\
             \x20       }} else if j % 3 == 0 {{\n\
             \x20           acc -= j;\n\
             \x20       }} else {{\n\
             \x20           acc ^= j;\n\
             \x20       }}\n\
             \x20   }}\n\
             \x20   if acc > threshold {{ acc / threshold.max(1) }}\n\
             \x20   else if acc == 0 {{ threshold }}\n\
             \x20   else {{ acc }}\n\
             }}\n\n",
        )
        .expect("invariant: writing to String cannot fail");
    }
    out
}

// ── benches ──────────────────────────────────────────────────────────────────

/// Parse a ~5 KLOC Rust source (100 functions × ~15 lines).
fn bench_parse_5kloc(c: &mut Criterion) {
    let source_text = generate_rust_source(100);
    let lang = RustLanguage;

    let mut group = c.benchmark_group("parse");
    group.sample_size(20);

    group.bench_function("rust_parse/5kloc_100fns", |b| {
        b.iter(|| {
            let src = Arc::new(SourceFile::new(
                "bench_5kloc.rs",
                black_box(source_text.as_bytes().to_vec()),
            ));
            let result = lang
                .parse(black_box(src))
                .expect("invariant: fixture is valid Rust");
            black_box(result.index().functions.len())
        });
    });

    group.finish();
}

/// Parse a ~10 KLOC Rust source (200 functions × ~15 lines).
fn bench_parse_10kloc(c: &mut Criterion) {
    let source_text = generate_rust_source(200);
    let lang = RustLanguage;

    let mut group = c.benchmark_group("parse");
    group.sample_size(20);

    group.bench_function("rust_parse/10kloc_200fns", |b| {
        b.iter(|| {
            let src = Arc::new(SourceFile::new(
                "bench_10kloc.rs",
                black_box(source_text.as_bytes().to_vec()),
            ));
            let result = lang
                .parse(black_box(src))
                .expect("invariant: fixture is valid Rust");
            black_box(result.index().functions.len())
        });
    });

    group.finish();
}

// ── criterion wiring ─────────────────────────────────────────────────────────

fn configure() -> Criterion {
    Criterion::default().sample_size(20)
}

criterion_group! {
    name   = parse_benches;
    config = configure();
    targets = bench_parse_5kloc, bench_parse_10kloc
}
criterion_main!(parse_benches);
