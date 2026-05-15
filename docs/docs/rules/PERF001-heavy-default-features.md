---
title: PERF001-heavy-default-features
sidebar_label: PERF001-heavy-default-features
---
# PERF001-heavy-default-features

**Dimension:** `performance`
**Default severity:** Medium
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when a dependency in `[dependencies]` either:

1. Specifies `features = ["full"]` (case-insensitive) without `default-features = false`.
2. Is a known-heavy crate (`tokio`, `reqwest`, `axum`, `actix-web`) and does **not** set `default-features = false`.

**Note:** This rule overlaps with `PKG009-default-features-bloat`, which fires under the `packaging` dimension. Both are intentionally kept: PKG009 is a packaging hygiene signal; PERF001 is a runtime-performance signal.

## Why it matters

Enabling the `full` feature set of a large async framework pulls in every sub-component, dramatically increasing compile times, binary size, and linker work. The default feature sets of crates like `tokio` and `reqwest` include TLS, HTTP/2, and other heavy subsystems that many projects do not need.

## Example — flagged

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.11" }  # known-heavy, no default-features = false
```

## Example — not flagged

```toml
[dependencies]
tokio = { version = "1", features = ["rt", "macros"], default-features = false }
reqwest = { version = "0.11", default-features = false, features = ["rustls-tls"] }
```

## Fix guidance

Audit which features your project actually uses:

```sh
cargo tree --edges features -p tokio
```

Then pin only those features and add `default-features = false`.

## Suppression

```toml
# Cargo.toml
# zuit: ignore PERF001-heavy-default-features
tokio = { version = "1", features = ["full"] }
```

## References

- [Cargo features reference](https://doc.rust-lang.org/cargo/reference/features.html)
- [The Rust Performance Book](https://nnethercote.github.io/perf-book/)
