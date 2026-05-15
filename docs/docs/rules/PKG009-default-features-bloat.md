---
title: PKG009-default-features-bloat
sidebar_label: PKG009-default-features-bloat
---
# PKG009-default-features-bloat

**Dimension:** `packaging`
**Default severity:** Medium
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires for each dependency in `[dependencies]` or `[dev-dependencies]` that:

1. Has a `features` array containing `"full"`, AND
2. Does **not** have `default-features = false`.

The canonical offender is `tokio = { version = "1", features = ["full"] }`.

## Why it matters

The `"full"` feature in libraries like `tokio`, `reqwest`, and `axum` enables
every sub-component, pulling in many transitive dependencies and significantly
increasing:

- Compile time (sometimes by 30–60 seconds on cold builds).
- Binary size (often by several megabytes).
- Attack surface (more code compiled in).

## Example — flagged

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
```

## Example — not flagged

```toml
[dependencies]
tokio = { version = "1", features = ["rt", "macros", "net"] }
```

Or with `default-features = false` (accepted even with `"full"` selected):

```toml
[dependencies]
tokio = { version = "1", features = ["full"], default-features = false }
```

## Fix guidance

Replace `features = ["full"]` with only the features your code actually uses:

```sh
# Identify which tokio features you import
rg "tokio::" src/ --no-heading | grep -o 'tokio::[a-z_:]*'
```

Then declare only those features explicitly.

## Suppression

```toml
# zuit: ignore PKG009
[dependencies]
tokio = { version = "1", features = ["full"] }
```

## References

- [Cargo features documentation](https://doc.rust-lang.org/cargo/reference/features.html)
- [tokio feature flags](https://docs.rs/tokio/latest/tokio/#feature-flags)
