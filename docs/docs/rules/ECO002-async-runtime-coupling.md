---
title: ECO002-async-runtime-coupling
sidebar_label: ECO002-async-runtime-coupling
---
# ECO002-async-runtime-coupling

**Dimension:** `ecosystem`
**Default severity:** Low
**Languages:** Rust (project-level)
**CWE:** (none)

## What it detects

Fires when `[dependencies]` contains `tokio` **and** none of the following runtime-agnostic alternatives are present: `async-std`, `smol`, `futures`, `async-trait`.

## Why it matters

A hard `tokio` dependency forces all downstream consumers to also depend on `tokio`, even if they prefer `async-std` or `smol`. For library crates this can cause runtime conflicts and limits adoption.

## Heuristic limitations

- **`cfg(…)`-gated runtime selection is not detected.** A project that feature-gates `tokio` as an optional executor will still trigger this rule.
- **Dev-dependencies are not checked.** If `tokio` is only in `[dev-dependencies]`, the rule is silent.
- The presence of `futures` or `async-trait` is used as a proxy for runtime-agnostic design — this may produce false-positives if those crates are used for unrelated reasons.

Always review findings manually before acting on them.

## Example — flagged

```toml
[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
serde = "1"
```

## Example — not flagged

```toml
[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
futures = "0.3"  # runtime-agnostic async traits
```

## Fix guidance

- For library crates: abstract the executor behind a feature flag:
  ```toml
  [features]
  tokio-runtime = ["tokio"]
  async-std-runtime = ["async-std"]
  ```
- Use the `futures` crate for executor-agnostic `AsyncRead`, `AsyncWrite`, and `Stream` traits.

## Suppression

```toml
# Cargo.toml
# zuit: ignore ECO002-async-runtime-coupling
tokio = { version = "1", features = ["rt-multi-thread"] }
```

## References

- [Async Rust ecosystem guide](https://rust-lang.github.io/async-book/)
- [futures crate](https://docs.rs/futures/latest/futures/)
