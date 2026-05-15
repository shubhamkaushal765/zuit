---
title: PERF003-arc-mutex-density
sidebar_label: PERF003-arc-mutex-density
---
# PERF003-arc-mutex-density

**Dimension:** `performance`
**Default severity:** Low
**Languages:** Rust (project-level)
**CWE:** (none)

## What it detects

Counts occurrences of the pattern `Arc<Mutex<…>` (via regex `\bArc\s*<\s*Mutex\b`) across all Rust source files. If any single file exceeds the threshold (default: 5), one finding is emitted pinned to the file with the highest density.

## Why it matters

`Arc<Mutex<T>>` is a valid pattern for shared mutable state, but overuse often signals:

- **Lock contention** — many threads waiting on a single lock degrades throughput.
- **Deadlock risk** — complex lock hierarchies are hard to reason about.
- **Design smell** — excessive shared state may indicate missing actor-pattern or message-passing opportunities.

The rule does not flag individual usages; it flags files where the density suggests a structural issue.

## Example — flagged

A file with 6+ `Arc<Mutex<…>>` type aliases or field declarations:

```rust
type Cache = Arc<Mutex<HashMap<String, Value>>>;
type Counter = Arc<Mutex<u64>>;
type State = Arc<Mutex<AppState>>;
// ... (3 more)
```

## Example — not flagged

Fewer than 6 occurrences per file (or zero).

## Fix guidance

- Consider the **actor pattern**: wrap state in a dedicated task that owns data exclusively, and communicate via channels (`tokio::sync::mpsc`, `std::sync::mpsc`).
- Use **per-item locks** (e.g. `DashMap`) for fine-grained concurrency.
- Prefer `RwLock` over `Mutex` for read-heavy workloads.
- Use `Arc<T>` without `Mutex` when interior mutability is not needed.

## Threshold

The default threshold is **5 occurrences per file**. Future versions will allow configuration via `[rust.perf] arc_mutex_density_threshold`.

## Suppression

```rust
// zuit: ignore PERF003-arc-mutex-density
```

## References

- [The Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [Tokio sync primitives](https://docs.rs/tokio/latest/tokio/sync/index.html)
- [DashMap](https://docs.rs/dashmap/latest/dashmap/)
