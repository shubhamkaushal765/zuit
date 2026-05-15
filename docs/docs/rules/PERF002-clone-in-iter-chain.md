---
title: PERF002-clone-in-iter-chain
sidebar_label: PERF002-clone-in-iter-chain
---
# PERF002-clone-in-iter-chain

**Dimension:** `performance`
**Default severity:** Medium
**Languages:** Rust (file-level)
**CWE:** (none)

## What it detects

A `.clone()` call appears inside a code block that also contains an iterator-start call (`.iter()`, `.into_iter()`, or `.iter_mut()`). This pattern often indicates unnecessary heap allocations inside an iterator chain.

**Heuristic:** The rule detects any `Block` that contains both an iter-start method call and a `.clone()` call. False-positives are possible when the clone is genuinely necessary (e.g. cloning a value before moving it into a closure, or cloning a non-iterator value in the same block). Always review findings manually.

## Why it matters

In tight loops or large data-processing pipelines, cloning each element in an iterator chain allocates heap memory for every iteration. Rust provides `.cloned()` and `.copied()` adapters that make the intent explicit and, in some cases, allow the optimizer to elide allocations.

## Example — flagged

```rust
// Clone inside an iter chain block
fn copy_names(items: &[String]) -> Vec<String> {
    items.iter().map(|x| x.clone()).collect()
}
```

## Example — not flagged

```rust
// Use .cloned() adapter instead
fn copy_names(items: &[String]) -> Vec<String> {
    items.iter().cloned().collect()
}

// Or .copied() for Copy types
fn copy_ids(items: &[u32]) -> Vec<u32> {
    items.iter().copied().collect()
}
```

## Fix guidance

- Replace `.iter().map(|x| x.clone())` with `.iter().cloned()` for `T: Clone`.
- Replace `.iter().map(|x| *x)` with `.iter().copied()` for `T: Copy`.
- If the clone is genuinely needed (e.g. before a move), suppress the finding.

## Known false-positives

- Cloning a non-iterator value in the same block as an `.iter()` call.
- Iterator chains where the `.clone()` targets a different value than the iterated element.

## Suppression

```rust
// zuit: ignore PERF002-clone-in-iter-chain
items.iter().map(|x| x.clone()).collect()
```

## References

- [Iterator::cloned](https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.cloned)
- [Iterator::copied](https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.copied)
- [The Rust Performance Book](https://nnethercote.github.io/perf-book/)
