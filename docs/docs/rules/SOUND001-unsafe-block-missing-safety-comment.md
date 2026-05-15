---
title: SOUND001-unsafe-block-missing-safety-comment
sidebar_label: SOUND001-unsafe-block-missing-safety-comment
---
# SOUND001-unsafe-block-missing-safety-comment

**Dimension:** `unsafe_soundness`
**Default severity:** Medium
**Languages:** Rust only
**CWE:** (none)

## What it detects

Fires when an `unsafe { … }` block has **no** `// SAFETY:` comment on the block
itself or the line immediately above it.

A `// SAFETY:` comment is the idiomatic Rust way to document _why_ an unsafe
block is sound. Without it, reviewers cannot tell whether the invariants required
by the unsafe code have been considered.

## Why it matters

Unsafe blocks without rationale comments are a maintenance hazard. When the
surrounding code changes, reviewers cannot tell which invariants the original
author relied on, making soundness regressions much harder to detect.

## Example — flagged

```rust
fn copy_bytes(dst: *mut u8, src: *const u8, len: usize) {
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst, len);
    }
}
```

## Example — not flagged

```rust
fn copy_bytes(dst: *mut u8, src: *const u8, len: usize) {
    // SAFETY: caller guarantees dst and src are valid, non-overlapping, and
    // at least `len` bytes long.
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst, len);
    }
}
```

## Fix guidance

Add `// SAFETY: <reason>` on the line immediately above the `unsafe` keyword.
Explain:

1. Which invariants the unsafe operation requires.
2. Why those invariants hold at this call site.

## Suppression

```rust
// zuit: ignore SOUND001
unsafe { ... }
```

## References

- [Rust Reference: Unsafe Blocks](https://doc.rust-lang.org/reference/unsafe-blocks.html)
- [Rustonomicon: Working with Unsafe](https://doc.rust-lang.org/nomicon/working-with-unsafe.html)

## See also

- `SEC101-rust-unsafe` — inventories all unsafe constructs (informational)
- `SOUND002` through `SOUND006` — related soundness rules
