---
title: SOUND006-ffi-without-safety-doc
sidebar_label: SOUND006-ffi-without-safety-doc
---
# SOUND006-ffi-without-safety-doc

**Dimension:** `unsafe_soundness`
**Default severity:** Medium
**Languages:** Rust only

## What it detects

Fires when an `unsafe fn` declared inside an `extern "…"` block has no
`// SAFETY:` or `/// SAFETY:` comment on the line immediately above it.

## Why it matters

Functions declared in `extern` blocks are foreign functions (C, C++, etc.).
Every call to them is implicitly unsafe. Without a safety comment, reviewers
cannot determine what preconditions the foreign function requires — alignment,
null-pointer rules, lifetime requirements, thread safety, etc.

## Example — flagged

```rust
extern "C" {
    unsafe fn do_thing(buf: *mut u8, len: usize) -> i32;
}
```

## Example — not flagged

```rust
extern "C" {
    // SAFETY: `buf` must be a valid pointer to at least `len` bytes.
    // `len` must be ≤ isize::MAX. Thread-safe.
    unsafe fn do_thing(buf: *mut u8, len: usize) -> i32;
}
```

## Fix guidance

Add `// SAFETY: <reason>` on the line immediately above each `unsafe fn`
declaration in the `extern` block. Document:

- Pointer validity requirements (alignment, non-null, size).
- Lifetime constraints.
- Thread safety guarantees.
- Any other preconditions from the C/C++ documentation.

## Suppression

```rust
extern "C" {
    // zuit: ignore SOUND006
    unsafe fn raw_ffi(p: *mut u8) -> i32;
}
```

## References

- [Rustonomicon: FFI](https://doc.rust-lang.org/nomicon/ffi.html)
- [Rust Reference: External Blocks](https://doc.rust-lang.org/reference/items/external-blocks.html)

## See also

`SEC101-rust-unsafe`, `SOUND001`, `SOUND004`
