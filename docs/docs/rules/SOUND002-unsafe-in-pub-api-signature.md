---
title: SOUND002-unsafe-in-pub-api-signature
sidebar_label: SOUND002-unsafe-in-pub-api-signature
---
# SOUND002-unsafe-in-pub-api-signature

**Dimension:** `unsafe_soundness`
**Default severity:** High
**Languages:** Rust only

## What it detects

Fires when an `unsafe fn` is visible at the module boundary — i.e. the function
has `pub`, `pub(crate)`, `pub(super)`, or any other visibility modifier.

## Why it matters

A `pub unsafe fn` pushes the safety burden onto every caller. Callers must
uphold invariants that the type system cannot enforce, which is error-prone and
makes library adoption risky. Prefer wrapping the unsafe implementation in a
safe, well-documented abstraction.

## Example — flagged

```rust
pub unsafe fn raw_copy(dst: *mut u8, src: *const u8, n: usize) {
    std::ptr::copy_nonoverlapping(src, dst, n);
}
```

## Example — not flagged

```rust
/// Copies `n` bytes from `src` to `dst`.
///
/// # Panics
///
/// Panics if `src` or `dst` slices are shorter than `n`.
pub fn safe_copy(dst: &mut [u8], src: &[u8], n: usize) {
    dst[..n].copy_from_slice(&src[..n]);
}
```

## Fix guidance

- Wrap unsafe logic in a safe abstraction that validates invariants before
  entering the unsafe block.
- If the function _must_ be `unsafe`, add a `# Safety` section to the doc
  comment specifying all required preconditions.

## Suppression

```rust
// zuit: ignore SOUND002
pub unsafe fn dangerous() { ... }
```

## References

- [Rustonomicon: Safe/Unsafe Meaning](https://doc.rust-lang.org/nomicon/safe-unsafe-meaning.html)
- [Rust API Guidelines: Safety](https://rust-lang.github.io/api-guidelines/documentation.html#c-failure)

## See also

`SEC101-rust-unsafe`, `SOUND001`, `SOUND004`
