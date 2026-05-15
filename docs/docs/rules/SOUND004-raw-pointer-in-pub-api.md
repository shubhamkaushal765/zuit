---
title: SOUND004-raw-pointer-in-pub-api
sidebar_label: SOUND004-raw-pointer-in-pub-api
---
# SOUND004-raw-pointer-in-pub-api

**Dimension:** `unsafe_soundness`
**Default severity:** High
**Languages:** Rust only

## What it detects

Fires when a `pub fn` (including `pub(crate)` and other restricted forms)
contains a `*const T` or `*mut T` raw pointer in argument or return position.

## Why it matters

Raw pointers in a public function signature force callers into unsafe code.
Callers must ensure the pointer is:

- Non-null (unless the function documents null as valid).
- Correctly aligned for the pointee type.
- Pointing to valid, initialized memory of the right size.
- Not aliased in ways the callee does not expect.

None of these constraints are enforced by the type system, making such APIs
error-prone for downstream users.

## Example — flagged

```rust
pub fn get_byte(ptr: *const u8, offset: usize) -> u8 {
    unsafe { *ptr.add(offset) }
}

pub fn null_terminated_len(s: *const u8) -> usize { ... }
```

## Example — not flagged

```rust
pub fn get_byte(slice: &[u8], offset: usize) -> Option<u8> {
    slice.get(offset).copied()
}
```

## Fix guidance

- Replace `*const T` parameters with `&T` or `&[T]`.
- Replace `*mut T` parameters with `&mut T` or `&mut [T]`.
- For return values that must be pointers (FFI), mark the function `unsafe` and
  add a `# Safety` doc section.
- For FFI boundaries, encapsulate the raw pointer in a newtype with invariant
  documentation.

## Suppression

```rust
// zuit: ignore SOUND004
pub fn ffi_shim(ptr: *mut u8) { ... }
```

## References

- [Rust Reference: Raw Pointer Types](https://doc.rust-lang.org/reference/types/pointer.html)
- [Rustonomicon: FFI](https://doc.rust-lang.org/nomicon/ffi.html)

## See also

`SEC101-rust-unsafe`, `SOUND002`, `SOUND006`
