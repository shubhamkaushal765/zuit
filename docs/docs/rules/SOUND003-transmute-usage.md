---
title: SOUND003-transmute-usage
sidebar_label: SOUND003-transmute-usage
---
# SOUND003-transmute-usage

**Dimension:** `unsafe_soundness`
**Default severity:** High
**Languages:** Rust only
**CWE:** CWE-704 (Incorrect Type Conversion or Cast)

## What it detects

Fires on every call to `mem::transmute`, `std::mem::transmute`, or bare
`transmute`. The check is best-effort: it inspects the final path segment of
the call expression and matches the name `transmute`.

## Why it matters

`std::mem::transmute` reinterprets the raw bits of a value as a different type
without any runtime check. It can produce undefined behaviour if:

- The types have different sizes.
- The target type has invalid bit patterns (e.g. `bool` requires `0` or `1`).
- The alignment of the underlying memory does not match the target type.

Safer alternatives exist for almost every use case.

## Example — flagged

```rust
use std::mem;

fn as_i32(x: u32) -> i32 {
    unsafe { mem::transmute(x) }
}
```

## Example — not flagged

```rust
fn as_i32(x: u32) -> i32 {
    x as i32  // defined behaviour for numeric casts
}
```

## Fix guidance

| Use case | Safer alternative |
|---|---|
| Numeric reinterpret | `x as T` or `i32::from_ne_bytes(x.to_ne_bytes())` |
| `&T` to `&[u8]` | `bytemuck::bytes_of` or `std::slice::from_raw_parts` with size/align proof |
| `*mut T` to `*mut U` | `pointer::cast()` |
| Enum discriminant | Explicit `match` or `TryFrom` |

If transmute is truly unavoidable, add a `// SAFETY:` comment proving that both
types have identical size, alignment, and valid bit patterns.

## Suppression

```rust
// zuit: ignore SOUND003
let y: i32 = unsafe { mem::transmute(x) };
```

## References

- [std::mem::transmute](https://doc.rust-lang.org/std/mem/fn.transmute.html)
- [CWE-704](https://cwe.mitre.org/data/definitions/704.html)
- [bytemuck crate](https://docs.rs/bytemuck)

## See also

`SEC101-rust-unsafe`, `SOUND001`, `SOUND005`
