---
title: SOUND005-unsafe-and-parsing-combo
sidebar_label: SOUND005-unsafe-and-parsing-combo
---
# SOUND005-unsafe-and-parsing-combo

**Dimension:** `unsafe_soundness`
**Default severity:** High
**Languages:** Rust only

## What it detects

Fires when a **single function body** contains both:

1. An `unsafe { … }` block, **and**
2. A call to a known parser/decoder family.

Recognized names (heuristic — matched on the final path segment or method name):

`from_bytes`, `from_raw`, `parse_unchecked`, `from_utf8_unchecked`,
`from_raw_parts`, `from_raw_parts_mut`, `from_ptr`

## Why it matters

Combining input parsing with unsafe operations in the same function is a common
source of soundness bugs. If the validation step is skipped or weakened (e.g.
during a refactor), the unsafe block may operate on untrusted, invalid data —
leading to memory corruption or undefined behaviour.

## Example — flagged

```rust
fn load_str(data: &[u8]) -> &str {
    // Parsing and unsafe in the same body.
    if data.is_ascii() {
        unsafe { std::str::from_utf8_unchecked(data) }
    } else {
        ""
    }
}
```

## Example — not flagged

```rust
/// Validates first, then delegates to an unsafe helper.
pub fn load_str(data: &[u8]) -> Result<&str, Utf8Error> {
    std::str::from_utf8(data)
}

/// # Safety
/// Caller must guarantee `data` is valid UTF-8.
pub unsafe fn load_str_unchecked(data: &[u8]) -> &str {
    std::str::from_utf8_unchecked(data)
}
```

## Fix guidance

- Separate the validation step from the unsafe operation into distinct functions.
- Use the safe API (e.g. `std::str::from_utf8`) and propagate the error.
- If the unchecked variant is needed for performance, isolate it in its own
  `unsafe fn` with a `# Safety` doc comment.

## Suppression

```rust
// zuit: ignore SOUND005
fn combined(data: &[u8]) -> &str { ... }
```

## References

- [Rustonomicon: Working with Unsafe](https://doc.rust-lang.org/nomicon/working-with-unsafe.html)
- [std::str::from_utf8_unchecked](https://doc.rust-lang.org/std/str/fn.from_utf8_unchecked.html)

## See also

`SEC101-rust-unsafe`, `SOUND001`, `SOUND003`
