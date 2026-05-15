---
title: SEC101-rust-unsafe — Unsafe code audit trail
sidebar_label: SEC101-rust-unsafe
description: Records every unsafe block, function, impl, or trait in a Rust source file.
---

# SEC101-rust-unsafe — Unsafe code audit trail

| Property         | Value     |
| ---------------- | --------- |
| Dimension        | Security  |
| Default severity | Info      |
| Languages        | Rust only |

## What it detects

Records every `unsafe` block, function, impl, or trait in a Rust source file. One finding is emitted per unsafe construct with the exact source span. This rule is **informational only** (severity: Info), designed to support manual security audits rather than flag a defect.

The analyzer uses the pre-extracted `RustAst` data from parsing; all unsafe-construct spans are computed at parse time with real byte offsets.

## Why it matters

Unsafe code in Rust bypasses the compiler's memory-safety guarantees and must be audited carefully. Security reviewers need a complete inventory of every unsafe construct in a codebase so that nothing is missed. This rule provides that inventory without requiring manual grepping or external tools.

## Configuration

No configuration knobs in v1.

## Examples — flagged

**Rust:**

```rust
/// Copies bytes using a raw pointer dereference.
pub unsafe fn raw_copy(dst: *mut u8, src: *const u8, n: usize) {
    // This unsafe function itself is flagged.
    unsafe {
        // This unsafe block is also flagged.
        ptr::copy_nonoverlapping(src, dst, n);
    }
}

unsafe trait Dangerous {
    // This unsafe trait is flagged.
    fn do_something();
}

struct Foo;
unsafe impl Dangerous for Foo {
    // This unsafe impl is flagged.
    fn do_something() {}
}
```

## Examples — not flagged

```rust
/// Safe code — no unsafe constructs.
pub fn safe_copy(dst: &mut [u8], src: &[u8]) {
    if dst.len() >= src.len() {
        dst[..src.len()].copy_from_slice(src);
    }
}
```

## Fix guidance

- **Document safety invariants:** For every `unsafe` block or function, add a `// SAFETY:` comment explaining the invariants that make the code sound.
- **Minimize scope:** Isolate unsafe code into the smallest possible block or function to reduce surface area.
- **Prefer safe abstractions:** Wrap unsafe code in a safe, well-documented public API so that users do not have to reason about safety directly.
- **Review thoroughly:** Unsafe code should be reviewed by someone familiar with Rust's memory model and the specific invariants being relied upon.
- **Add tests:** Write tests that exercise the unsafe code and catch edge cases (e.g., null pointers, alignment, overflow).

## Implementation

- Source: [`crates/zuit-lang-rust/src/analyzers/unsafe_block.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/unsafe_block.rs)

## References

- [Rust Reference: Unsafe Blocks](https://doc.rust-lang.org/reference/unsafe-blocks.html)
- [Rustonomicon: Unsafe Code](https://doc.rust-lang.org/nomicon/unsafe.html)
- [OWASP: Memory Corruption](https://owasp.org/www-community/attacks/Pointer_Subtraction)
