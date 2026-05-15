---
title: ECO003-send-sync-violations-on-pub-types
sidebar_label: ECO003-send-sync-violations-on-pub-types
---
# ECO003-send-sync-violations-on-pub-types

**Dimension:** `ecosystem`
**Default severity:** Low
**Languages:** Rust (file-level)
**CWE:** (none)

## What it detects

Fires when a `pub struct` contains a raw pointer field (`*mut T` or `*const T`) without an `unsafe impl Send` declaration in the same file.

Raw pointers are not `Send` by default. A public struct containing a raw pointer that is neither `Send` nor documented as non-`Send` is a usability hazard: downstream consumers cannot share it across threads without unsafe code.

## Heuristic limitations

- **File-wide suppression:** if *any* `unsafe impl Send` appears anywhere in the file, the rule is suppressed for the entire file. This may miss structs in the same file that lack `Send` implementations.
- **`Sync` is not checked** — only `Send`.
- Wrapping types (e.g. `NonNull<T>`, `AtomicPtr<T>`) that are safe to send are not recognized; they appear as raw pointer wrappers.

Always review findings manually.

## Example — flagged

```rust
pub struct Buffer {
    ptr: *mut u8,
    len: usize,
}
// No unsafe impl Send — downstream users cannot share Buffer across threads
```

## Example — not flagged

```rust
pub struct Buffer {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: Buffer owns the pointer and provides exclusive access via &mut self
unsafe impl Send for Buffer {}
```

## Fix guidance

Add `unsafe impl Send for YourStruct {}` with a `// SAFETY:` comment explaining the invariants, or change the raw pointer to a wrapper type that is `Send` by default (e.g. `NonNull<T>` is `!Send`, but `AtomicPtr<T>` is `Send`).

## Suppression

```rust
// zuit: ignore ECO003-send-sync-violations-on-pub-types
pub struct Buffer { ptr: *mut u8, len: usize }
```

## References

- [The Rustonomicon — Send and Sync](https://doc.rust-lang.org/nomicon/send-and-sync.html)
- [std::marker::Send](https://doc.rust-lang.org/std/marker/trait.Send.html)
