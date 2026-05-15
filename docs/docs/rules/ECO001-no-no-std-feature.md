---
title: ECO001-no-no-std-feature
sidebar_label: ECO001-no-no-std-feature
---
# ECO001-no-no-std-feature

**Dimension:** `ecosystem`
**Default severity:** Low
**Languages:** Rust (project-level)
**CWE:** (none)

## What it detects

Fires when:
- The project declares a `[lib]` section in `Cargo.toml`, **or** has `src/lib.rs`, **AND**
- The `[features]` table is absent **or** contains no key matching `no_std`, `no-std`, `alloc`, or `std`.

## Why it matters

Library crates that want to support `#![no_std]` environments (embedded systems, WASM, OS kernels) must expose a feature gate so downstream consumers can disable the standard library. Without it, using the crate in `no_std` contexts requires vendoring or patching.

Even if the crate has no immediate `no_std` users, declaring a `std` feature gate early is best practice and costs nothing.

## Example — flagged

```toml
[package]
name = "mylib"
version = "1.0.0"

[lib]
# No [features] table — no no_std story
```

## Example — not flagged

```toml
[package]
name = "mylib"
version = "1.0.0"

[lib]

[features]
default = ["std"]
std = []
no_std = []
```

## Fix guidance

Add a `[features]` table with at least a `std` and/or `no_std` gate, then guard `std`-requiring items:

```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std::collections::HashMap;
```

## Suppression

```toml
# Cargo.toml
# zuit: ignore ECO001-no-no-std-feature
[lib]
```

## References

- [Cargo features reference](https://doc.rust-lang.org/cargo/reference/features.html)
- [The Embedded Rust Book — no_std](https://docs.rust-embedded.org/book/intro/no-std.html)
