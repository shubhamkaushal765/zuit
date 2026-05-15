---
title: PKG001-invalid-cargo-toml
sidebar_label: PKG001-invalid-cargo-toml
---
# PKG001-invalid-cargo-toml

**Dimension:** `packaging`
**Default severity:** High
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when `Cargo.toml` exists in the project root but **fails TOML parsing**.

A malformed `Cargo.toml` causes every Cargo command (`cargo build`, `cargo
check`, `cargo publish`) to fail with an opaque parse error.  Detecting this
early avoids CI mysteries.

## Why it matters

`Cargo.toml` is the single source of truth for the crate's dependencies,
features, and metadata.  If it cannot be parsed, the project is effectively
unbuildable.

## Example — flagged

```toml
[package
name = "my-crate"
version = "1.0.0"
```

(Missing closing `]` on the section header.)

## Example — not flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
edition = "2021"
```

## Fix guidance

Validate the file with a TOML linter:

```sh
taplo lint Cargo.toml
```

Or use `cargo metadata --no-deps` which will report the exact parse error with
line and column numbers.

## Suppression

Because this rule fires on files that **cannot** be parsed, engine-level
suppression (`# zuit: ignore PKG001`) in the file itself is not meaningful
(the parser never reaches that comment).  Fix the parse error instead.

## References

- [Cargo manifest format](https://doc.rust-lang.org/cargo/reference/manifest.html)
- [TOML specification](https://toml.io/en/v1.0.0)
