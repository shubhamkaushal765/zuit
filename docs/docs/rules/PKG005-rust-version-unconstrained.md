---
title: PKG005-rust-version-unconstrained
sidebar_label: PKG005-rust-version-unconstrained
---
# PKG005-rust-version-unconstrained

**Dimension:** `packaging`
**Default severity:** Low
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when `[package]` in `Cargo.toml` has no `rust-version` key (also called
the Minimum Supported Rust Version, or MSRV).

## Why it matters

Without a declared MSRV:

- Users with older Rust toolchains encounter confusing build errors.
- Dependents that need to support an older toolchain cannot determine
  compatibility without manual testing.
- CI cannot automatically test the MSRV.

## Example — flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
edition = "2021"
# No rust-version
```

## Example — not flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
edition = "2021"
rust-version = "1.70"
```

Workspace inheritance is also accepted:

```toml
[package]
rust-version.workspace = true
```

## Fix guidance

Determine the oldest Rust version your crate compiles with and add it:

```toml
rust-version = "1.70"
```

Test the MSRV in CI:

```yaml
- uses: dtolnay/rust-toolchain@master
  with:
    toolchain: "1.70"
- run: cargo check
```

## Suppression

```toml
# zuit: ignore PKG005
[package]
name = "my-crate"
```

## References

- [Cargo manifest: rust-version](https://doc.rust-lang.org/cargo/reference/manifest.html#the-rust-version-field)
- [The MSRV policy guide](https://doc.rust-lang.org/cargo/reference/rust-version.html)
