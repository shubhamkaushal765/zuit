---
title: PKG002-license-not-declared
sidebar_label: PKG002-license-not-declared
---
# PKG002-license-not-declared

**Dimension:** `packaging`
**Default severity:** Medium
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when `[package]` in `Cargo.toml` has **neither** a `license` key nor a
`license-file` key.

## Why it matters

A crate without a declared license is legally "all rights reserved" under the
laws of most jurisdictions.  This means organisations cannot legally incorporate
the crate into their products, regardless of how the source code is distributed.
crates.io will warn about missing licenses and may refuse to publish in future
versions of its policies.

## Example — flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
edition = "2021"
# No license key
```

## Example — not flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
edition = "2021"
license = "MIT OR Apache-2.0"
```

Or using a license file:

```toml
[package]
name = "my-crate"
version = "1.0.0"
license-file = "LICENSE"
```

## Fix guidance

Add an SPDX license expression to `[package]`:

```toml
license = "MIT OR Apache-2.0"
```

The Rust ecosystem convention is to dual-license under MIT and Apache-2.0.  See
the [SPDX license list](https://spdx.org/licenses/) for valid identifiers.

## Suppression

```toml
# zuit: ignore PKG002
[package]
name = "internal-only"
```

## References

- [Cargo manifest: license](https://doc.rust-lang.org/cargo/reference/manifest.html#the-license-and-license-file-fields)
- [SPDX license list](https://spdx.org/licenses/)
- [crates.io publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html)
