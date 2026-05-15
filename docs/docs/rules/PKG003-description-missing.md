---
title: PKG003-description-missing
sidebar_label: PKG003-description-missing
---
# PKG003-description-missing

**Dimension:** `packaging`
**Default severity:** Low
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when `[package]` in `Cargo.toml` has no `description` key, or has an
empty/whitespace-only description string.

## Why it matters

The description is the one-line summary displayed on crates.io, in
`cargo search` results, and in IDE dependency pickers.  Without it, users
cannot quickly determine whether the crate meets their needs, reducing
discoverability.

## Example — flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
edition = "2021"
# No description
```

Empty description also fires:

```toml
description = ""
```

## Example — not flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
edition = "2021"
description = "A fast, ergonomic TOML parser for Rust."
```

## Fix guidance

Add a concise one-line description to `[package]`:

```toml
description = "A short, accurate summary of what the crate does."
```

Keep it under 200 characters.  Avoid starting with "A crate that…" — just
state what it does.

## Suppression

```toml
# zuit: ignore PKG003
[package]
name = "internal-tool"
```

## References

- [Cargo manifest: description](https://doc.rust-lang.org/cargo/reference/manifest.html#the-description-field)
