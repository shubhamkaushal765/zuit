---
title: PKG008-keywords-categories-missing
sidebar_label: PKG008-keywords-categories-missing
---
# PKG008-keywords-categories-missing

**Dimension:** `packaging`
**Default severity:** Low
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when `[package]` has **neither** `keywords` **nor** `categories`.

## Why it matters

Keywords and categories are the primary mechanisms for crate discovery on
crates.io.  Without them:

- The crate is invisible to users browsing by category.
- `cargo search` returns the crate only when users know its exact name.
- Automated dependency analysis tools cannot classify the crate.

## Example — flagged

```toml
[package]
name = "my-parser"
version = "1.0.0"
# No keywords or categories
```

## Example — not flagged

```toml
[package]
name = "my-parser"
version = "1.0.0"
keywords = ["parser", "toml", "configuration"]
categories = ["parser-implementations"]
```

## Fix guidance

Add up to five keywords and up to five category slugs:

```toml
keywords = ["parser", "toml", "config"]
categories = ["parser-implementations", "encoding"]
```

Browse the [crates.io category list](https://crates.io/categories) for valid
category slugs.

## Suppression

```toml
# zuit: ignore PKG008
[package]
name = "internal-crate"
```

## References

- [Cargo manifest: keywords](https://doc.rust-lang.org/cargo/reference/manifest.html#the-keywords-field)
- [Cargo manifest: categories](https://doc.rust-lang.org/cargo/reference/manifest.html#the-categories-field)
- [crates.io categories](https://crates.io/categories)
