---
title: PKG006-readme-missing
sidebar_label: PKG006-readme-missing
---
# PKG006-readme-missing

**Dimension:** `packaging`
**Default severity:** Low
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when **no README file** is found in the project root (`README.md`,
`README.rst`, `README.txt`, or `README`) AND `[package].readme` is not set.

## Why it matters

crates.io renders the README as the crate's landing page.  Without a README:

- Users have no entry-point documentation beyond rustdoc API reference.
- The crates.io page is empty, reducing adoption.

## Example — flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
# No readme key, and no README.md file in the project root
```

## Example — not flagged

A `README.md` file exists in the project root (auto-detected), **or**:

```toml
[package]
name = "my-crate"
version = "1.0.0"
readme = "DOCS.md"
```

## Fix guidance

Create a `README.md` in the project root with at minimum: a one-line description,
a quick-start code example, and a link to the docs.rs documentation.

## Suppression

```toml
# zuit: ignore PKG006
[package]
name = "internal-tool"
```

## References

- [Cargo manifest: readme](https://doc.rust-lang.org/cargo/reference/manifest.html#the-readme-field)
