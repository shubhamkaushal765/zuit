---
title: PKG007-version-mismatch
sidebar_label: PKG007-version-mismatch
---
# PKG007-version-mismatch

**Dimension:** `packaging`
**Default severity:** Medium
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when `[package].version` in `Cargo.toml` **differs from the latest git
tag** (matching `vX.Y.Z` or `X.Y.Z` format).

If no `.git` directory exists, or `git` is not on `$PATH`, or no version tags
exist, the rule skips silently.

## Why it matters

A mismatch between the crate version and the git tag means:

- A release may have been tagged without bumping the version (or vice versa).
- `cargo publish` will publish a version that does not correspond to any tag.
- Users cloning the tag get different code than users installing from crates.io.

## Example — flagged

`Cargo.toml`:
```toml
[package]
version = "1.2.3"
```

Latest git tag: `v1.2.2`  → mismatch, finding emitted.

## Example — not flagged

`Cargo.toml`:
```toml
[package]
version = "1.2.3"
```

Latest git tag: `v1.2.3`  → match, no finding.

## Fix guidance

Before publishing, ensure the git tag matches the `Cargo.toml` version:

```sh
git tag v1.2.3
git push origin v1.2.3
```

Or bump the version in `Cargo.toml` to match the existing tag.

## Suppression

```toml
# zuit: ignore PKG007
[package]
version = "0.0.0-dev"
```

## References

- [Cargo: publishing a crate](https://doc.rust-lang.org/cargo/reference/publishing.html)
