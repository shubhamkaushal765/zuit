---
title: PKG004-repository-missing
sidebar_label: PKG004-repository-missing
---
# PKG004-repository-missing

**Dimension:** `packaging`
**Default severity:** Low
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when `[package]` in `Cargo.toml` has no `repository` key.

## Why it matters

Without a repository link:

- Users cannot find the source code to audit, fork, or contribute to.
- Security teams cannot locate the issue tracker to report vulnerabilities.
- crates.io displays no "Repository" link on the crate's page.

## Example — flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
edition = "2021"
license = "MIT"
# No repository key
```

## Example — not flagged

```toml
[package]
name = "my-crate"
version = "1.0.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/my-org/my-crate"
```

## Fix guidance

Add the canonical URL of the source repository to `[package]`:

```toml
repository = "https://github.com/your-org/your-crate"
```

## Suppression

```toml
# zuit: ignore PKG004
[package]
name = "private-crate"
```

## References

- [Cargo manifest: repository](https://doc.rust-lang.org/cargo/reference/manifest.html#the-repository-field)
