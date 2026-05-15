---
title: PKG010-workspace-inheritance-broken
sidebar_label: PKG010-workspace-inheritance-broken
---
# PKG010-workspace-inheritance-broken

**Dimension:** `packaging`
**Default severity:** Medium
**Languages:** Rust (all projects)
**CWE:** (none)

## What it detects

Fires when `[package]` in `Cargo.toml` uses `key.workspace = true` (workspace
inheritance) on one or more keys, but the **same file has no `[workspace]`
table**.

This indicates a broken workspace setup: the crate tries to inherit values from
a workspace, but no workspace is defined in this file.  Cargo will reject the
build.

## Why it matters

Workspace key inheritance (`version.workspace = true`, `license.workspace = true`,
etc.) is only valid when the inheriting crate is a member of a workspace whose
root `Cargo.toml` defines `[workspace.package]`.  If the `[workspace]` section
is missing from this file, the build will fail with a confusing error message.

## Example — flagged

```toml
[package]
name = "my-crate"
version = { workspace = true }
license = { workspace = true }
# No [workspace] section in this file
```

## Example — not flagged

```toml
[package]
name = "my-crate"
version = { workspace = true }

[workspace]
members = ["."]

[workspace.package]
version = "1.2.3"
license = "MIT"
```

## Fix guidance

**Option A:** If this is the workspace root, add the `[workspace]` and
`[workspace.package]` sections:

```toml
[workspace]
members = [".", "crates/*"]

[workspace.package]
version = "1.0.0"
license = "MIT OR Apache-2.0"
```

**Option B:** If this is a member crate (not the root), remove the
`workspace = true` references and declare values directly:

```toml
[package]
name = "my-crate"
version = "1.0.0"
license = "MIT"
```

## Suppression

```toml
# zuit: ignore PKG010
[package]
name = "my-crate"
version = { workspace = true }
```

## References

- [Cargo: workspace inheritance](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-package-table)
- [Cargo manifest: workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html)
