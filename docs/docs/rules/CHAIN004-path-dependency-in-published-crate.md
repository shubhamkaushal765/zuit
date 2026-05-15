---
title: CHAIN004 — path-dependency-in-published-crate
sidebar_label: CHAIN004
---
# CHAIN004 — path-dependency-in-published-crate

| Property | Value |
|----------|-------|
| **Rule ID** | `CHAIN004-path-dependency-in-published-crate` |
| **Dimension** | `supply_chain` |
| **Severity** | Medium |
| **Analyzer kind** | `ProjectLevel` |
| **Languages** | Rust (all projects) |

## What it detects

`CHAIN004` fires for each entry in `[dependencies]` or `[dev-dependencies]` that
has a `path = "..."` key **without** a sibling `version = "..."` key.

```toml
# Flagged — path-only, no version
my-local = { path = "../my-local" }
```

## Why it matters

`cargo publish` refuses to publish a crate that contains path-only dependencies.
Users who install the crate from crates.io cannot resolve a local `path`
reference — it only exists on the developer's machine.

Without a `version` key, the crate is simply unpublishable, and any CI pipeline
that runs `cargo publish --dry-run` will fail with an error like:

```
error: all path dependencies must have a version specified when publishing
```

Additionally, path-only dependencies create supply-chain ambiguity: there is no
registry record of the dependency, and `cargo audit` cannot check it for
advisories.

## Examples — flagged

```toml
[dependencies]
my-utils = { path = "../my-utils" }

[dev-dependencies]
test-fixtures = { path = "../test-fixtures" }
```

## Examples — not flagged

```toml
[dependencies]
# Both path (for local dev) and version (for registry consumers) are present.
my-utils = { path = "../my-utils", version = "^1.0" }
```

## How to fix

Add a `version` key alongside the `path`:

```toml
my-utils = { path = "../my-utils", version = "^1.0" }
```

When the `version` key is present:
- Local development uses the `path` version.
- Published consumers resolve via the crates.io registry version.

Ensure the crate at the path and the version declared in `Cargo.toml` stay in
sync.

## Suppression

To suppress for a project that intentionally uses path-only dependencies (e.g.
a private workspace that will never be published), add the rule to the engine's
ignore list:

```toml
[ignore]
rules = ["CHAIN004-path-dependency-in-published-crate"]
```

## References

- [Cargo: Specifying path dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)
- [cargo publish documentation](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)
- [Cargo workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html)
