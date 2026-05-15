---
title: CHAIN003 — git-dependency-without-rev
sidebar_label: CHAIN003
---
# CHAIN003 — git-dependency-without-rev

| Property | Value |
|----------|-------|
| **Rule ID** | `CHAIN003-git-dependency-without-rev` |
| **Dimension** | `supply_chain` |
| **Severity** | Medium |
| **Analyzer kind** | `ProjectLevel` |
| **Languages** | Rust (all projects) |

## What it detects

`CHAIN003` fires for each entry in `[dependencies]` or `[dev-dependencies]` that
has a `git = "..."` key **without** a `rev = "..."` or `tag = "..."` sibling key.

A `branch`-only git dependency is considered unpinned:

```toml
# Flagged — branch tip moves between builds
mycrate = { git = "https://github.com/example/mycrate", branch = "main" }

# Flagged — no pin at all
mycrate = { git = "https://github.com/example/mycrate" }
```

## Why it matters

A git dependency without a stable pin (`rev` or `tag`) resolves to whatever
commit the branch points at **at build time**.  Two builds on different days
may resolve to different commits, making the build non-reproducible.

More critically, if the upstream repository is compromised or the branch is
force-pushed, a dependency that was previously benign could introduce malicious
code into your build without any change to `Cargo.toml`.

## Examples — flagged

```toml
[dependencies]
my-lib = { git = "https://github.com/example/my-lib" }
other-lib = { git = "https://github.com/example/other", branch = "dev" }
```

## Examples — not flagged

```toml
[dependencies]
# Pinned by commit hash (preferred)
my-lib = { git = "https://github.com/example/my-lib", rev = "a1b2c3d4" }

# Pinned by tag (acceptable)
other-lib = { git = "https://github.com/example/other", tag = "v1.2.3" }
```

## How to fix

Identify the exact commit you want to use and pin it with `rev`:

```sh
git ls-remote https://github.com/example/my-lib HEAD
# Copy the SHA and add: rev = "<sha>"
```

Or use a specific tagged release:

```toml
my-lib = { git = "https://github.com/example/my-lib", tag = "v1.2.3" }
```

When the upstream crate is published on crates.io, prefer using the registry
version instead of a git dependency — this gives you reproducible resolution
with `Cargo.lock` and access to `cargo audit` advisories.

## Suppression

To suppress globally for a project, add the rule to the engine's ignore list:

```toml
[ignore]
rules = ["CHAIN003-git-dependency-without-rev"]
```

## References

- [Cargo: Specifying dependencies from git repositories](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories)
- [Cargo.lock and reproducible builds](https://doc.rust-lang.org/cargo/faq.html#why-do-binaries-have-cargolock-in-version-control-but-not-libraries)
