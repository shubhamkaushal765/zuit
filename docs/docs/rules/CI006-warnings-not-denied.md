---
title: CI006-warnings-not-denied
sidebar_label: CI006-warnings-not-denied
---
# CI006-warnings-not-denied

| Property | Value |
|----------|-------|
| Dimension | `ci_release` |
| Severity | Low |
| Languages | Rust (project-level) |
| CWE | [CWE-1127](https://cwe.mitre.org/data/definitions/1127.html) |

## What it detects

Fires when CI configuration exists **and** neither of the following is present:

- `[workspace.lints.rust]` or `[lints.rust]` in `Cargo.toml` with `warnings = "deny"` or `warnings = "forbid"`
- A CI workflow file that sets `RUSTFLAGS=-D warnings` (or `-Dwarnings`) or `RUSTDOCFLAGS=-D warnings`

## Why it matters

By default, Rust compiler warnings do not fail a build.  Without an explicit deny, warning
regressions accumulate silently across CI runs and reach production unnoticed.  Denying warnings
forces every contributor and every CI run to keep the codebase warning-free, making it much
harder for latent correctness issues or dead code to hide in plain sight.

[CWE-1127](https://cwe.mitre.org/data/definitions/1127.html) ("Compilation with Insufficient
Warnings or Errors") captures the class of defects where a build artifact is shipped despite
compiler diagnostics that, if treated as errors, would have caught the issue at build time.

## Example — flagged

`Cargo.toml` has only a `[package]` table and the CI workflow does not set `RUSTFLAGS`:

```yaml
# .github/workflows/ci.yml
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test
```

```toml
# Cargo.toml — no [lints] table
[package]
name = "my-crate"
version = "0.1.0"
```

## Example — not flagged

### Option A — Cargo.toml lints (preferred, Cargo 1.74+)

```toml
[workspace.lints.rust]
warnings = "deny"
```

### Option B — CI environment variable

```yaml
jobs:
  test:
    env:
      RUSTFLAGS: -D warnings
    steps:
      - run: cargo test
```

## Fix guidance

**Preferred (Cargo 1.74+):** add the following to your workspace `Cargo.toml`:

```toml
[workspace.lints.rust]
warnings = "deny"
```

This propagates to all workspace members automatically and works independently of the CI
provider.

**Alternative:** set the environment variable in your CI workflow:

```yaml
env:
  RUSTFLAGS: -D warnings
```

Using both is redundant but harmless.

## References

- [CWE-1127 — Compilation with Insufficient Warnings or Errors](https://cwe.mitre.org/data/definitions/1127.html)
- [Cargo manifest — `[lints]` section](https://doc.rust-lang.org/cargo/reference/manifest.html#the-lints-section)
- [The `rustflags` config key](https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags)
