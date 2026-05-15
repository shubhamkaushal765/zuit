---
title: CI003-no-windows-job
sidebar_label: CI003-no-windows-job
---
# CI003-no-windows-job

**Dimension:** `ci_release`
**Default severity:** Low
**Languages:** Rust (project-level)
**CWE:** (none)

## What it detects

Fires when CI configuration exists **and** no workflow file mentions a Windows runner: `windows-latest`, `windows-2019`, or `windows-2022`.

## Why it matters

Path separator differences (`/` vs `\`), FFI ABI differences, and Windows-specific API behaviour can cause failures that only appear on Windows. Crates published on crates.io are expected to work cross-platform; without a Windows CI job, platform-specific bugs may reach users.

## Example — flagged

```yaml
# Only Ubuntu runner
runs-on: ubuntu-latest
```

## Example — not flagged

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest, macos-latest]
runs-on: ${{ matrix.os }}
```

## Fix guidance

Add a Windows runner to your CI matrix:

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
runs-on: ${{ matrix.os }}
steps:
  - uses: actions/checkout@v4
  - uses: dtolnay/rust-toolchain@stable
  - run: cargo test --locked
```

## References

- [GitHub-hosted runners](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners)
- [Cross-platform Rust](https://doc.rust-lang.org/cargo/reference/config.html)
