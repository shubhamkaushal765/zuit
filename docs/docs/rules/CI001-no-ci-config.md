---
title: CI001-no-ci-config
sidebar_label: CI001-no-ci-config
---
# CI001-no-ci-config

**Dimension:** `ci_release`
**Default severity:** Medium
**Languages:** Rust (project-level)
**CWE:** (none)

## What it detects

No CI configuration is found in the project root. Checks for:

- `.github/workflows/*.yml` or `.github/workflows/*.yaml`
- `.gitlab-ci.yml`
- `.circleci/config.yml`

## Why it matters

A project without CI has no automated test gate. Bugs, test failures, and regressions may go undetected before release. For crates published on crates.io, CI is the primary signal of active maintenance.

## Example — flagged

Project root with no CI configuration file.

## Example — not flagged

```
.github/workflows/ci.yml
```

## Fix guidance

Add a GitHub Actions workflow that runs `cargo test` and `cargo clippy` on every push:

```yaml
# .github/workflows/ci.yml
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --locked
      - run: cargo clippy -- -D warnings
```

## References

- [GitHub Actions for Rust](https://docs.github.com/en/actions)
- [dtolnay/rust-toolchain action](https://github.com/dtolnay/rust-toolchain)
