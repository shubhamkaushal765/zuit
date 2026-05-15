---
title: CI002-no-msrv-test-job
sidebar_label: CI002-no-msrv-test-job
---
# CI002-no-msrv-test-job

**Dimension:** `ci_release`
**Default severity:** Low
**Languages:** Rust (project-level)
**CWE:** (none)

## What it detects

Fires when:
- CI configuration exists (`.github/workflows/`, `.gitlab-ci.yml`, or `.circleci/config.yml`), **AND**
- `Cargo.toml` declares `rust-version = "…"` (the MSRV), **AND**
- No workflow file mentions the `rust-version` string anywhere.

Silently skipped when `rust-version` is absent from `Cargo.toml`.

## Why it matters

Declaring an MSRV in `Cargo.toml` commits to supporting that Rust version. Without a CI job that actually installs that toolchain and runs `cargo test`, the MSRV guarantee is purely nominal and can silently break as dependencies add newer language features.

## Heuristic limitations

This is a **best-effort substring match**: if the MSRV string appears anywhere in a workflow file (including in comments), the rule is suppressed. This may suppress true positives if the version string appears only in a comment. Always verify that an actual test job uses the MSRV toolchain.

## Example — flagged

```toml
# Cargo.toml
[package]
rust-version = "1.70"
```

Workflow file that never mentions `1.70`.

## Example — not flagged

```yaml
# .github/workflows/ci.yml
- uses: dtolnay/rust-toolchain@1.70  # MSRV check
  with:
    toolchain: "1.70"
```

## Fix guidance

Add a CI matrix entry that pins the MSRV toolchain:

```yaml
strategy:
  matrix:
    rust: [stable, "1.70"]  # Replace with your rust-version value
steps:
  - uses: dtolnay/rust-toolchain@${{ matrix.rust }}
  - run: cargo test --locked
```

## References

- [Cargo — rust-version field](https://doc.rust-lang.org/cargo/reference/manifest.html#the-rust-version-field)
- [dtolnay/rust-toolchain action](https://github.com/dtolnay/rust-toolchain)
