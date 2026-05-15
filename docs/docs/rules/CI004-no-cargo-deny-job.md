---
title: CI004-no-cargo-deny-job
sidebar_label: CI004-no-cargo-deny-job
---
# CI004-no-cargo-deny-job

**Dimension:** `ci_release`
**Default severity:** Low
**Languages:** Rust (project-level)
**CWE:** (none)

## What it detects

Fires when CI configuration exists **and** no workflow file mentions `cargo deny` or `EmbarkStudios/cargo-deny-action`.

## Why it matters

`cargo deny` enforces:
- **License compliance** — ensures all dependencies use approved licenses.
- **Dependency bans** — blocks unwanted or vulnerable packages.
- **Security advisories** — checks against the RustSec advisory database.
- **Source restrictions** — limits where dependencies come from.

Without a CI job running `cargo deny`, these checks can silently regress as the dependency tree changes.

## Example — flagged

CI exists but only runs `cargo test` and `cargo clippy`.

## Example — not flagged

```yaml
- run: cargo deny check
```

Or:

```yaml
- uses: EmbarkStudios/cargo-deny-action@v1
```

## Fix guidance

Add `cargo deny` to your CI workflow:

```yaml
- name: cargo deny
  run: cargo deny check
```

Or use the managed action:

```yaml
- uses: EmbarkStudios/cargo-deny-action@v1
  with:
    command: check
    arguments: --all-features
```

Install `cargo deny` with:

```sh
cargo install cargo-deny --locked
```

## References

- [cargo-deny documentation](https://embarkstudios.github.io/cargo-deny/)
- [EmbarkStudios/cargo-deny-action](https://github.com/EmbarkStudios/cargo-deny-action)
