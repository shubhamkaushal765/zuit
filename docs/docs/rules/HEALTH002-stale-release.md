---
title: HEALTH002-stale-release — Stale Release
sidebar_label: HEALTH002-stale-release
---
# HEALTH002-stale-release — Stale Release

**Dimension:** Project Health
**Default severity:** Medium
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when:
- no git tag exists in the repository, **or**
- the most recent git tag is older than `stale_release_days` (default 365 days).

Tag dates are read from `git tag --sort=-creatordate`; no network calls are made.

## Why it matters

A release cadence signals active maintenance.  Projects that have not tagged a
release in over a year may be abandoned, meaning:
- Security vulnerabilities accumulate without patches.
- Bug fixes are never shipped to downstream users.
- Downstream consumers cannot safely pin a stable version.

## Configuration

`stale_release_days` (default 365): number of days since the last tag before
the project is considered stale.  Config-table wiring is deferred to a later
phase; the default is currently compiled in.

## Example — flagged

```
$ git tag --sort=-creatordate | head -1
v1.4.2
$ git log -1 --format="%aI" v1.4.2
2023-12-01T10:00:00+00:00
# More than 365 days ago → HEALTH002 flagged
```

## Example — not flagged

A repository with a tag created within the last 365 days passes this check.

## Fix guidance

- Tag your next release: `git tag vX.Y.Z && git push --tags`.
- If the project is intentionally in maintenance-only mode, document this in
  the README and consider archiving the repository.
- Set up automated release tooling (e.g. `release-please`, `semantic-release`)
  to reduce the friction of tagging.

## Suppression

Project-level analyzers do not read per-file `# zuit: ignore` directives.
Suppress via the engine's global ignore list in `zuit.toml`:

```toml
[ignore]
rules = ["HEALTH002-stale-release"]
```

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/health/health002_stale_release.rs`

## References

- [Keep a Changelog](https://keepachangelog.com)
- [Semantic Versioning](https://semver.org)
