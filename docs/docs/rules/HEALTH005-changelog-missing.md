---
title: HEALTH005-changelog-missing — Missing Changelog
sidebar_label: HEALTH005-changelog-missing
---
# HEALTH005-changelog-missing — Missing Changelog

**Dimension:** Project Health
**Default severity:** Low
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when no changelog file with non-trivial content (≥ 50 non-whitespace
bytes) is found at the project root.  The following filenames are recognised:

`CHANGELOG.md`, `CHANGELOG.rst`, `CHANGELOG.txt`, `CHANGELOG`,
`HISTORY.md`, `HISTORY.rst`, `HISTORY.txt`, `HISTORY`,
`CHANGES.md`, `CHANGES.rst`, `CHANGES.txt`, `CHANGES`.

## Why it matters

A changelog is a curated record of notable changes between releases.  Without
one, downstream consumers must read raw diffs or release notes to understand
what changed and whether upgrading is safe.  This slows adoption and reduces
trust in the project.

## Configuration

No configuration knobs in v1.  The 50-byte content threshold is compiled in.

## Example — flagged

A project root with only a `pyproject.toml` and source files but no changelog
triggers this rule.

A nearly-empty placeholder file (`# WIP\n`) also triggers it because it has
fewer than 50 non-whitespace bytes.

## Example — not flagged

```
project-root/
├── CHANGELOG.md     ← present with ≥ 50 non-whitespace bytes
├── pyproject.toml
└── src/
```

## Fix guidance

Create a `CHANGELOG.md` at the project root following the
[Keep a Changelog](https://keepachangelog.com) format:

```markdown
# Changelog

## [Unreleased]

## [1.0.0] - 2024-01-01
### Added
- Initial release.
```

Tooling options:
- [`towncrier`](https://towncrier.readthedocs.io/) — fragment-based changelog generation.
- [`git-cliff`](https://git-cliff.org/) — generates changelog from conventional commits.
- [`release-please`](https://github.com/googleapis/release-please) — automated GitHub releases.

## Suppression

Project-level analyzers do not read per-file `# zuit: ignore` directives.
Suppress via the engine's global ignore list in `zuit.toml`:

```toml
[ignore]
rules = ["HEALTH005-changelog-missing"]
```

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/health/health005_changelog_missing.rs`

## References

- [Keep a Changelog](https://keepachangelog.com)
- [towncrier documentation](https://towncrier.readthedocs.io/)
- [Conventional Commits](https://www.conventionalcommits.org/)
