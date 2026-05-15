---
title: HEALTH001-single-author — Single-Author Dominance
sidebar_label: HEALTH001-single-author
---
# HEALTH001-single-author — Single-Author Dominance

**Dimension:** Project Health
**Default severity:** Medium
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when one author is responsible for more than 50% of commits in the
configured git history window (`git_history_window_days`, default 365 days).

## Why it matters

A project where a single contributor dominates the commit history carries a
high bus-factor risk.  If that author becomes unavailable—through illness,
job change, or loss of interest—the project may stall, leaving downstream
users stranded on an unmaintained dependency.

## Configuration

`git_history_window_days` (default 365): look-back window for commit analysis.
Config-table wiring is deferred to a later phase; the default is currently
compiled in.

## Example — flagged

A repository where one email address authored 45 of the last 50 commits
triggers this rule.

## Example — not flagged

A repository where no single author exceeds 50% of commits in the window
passes this check.

## Fix guidance

- Actively invite trusted contributors to become co-maintainers.
- Lower the barrier to first contributions: add a `CONTRIBUTING.md`, label
  beginner-friendly issues, and respond promptly to pull requests.
- Document the release and review process so new maintainers can act
  independently.
- Consider joining an open-source umbrella organisation.

## Suppression

Project-level analyzers do not read per-file `# zuit: ignore` directives.
Suppress via the engine's global ignore list in `zuit.toml`:

```toml
[ignore]
rules = ["HEALTH001-single-author"]
```

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/health/health001_single_author.rs`

## Git unavailability

When git is unavailable (no `.git` directory, `git` binary missing, timeout),
this analyzer emits a single `HEALTH/git-unavailable` Info finding.  The
remaining HEALTH analyzers (HEALTH002–HEALTH004) stay silent in that case to
avoid repeating the notice.

## References

- [Bus factor — Wikipedia](https://en.wikipedia.org/wiki/Bus_factor)
- [OSSF Scorecard — Contributors](https://securityscorecards.dev/)
