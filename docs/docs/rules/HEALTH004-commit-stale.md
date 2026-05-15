---
title: HEALTH004-commit-stale — Stale Commits
sidebar_label: HEALTH004-commit-stale
---
# HEALTH004-commit-stale — Stale Commits

**Dimension:** Project Health
**Default severity:** Low
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when the most recent commit within the history window is older than
`stale_commit_days` (default 180 days).

## Why it matters

A project with no commits for six months is likely unmaintained or on an
extended hiatus.  Downstream consumers who depend on such a project face:

- Unaddressed security vulnerabilities.
- Bug fixes that will never be released.
- Uncertainty about whether the project is still alive.

This check is intentionally low-severity because some stable, small projects
legitimately have infrequent commits; the finding should prompt investigation
rather than immediate alarm.

## Configuration

`stale_commit_days` (default 180): age threshold in days for the most recent
commit.  `git_history_window_days` (default 365): look-back window passed to
`git log --since`.  Config-table wiring is deferred to a later phase.

## Example — flagged

```
$ git log -1 --format="%aI"
2024-08-15T14:30:00+00:00
# Last commit is more than 180 days ago → HEALTH004 flagged
```

## Example — not flagged

A repository with a commit in the last 180 days passes this check.

## Fix guidance

- If the project is still maintained, push a commit (even a dependency
  update or documentation improvement) to signal activity.
- If the project is complete/stable, add a note to the README explaining
  its status to reassure downstream users.
- If the project is abandoned, consider archiving the repository on GitHub.

## Suppression

Project-level analyzers do not read per-file `# zuit: ignore` directives.
Suppress via the engine's global ignore list in `zuit.toml`:

```toml
[ignore]
rules = ["HEALTH004-commit-stale"]
```

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/health/health004_commit_stale.rs`

## References

- [GitHub — Archiving repositories](https://docs.github.com/en/repositories/archiving-a-github-repository)
- [OSSF Scorecard — Maintained](https://securityscorecards.dev/)
