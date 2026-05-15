---
title: HEALTH003-low-bus-factor — Low Bus Factor
sidebar_label: HEALTH003-low-bus-factor
---
# HEALTH003-low-bus-factor — Low Bus Factor

**Dimension:** Project Health
**Default severity:** Medium
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when there are ≤ 2 distinct commit authors in the configured git history
window (`git_history_window_days`, default 365 days), as counted by author
email from `git log`.

## Why it matters

The bus factor (or "truck factor") of a project is the minimum number of
contributors whose sudden unavailability would put the project in jeopardy.
Projects with only one or two authors are extremely fragile:

- A single author leaving can immediately halt development.
- Knowledge is concentrated in one place and not shared.
- Downstream users face the risk of an unmaintained dependency.

## Configuration

`git_history_window_days` (default 365): look-back window for commit analysis.
`bus_factor_threshold` (default 2): projects with ≤ this many distinct authors
trigger the rule.  Config-table wiring is deferred to a later phase.

## Example — flagged

A repository where only `alice@example.com` and `bob@example.com` have made
commits in the last year triggers this rule (2 ≤ threshold of 2).

## Example — not flagged

A repository with three or more distinct author emails in the window passes
this check.

## Fix guidance

- Actively recruit contributors; respond promptly to pull requests.
- Split the project into smaller pieces with independent ownership.
- Write documentation that lets new contributors act without needing the
  original authors.
- Join an umbrella organisation (PSF, NumFOCUS, etc.) that can steward the
  project if primary authors step back.

## Suppression

Project-level analyzers do not read per-file `# zuit: ignore` directives.
Suppress via the engine's global ignore list in `zuit.toml`:

```toml
[ignore]
rules = ["HEALTH003-low-bus-factor"]
```

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/health/health003_low_bus_factor.rs`

## References

- [Bus factor — Wikipedia](https://en.wikipedia.org/wiki/Bus_factor)
- [OSSF Scorecard — Contributors](https://securityscorecards.dev/)
- [Truck Factor Tool](https://github.com/aserg-ufmg/Truck-Factor)
