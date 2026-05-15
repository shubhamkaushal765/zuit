---
title: API003 — semver-alignment
sidebar_label: API003
---
# API003 — semver-alignment

| Field | Value |
|---|---|
| **Rule ID** | `API003-semver-alignment` |
| **Family** | API Stability |
| **Severity** | Low |
| **Kind** | `ProjectLevel` |
| **Dimension** | `api_stability` |

## Summary

The `pyproject.toml` version bump is inconsistent with the breaking-change
signal from `API001`/`API002`:

- **Case A** — Major bump (`N.x → (N+1).0`) with *no* breaking changes
  detected.  Was the major bump intentional?
- **Case B** — Breaking changes detected (`API001` or `API002` would fire) but
  the version bump is only patch or minor.  The change should be accompanied by
  a major bump.

Severity is **Low** because this is an alignment hint rather than a hard error.

## Activation

This rule is **disabled by default**.  It activates only when a `baseline_ref`
is configured on the analyzer.

## Algorithm

1. Parse the baseline and HEAD versions from `pyproject.toml`.
2. Determine whether there are breaking changes (removed symbols or arity
   changes) using the same logic as `API001`/`API002`.
3. Classify the version bump as major, minor, patch, or unchanged.
4. Emit if Case A or Case B applies.

## Pre-1.0 carve-out

Packages whose **baseline** version has a major component of `0`
(e.g. `0.9.0`) are **exempt** from this rule.  Semantic versioning explicitly
allows breaking changes in pre-1.0 packages at the author's discretion.

## Examples

### Case A — major bump without breaking change

Baseline `pyproject.toml`: `version = "1.5.0"`, HEAD `pyproject.toml`:
`version = "2.0.0"`.  Public API surface is identical.

Emits one `API003` Low: "Version bumped from 1.5.0 to 2.0.0 (major bump) but
no public API removals or arity changes were detected."

### Case B — breaking change without major bump

Baseline `pyproject.toml`: `version = "1.0.0"`.  HEAD removes a public
function.  HEAD `pyproject.toml`: `version = "1.1.0"`.

Emits one `API003` Low: "Breaking API changes detected but version only bumped
from 1.0.0 to 1.1.0 (patch/minor bump)."

### Clean

Major bump + breaking change: aligned.  No finding.

Minor bump + no breaking change: aligned.  No finding.

## Remediation

- For Case A: consider reverting to a minor or patch bump if no intentional
  breaking changes were made.
- For Case B: bump the major version before publishing.

## References

- [Semantic Versioning 2.0.0](https://semver.org/)
- [PEP 440 — Version Identification](https://peps.python.org/pep-0440/)
