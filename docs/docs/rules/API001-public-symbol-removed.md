---
title: API001 — public-symbol-removed
sidebar_label: API001
---
# API001 — public-symbol-removed

| Field | Value |
|---|---|
| **Rule ID** | `API001-public-symbol-removed` |
| **Family** | API Stability |
| **Severity** | High |
| **Kind** | `ProjectLevel` |
| **Dimension** | `api_stability` |

## Summary

A public function or class that was present in the baseline revision is absent
in `HEAD`.  Removing a public symbol is a breaking change for any downstream
caller.

## Activation

This rule is **disabled by default**.  It activates only when a `baseline_ref`
is configured on the analyzer (the wiring of `[python.api] baseline_ref` from
the global config is deferred to a later phase).

## Algorithm

1. Extract a `PublicApi` snapshot from the baseline (git ref or injected).
2. Extract a `PublicApi` snapshot from the HEAD project directory.
3. For every public function or class name present in the baseline but absent
   in HEAD, emit one `API001` finding.

Public symbols are defined as top-level `def`, `async def`, or `class`
statements whose name does **not** start with `_`, **unless** the module
declares `__all__` — in that case the `__all__` list is authoritative.

## Examples

### Violation

Baseline:
```python
def create_user(name: str) -> User: ...
class UserRepository: ...
```

HEAD:
```python
# create_user and UserRepository removed
```

Emits two `API001` findings.

### Clean

Baseline and HEAD both define `create_user` and `UserRepository` — no findings.

## Remediation

Either:
- Restore the removed symbol (or provide a compatibility shim), or
- Bump the **major** version number before publishing the removal.

## Pre-1.0 note

For packages whose version is `< 1.0.0`, consider using `API003` to check
semver alignment; `API001` still fires for those packages because the removal
itself is factual.

## References

- [Semantic Versioning 2.0.0](https://semver.org/)
- [PEP 387 — Backwards Compatibility Policy](https://peps.python.org/pep-0387/)
