---
title: API002 — signature-arity-changed
sidebar_label: API002
---
# API002 — signature-arity-changed

| Field | Value |
|---|---|
| **Rule ID** | `API002-signature-arity-changed` |
| **Family** | API Stability |
| **Severity** | Medium |
| **Kind** | `ProjectLevel` |
| **Dimension** | `api_stability` |

## Summary

A public function's total argument count (positional-only + regular + keyword-only)
changed between the baseline revision and `HEAD`.  This is a breaking change
for callers who use positional arguments or rely on the parameter count.

## Activation

This rule is **disabled by default**.  It activates only when a `baseline_ref`
is configured on the analyzer.

## Algorithm

1. Extract a `PublicApi` snapshot from the baseline.
2. Extract a `PublicApi` snapshot from HEAD.
3. For every public function present in **both** snapshots, compare total arity.
   If the counts differ, emit one `API002` finding.

Note: if a function is *removed entirely*, that is reported by `API001`, not
`API002`.

## Arity definition

Total arity = `posonly_count + args_count + kwonly_count`.  `*args` and
`**kwargs` are **not** counted (they cannot change in a breaking way by
themselves), but keyword-only parameters after `*` are included.

## Examples

### Violation

Baseline:
```python
def process(data: list, timeout: int = 30) -> None: ...
# total arity = 2
```

HEAD:
```python
def process(data: list) -> None: ...
# total arity = 1 — BREAKING
```

### Clean

Baseline and HEAD both define `process(data, timeout)` — no finding.

## Remediation

- Add the new parameter with a **default value** so existing callers are not
  broken.
- Or bump the **major** version before publishing an arity reduction.

## References

- [Semantic Versioning 2.0.0](https://semver.org/)
- [PEP 387 — Backwards Compatibility Policy](https://peps.python.org/pep-0387/)
