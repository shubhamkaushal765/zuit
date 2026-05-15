---
title: CHAIN004 — unpinned-runtime-dep
sidebar_label: CHAIN004
---
# CHAIN004 — unpinned-runtime-dep

| Property | Value |
|----------|-------|
| **Rule ID** | `CHAIN004-unpinned-runtime-dep` |
| **Dimension** | `supply_chain` |
| **Severity** | Medium |
| **Analyzer kind** | `ProjectLevel` |

## What it detects

`CHAIN004` fires for each runtime dependency in `pyproject.toml` that has no
version constraint — specifically:

- PEP 621 style (`[project].dependencies`): a dependency string with no version
  operator (`>`, `<`, `=`, `~`, `!`), such as `"requests"` or
  `"requests[security]"`.
- Poetry style (`[tool.poetry.dependencies]`): a dependency whose version value
  is `"*"` or an empty string `""`.

### Not flagged (fine)

- `"requests>=2.31"` — has a lower bound
- `"requests>=2.0,<3"` — range constraint
- `"requests~=2.31"` — compatible release
- `"requests==2.31.0"` — exact pin
- Poetry: `requests = "^2.31"` — caret constraint

## Why it matters

An unconstrained dependency allows the package manager to install **any**
version, including future releases that may introduce:

- Breaking API changes.
- Security vulnerabilities.
- Malicious code (supply-chain compromise via a hijacked package).

Pinning at least a minimum version prevents surprise upgrades and makes the
dependency tree more auditable.

## How to fix

Add a version constraint to the dependency:

```toml
# PEP 621 — before (triggers CHAIN004):
[project]
dependencies = ["requests"]

# After:
[project]
dependencies = ["requests>=2.31"]
```

```toml
# Poetry — before (triggers CHAIN004):
[tool.poetry.dependencies]
requests = "*"

# After:
[tool.poetry.dependencies]
requests = "^2.31"
```

## Scope

This rule only inspects **runtime** dependencies.  Optional extras, dev
dependencies, and build-system requirements are out of scope.

## Suppression

Pyproject-anchored inline suppression is not currently parsed by the engine for
`ProjectLevel` rules.  To suppress, add the rule to the engine's global ignore
list:

```toml
[ignore]
rules = ["CHAIN004-unpinned-runtime-dep"]
```

## References

- [PEP 508 — Dependency specification](https://peps.python.org/pep-0508/)
- [PEP 621 — Storing project metadata in pyproject.toml](https://peps.python.org/pep-0621/)
- [Poetry dependency constraints](https://python-poetry.org/docs/dependency-specification/)
