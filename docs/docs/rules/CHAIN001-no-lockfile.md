---
title: CHAIN001 — no-lockfile
sidebar_label: CHAIN001
---
# CHAIN001 — no-lockfile

| Property | Value |
|----------|-------|
| **Rule ID** | `CHAIN001-no-lockfile` |
| **Dimension** | `supply_chain` |
| **Severity** | Medium |
| **Analyzer kind** | `ProjectLevel` |

## What it detects

`CHAIN001` fires when a `pyproject.toml` is present at the project root but no
recognised lock file exists alongside it.

Recognised lock files (any of the following satisfies the rule):

- `poetry.lock`
- `uv.lock`
- `pdm.lock`
- Any file matching `requirements*.txt` (e.g. `requirements.txt`,
  `requirements-dev.txt`, `requirements-prod.txt`)

## Why it matters

Without a lock file, every `pip install` or equivalent resolves dependency
versions at install time.  This means:

- Builds are non-deterministic across machines and over time.
- A future release of any transitive dependency can introduce a breaking change
  or, in the worst case, a supply-chain compromise.

Lock files record the exact version of every dependency (direct and transitive)
so that all environments reproduce the same resolved graph.

## How to fix

Generate a lock file with your package manager:

```sh
# Poetry
poetry lock

# uv
uv lock

# PDM
pdm lock

# pip-tools
pip-compile requirements.in
```

Then commit the generated lock file to version control.

## Suppression

Pyproject-anchored inline suppression (`# zuit: ignore CHAIN001`) is not
currently parsed by the engine for `ProjectLevel` rules.  To suppress, add the
rule to the engine's global ignore list in `.zuit/config.toml`:

```toml
[ignore]
rules = ["CHAIN001-no-lockfile"]
```

## References

- [pip-tools documentation](https://pip-tools.readthedocs.io/)
- [uv lock documentation](https://docs.astral.sh/uv/concepts/projects/)
- [Poetry lock file](https://python-poetry.org/docs/basic-usage/#installing-without-poetrylock)
