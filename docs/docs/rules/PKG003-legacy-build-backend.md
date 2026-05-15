---
title: PKG003-legacy-build-backend — Legacy `setup.py`-only Project
sidebar_label: PKG003-legacy-build-backend
---
# PKG003-legacy-build-backend — Legacy `setup.py`-only Project

**Dimension:** Packaging
**Default severity:** Medium
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when a `setup.py` file exists at the project root **and** no
`pyproject.toml` is present. This combination indicates that the project uses
the legacy `distutils`/`setuptools` build path.

Note: if both `setup.py` and `pyproject.toml` are present, no finding is
emitted — transitional projects that keep `setup.py` for backward compatibility
while adopting `pyproject.toml` are accepted.

## Why it matters

The `setup.py`-only build path is deprecated. Python packaging has standardized
on `pyproject.toml` (PEP 517/518/621). Projects relying solely on `setup.py`:

- Cannot use `pip install --no-build-isolation` reliably.
- Are excluded from modern build tools (`hatch`, `flit`, `poetry`, `uv`).
- Will break as `distutils` is removed from the standard library (Python 3.12+).

## Configuration

No configuration knobs in v1.

## Example — flagged

Project structure:
```
my-project/
  setup.py        ← exists
  my_package/
    __init__.py
```

## Example — not flagged

Project structure with `pyproject.toml`:
```
my-project/
  pyproject.toml  ← present
  setup.py        ← kept for compatibility (no finding)
  my_package/
    __init__.py
```

## Fix guidance

1. Add a `pyproject.toml` with `[build-system]` and `[project]` tables.
2. Gradually remove `setup.py` once all users have migrated to `pip >= 21.3`.

```toml
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "my-package"
version = "1.0.0"
```

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/pkg/pkg003_legacy_build_backend.rs`

## References

- [PEP 517 – A build-system independent format for source trees](https://peps.python.org/pep-0517/)
- [Python packaging user guide: modern build backends](https://packaging.python.org/en/latest/tutorials/packaging-projects/)
