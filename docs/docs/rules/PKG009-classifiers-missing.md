---
title: PKG009-classifiers-missing — Missing PyPI Classifiers
sidebar_label: PKG009-classifiers-missing
---
# PKG009-classifiers-missing — Missing PyPI Classifiers

**Dimension:** Packaging
**Default severity:** Low
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when `[project]` in `pyproject.toml` has no `classifiers` field **or**
has a `classifiers` array that does not contain at least one
`Programming Language :: Python :: 3` (or `3.x`) classifier.

## Why it matters

PyPI classifiers are metadata tags that:

- Allow users to filter packages by Python version, OS, topic, and development
  status on the PyPI search interface.
- Signal to `pip` (and other resolvers) which Python versions and
  implementations are supported.
- Enable automated tooling (bandersnatch, devpi, pip's `--python-requires`
  filtering) to correctly handle compatibility.

A package without a Python version classifier will not appear in version-
filtered searches and cannot benefit from pip's interpreter-compatibility checks.

## Configuration

No configuration knobs in v1.

## Example — flagged

```toml
[project]
name = "my-package"
version = "1.0.0"
# No classifiers at all — flagged
```

```toml
[project]
name = "my-package"
version = "1.0.0"
classifiers = [
    "License :: OSI Approved :: MIT License",
    # No Python version classifier — flagged
]
```

## Example — not flagged

```toml
[project]
name = "my-package"
version = "1.0.0"
classifiers = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.11",
    "License :: OSI Approved :: MIT License",
]
```

## Fix guidance

Add a `classifiers` array to `[project]` with at minimum a Python version
classifier and a development status classifier:

```toml
[project]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]
```

The full list of valid classifiers is available at
[pypi.org/classifiers/](https://pypi.org/classifiers/).

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/pkg/pkg009_classifiers_missing.rs`

## References

- [PyPI classifiers](https://pypi.org/classifiers/)
- [Classifier specification](https://packaging.python.org/en/latest/specifications/classifiers/)
