---
title: PKG002-metadata-incomplete — Missing Required Metadata
sidebar_label: PKG002-metadata-incomplete
---
# PKG002-metadata-incomplete — Missing Required Metadata

**Dimension:** Packaging
**Default severity:** Medium
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when `pyproject.toml` is missing the `[project]` table entirely, or when
the `[project]` table is present but lacks the required `name` field, or lacks
`version` without listing it in `dynamic`.

## Why it matters

PEP 621 requires `name` and `version` (or `dynamic = ["version"]`) in
`[project]`. Without `name`, the package cannot be installed or referenced by
name. Without `version`, build tools produce a distribution with no version
string, which confuses `pip`, PyPI, and downstream dependency resolvers.

## Configuration

No configuration knobs in v1.

## Example — flagged

```toml
# Missing both name and version
[project]
description = "A useful library"
```

## Example — not flagged

```toml
[project]
name = "my-package"
version = "1.0.0"
```

```toml
# Dynamic version is also acceptable
[project]
name = "my-package"
dynamic = ["version"]
```

## Fix guidance

Add the missing fields to `[project]`:

```toml
[project]
name = "my-package"
version = "1.0.0"
```

Or use dynamic versioning with a backend:

```toml
[project]
name = "my-package"
dynamic = ["version"]

[tool.hatch.version]
path = "my_package/__init__.py"
```

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/pkg/pkg002_metadata_incomplete.rs`

## References

- [PEP 621 – Storing project metadata in pyproject.toml](https://peps.python.org/pep-0621/)
- [pyproject.toml guide](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
