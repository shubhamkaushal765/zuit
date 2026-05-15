---
title: PKG005-python-version-unconstrained — Missing `requires-python`
sidebar_label: PKG005-python-version-unconstrained
---
# PKG005-python-version-unconstrained — Missing `requires-python`

**Dimension:** Packaging
**Default severity:** Low
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when `[project]` in `pyproject.toml` has no `requires-python` field.

## Why it matters

Without `requires-python`, `pip` will happily install a package on any Python
version, including Python 2 and Python 3.5 — versions where the package may
fail to import, raise syntax errors, or behave incorrectly. The
`requires-python` constraint is the primary mechanism for communicating
interpreter compatibility to both `pip` and build tools.

## Configuration

No configuration knobs in v1.

## Example — flagged

```toml
[project]
name = "my-package"
version = "1.0.0"
# No requires-python — flagged
```

## Example — not flagged

```toml
[project]
name = "my-package"
version = "1.0.0"
requires-python = ">=3.9"
```

## Fix guidance

Add a `requires-python` constraint that reflects the oldest interpreter your
package actually supports. Test against that version in CI.

```toml
[project]
requires-python = ">=3.9"
```

Common floor choices:
- `">=3.9"` — drops EOL 3.7 and 3.8; good default for new projects.
- `">=3.11"` — targets only actively maintained versions.
- `">=3.8"` — maximizes compatibility; note 3.8 reached EOL October 2024.

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/pkg/pkg005_python_version_unconstrained.rs`

## References

- [PEP 345 – requires-python](https://peps.python.org/pep-0345/)
- [Python release schedule](https://endoflife.date/python)
