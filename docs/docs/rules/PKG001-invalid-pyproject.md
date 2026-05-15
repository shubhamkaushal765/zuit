---
title: PKG001-invalid-pyproject — Malformed `pyproject.toml`
sidebar_label: PKG001-invalid-pyproject
---
# PKG001-invalid-pyproject — Malformed `pyproject.toml`

**Dimension:** Packaging
**Default severity:** High
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when `pyproject.toml` exists in the project root but cannot be parsed as
valid TOML. The finding is anchored to the line and column of the first parse
error.

## Why it matters

A broken `pyproject.toml` silently disables every tool that reads it: build
backends (`pip`, `build`), linters (`ruff`, `mypy`), and package managers
(`poetry`, `uv`). Downstream consumers who run `pip install .` will receive a
cryptic error with no clear cause.

## Configuration

No configuration knobs in v1.

## Example — flagged

```toml
# pyproject.toml — truncated table header (missing closing bracket)
[project
name = "my-package"
```

## Example — not flagged

```toml
[project]
name = "my-package"
version = "1.0.0"
```

## Fix guidance

- Validate with `taplo lint pyproject.toml` or an online TOML validator.
- Common causes: unclosed `[table`, missing quotes around values, trailing
  commas in inline arrays/tables.

## Suppression

Because `pyproject.toml` is not parsed as a Python source file by zuit,
engine-level `# zuit: ignore PKG001` suppression in the TOML file does not
apply. Fix the TOML syntax error instead.

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/pkg/pkg001_invalid_pyproject.rs`

## References

- [pyproject.toml specification](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
- [TOML specification](https://toml.io/en/v1.0.0)
