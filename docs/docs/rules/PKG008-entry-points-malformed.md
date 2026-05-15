---
title: PKG008-entry-points-malformed — Malformed Entry-Point String
sidebar_label: PKG008-entry-points-malformed
---
# PKG008-entry-points-malformed — Malformed Entry-Point String

**Dimension:** Packaging
**Default severity:** Medium
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when any value in `[project.scripts]`, `[project.gui-scripts]`, or
`[project.entry-points.<group>]` is not a valid entry-point string.

A valid entry-point string has the form `module.path:callable`, where:

- `module.path` is a non-empty dotted Python identifier (e.g. `mypackage.cli`).
- `callable` is a non-empty dotted attribute path (e.g. `main` or `MyClass.run`).
- The two parts are separated by exactly one colon (`:`).

## Why it matters

An invalid entry-point string causes `pip install` to succeed, but the
installed command will fail at runtime with an `ImportError` or
`AttributeError`. The error is often cryptic and hard to trace back to a
packaging mistake.

## Configuration

No configuration knobs in v1.

## Example — flagged

```toml
[project.scripts]
# No colon separator — invalid
my-cli = "mypackage-main"

# Empty callable part — invalid
bad-ep = "mypackage:"
```

## Example — not flagged

```toml
[project.scripts]
my-cli = "mypackage.cli:main"

[project.gui-scripts]
my-gui = "mypackage.gui:App.run"

[project.entry-points."mypackage.plugins"]
plugin-a = "mypackage.plugins.a:Plugin"
```

## Fix guidance

Ensure every entry-point value follows `module:attr` form:

```toml
[project.scripts]
# Pattern: "importable.module:callable_attribute"
my-cli = "mypackage.cli:main"
```

To verify that the entry point resolves, install the package in a virtual
environment and run the command, or use:

```python
from importlib.metadata import entry_points
eps = entry_points(group="console_scripts")
```

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/pkg/pkg008_entry_points_malformed.rs`

## References

- [Entry points specification](https://packaging.python.org/en/latest/specifications/entry-points/)
- [PEP 517 – console_scripts](https://peps.python.org/pep-0517/)
