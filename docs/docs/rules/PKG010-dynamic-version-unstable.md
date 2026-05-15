---
title: PKG010-dynamic-version-unstable — Dynamic Version Without Backend Config
sidebar_label: PKG010-dynamic-version-unstable
---
# PKG010-dynamic-version-unstable — Dynamic Version Without Backend Config

**Dimension:** Packaging
**Default severity:** Low
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when `[project].dynamic` includes `"version"` but no recognised dynamic-
version backend configuration block is present in `pyproject.toml`.

Recognised backend blocks:
- `[tool.setuptools.dynamic.version]` — setuptools-scm / `attr:` source
- `[tool.hatch.version]` — hatch-vcs or hatch's built-in versioning
- `[tool.poetry-dynamic-versioning]` — poetry-dynamic-versioning plugin
- `[tool.versioneer]` — versioneer
- `[tool.bumpversion]` or `[tool.bump2version]` — bump2version / bumpversion

## Why it matters

Declaring `dynamic = ["version"]` instructs build tools to derive the version
at build time from a backend. If no backend is configured, the build will:

- **setuptools**: raise `SetuptoolsDeprecationWarning: version is not specified`
  or produce a distribution with `version = "0.0.0"`.
- **hatch**: abort with a configuration error.

The resulting package may be published to PyPI with an incorrect or empty
version, making it impossible to install a specific release.

## Configuration

No configuration knobs in v1. To silence this rule, configure a supported
dynamic-version backend (recommended) or switch to a static `version` field.

## Example — flagged

```toml
[project]
name = "my-package"
dynamic = ["version"]
# No [tool.*] version backend config — flagged
```

## Example — not flagged

```toml
[project]
name = "my-package"
dynamic = ["version"]

[tool.hatch.version]
path = "my_package/__init__.py"
```

```toml
[project]
name = "my-package"
dynamic = ["version"]

[tool.setuptools.dynamic.version]
attr = "my_package.__version__"
```

## Fix guidance

Either configure a dynamic-version backend or switch to a static version:

**Option A — static version (simplest):**
```toml
[project]
name = "my-package"
version = "1.0.0"
# Remove "version" from dynamic
```

**Option B — hatch-vcs (git tags):**
```toml
[build-system]
requires = ["hatchling", "hatch-vcs"]
build-backend = "hatchling.build"

[project]
dynamic = ["version"]

[tool.hatch.version]
source = "vcs"
```

**Option C — setuptools dynamic:**
```toml
[project]
dynamic = ["version"]

[tool.setuptools.dynamic.version]
attr = "my_package.__version__"
```

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/pkg/pkg010_dynamic_version_unstable.rs`

## References

- [setuptools dynamic metadata](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html#dynamic-metadata)
- [hatch versioning](https://hatch.pypa.io/latest/version/)
- [hatch-vcs](https://github.com/ofek/hatch-vcs)
