---
title: PERF002-wheel-size
sidebar_label: PERF002-wheel-size
---
# PERF002-wheel-size

**Dimension:** Performance
**Severity:** Low
**Kind:** ProjectLevel

## Description

Detects distribution artifacts in the `dist/` directory that exceed the recommended
size thresholds:

| Artifact | Threshold |
|----------|-----------|
| `dist/*.whl` | > 50 MiB |
| `dist/*.tar.gz` | > 100 MiB |

Large distributions inflate install time, bandwidth consumption, and CI/CD cache
storage. They are often caused by accidentally bundled test fixtures, large binary
assets, or vendored third-party libraries.

## Examples

### Flagged

```
dist/mylib-1.0-py3-none-any.whl   (62 MiB)  # PERF002: exceeds 50 MiB threshold
```

### Not flagged

```
dist/mylib-1.0-py3-none-any.whl   (8 MiB)   # within threshold
dist/mylib-1.0.tar.gz             (95 MiB)   # within 100 MiB threshold
```

## Diagnosis

Inspect the contents of the wheel to find the bloat:

```shell
unzip -l dist/mylib-1.0-py3-none-any.whl | sort -rk1 | head -30
```

Common culprits:
- Test fixtures or datasets included via `MANIFEST.in` or `package_data`
- Compiled binaries built for multiple platforms vendored together
- Documentation or example notebooks inadvertently included

## Fix

1. Review `MANIFEST.in` / `pyproject.toml` `[tool.setuptools.package-data]` and
   exclude large files:

   ```toml
   [tool.setuptools.package-data]
   mylib = ["*.py"]   # exclude *.dat, *.h5, etc.
   ```

2. Move test data out of the package directory into a top-level `tests/` directory
   that is not installed.

3. Rebuild and verify:

   ```shell
   python -m build
   ls -lh dist/
   ```

## Suppression

```python
# zuit: ignore PERF002-wheel-size
```

Add the comment to `pyproject.toml` (above the `[build-system]` table) if the large
wheel is intentional (e.g., a binary distribution with bundled native libraries).
