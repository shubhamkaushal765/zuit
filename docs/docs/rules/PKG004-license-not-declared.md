---
title: PKG004-license-not-declared — Missing License Declaration
sidebar_label: PKG004-license-not-declared
---
# PKG004-license-not-declared — Missing License Declaration

**Dimension:** Packaging
**Default severity:** Medium
**Languages:** All (project-level)
**Last reviewed:** 2026-05-08

## What it detects

Emits when `[project]` in `pyproject.toml` has neither a `license` nor a
`license-files` field.

## Why it matters

Without a declared license, a package is legally "all rights reserved" in most
jurisdictions. Organizations cannot legally use, modify, or distribute it. Open
source projects that forget to declare a license effectively lock out all
downstream users, including developers who assume permissive terms.

## Configuration

No configuration knobs in v1.

## Example — flagged

```toml
[project]
name = "my-package"
version = "1.0.0"
# No license field — flagged
```

## Example — not flagged

```toml
# Using the SPDX expression form (PEP 639)
[project]
name = "my-package"
version = "1.0.0"
license = { text = "MIT" }
```

```toml
# Using the license-files form
[project]
name = "my-package"
version = "1.0.0"
license-files = ["LICENSE"]
```

## Fix guidance

Add a license declaration using one of these forms:

**SPDX expression (recommended for PEP 639):**
```toml
[project]
license = { text = "MIT" }
```

**File reference:**
```toml
[project]
license-files = ["LICENSE", "LICENSE.APACHE", "LICENSE.MIT"]
```

Also add a `LICENSE` file in your repository root if it doesn't exist. Common
permissive choices: MIT, Apache-2.0, BSD-2-Clause.

## Implementation

Source: `crates/zuit-lang-python/src/analyzers/pkg/pkg004_license_not_declared.rs`

## References

- [PEP 639 – Improving License Clarity with Better Package Metadata](https://peps.python.org/pep-0639/)
- [SPDX license list](https://spdx.org/licenses/)
- [Choose a license](https://choosealicense.com/)
