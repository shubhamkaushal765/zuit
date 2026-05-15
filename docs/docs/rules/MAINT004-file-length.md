---
title: MAINT004-file-length — File length
sidebar_label: MAINT004-file-length
description: Detects files whose total line count exceeds a configurable threshold.
---

# MAINT004-file-length — File length

| Property         | Value           |
| ---------------- | --------------- |
| Dimension        | Maintainability |
| Default severity | Low             |
| Languages        | All             |

## What it detects

Flags files whose total line count exceeds a configurable threshold. The default threshold is 600 lines. Files that are too long tend to serve multiple purposes, mix concerns, and become harder to navigate, test, and maintain.

## Why it matters

Large files are often a sign of unclear module boundaries and mixed responsibilities. A file that spans hundreds of lines suggests that it may contain multiple independent concepts or features that deserve their own modules. Splitting long files:

- Improves code navigability and reduces cognitive load
- Clarifies module responsibilities (single responsibility principle)
- Makes testing and reuse easier
- Reduces merge conflicts in version control
- Allows concurrent development on related but separate concerns

The 600-line default threshold is empirically motivated: files beyond this point typically contain multiple cohesive components that can be factored out.

## Configuration

| Parameter | Type | Default | Notes |
| --- | --- | --- | --- |
| `threshold` | u32 | 600 | Files with line count exceeding this value are flagged. |

Set in `zuit.toml`:

```toml
[rules.MAINT004-file-length]
threshold = 600
```

## Examples — flagged

**Rust:** A file with 700+ lines combining a public API, internal helpers, tests, and serialization logic:

```rust
//! A large module handling too many concerns.

pub struct UserManager { ... }
impl UserManager { ... }

struct InternalCache { ... }
impl InternalCache { ... }

pub struct UserDTO { ... }
impl serde::Serialize for UserDTO { ... }
impl serde::Deserialize for UserDTO { ... }

pub fn legacy_compat_parse(...) { ... }

#[cfg(test)]
mod tests { ... }
```

**Python:** A 650+ line module mixing data handling, business logic, and API endpoints:

```python
"""
User management utilities.
Contains database models, service logic, Flask routes, and helpers.
"""

class User:
    ...

class UserService:
    ...

@app.route('/users', methods=['GET'])
def list_users():
    ...

def _internal_helper_1():
    ...

def _internal_helper_2():
    ...
```

## Examples — not flagged

**Rust:** A focused 150-line module with a single responsibility:

```rust
//! Command-line argument parsing for the build tool.

pub struct Config { ... }
impl Config {
    pub fn from_args(args: &[String]) -> Result<Self, Error> { ... }
    pub fn validate(&self) -> Result<(), Error> { ... }
}

#[cfg(test)]
mod tests { ... }
```

**Python:** A 200-line data utilities module:

```python
"""Utilities for common data transformations."""

def normalize_email(email: str) -> str:
    ...

def validate_phone(phone: str) -> bool:
    ...

class DataCleaner:
    ...
```

## Fix guidance

- **Split by responsibility**: Identify logical groupings (e.g., API layer, service layer, data models) and move each to its own file.
- **Extract private modules**: Move internal helpers and implementation details to separate files prefixed with `_` (Rust/Python convention).
- **Create a module directory**: Convert a single file `foo.rs` / `foo.py` into a directory `foo/` with `__init__.rs` / `__init__.py` and submodules.
- **Consolidate tests**: If tests are mixed in the main file and they exceed a few hundred lines, move them to a dedicated test module or file.
- **Review module boundaries**: Ensure each file has a clear, single purpose. If you struggle to describe the file's role in one sentence, it likely has too many responsibilities.

## Implementation

- Source: [`crates/zuit-analyzers/src/file_length.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/file_length.rs)
- Line counting: [`crates/zuit-core/src/source.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-core/src/source.rs) — `SourceFile::line_count()`

## References

- [Style Guide for Python Code: Module Length](https://pep8.org) — general guidance on keeping modules focused.
- [Effective Go: Package Names](https://golang.org/doc/effective_go#package-names) — principles applicable across languages.
- [Robert C. Martin, "Clean Code"](https://www.oreilly.com/library/view/clean-code-a/9780136083238/) — Chapter 4 (Comments) discusses optimal file sizes and responsibilities.
