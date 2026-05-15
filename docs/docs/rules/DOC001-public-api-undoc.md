---
title: DOC001 — Public API Documentation
sidebar_label: DOC001
description: Flags every public function or type that lacks a documentation comment
---

# DOC001-public-api-undoc — Public API Documentation

**Dimension:** Documentation
**Default severity:** Medium
**Languages:** All
**Last reviewed:** 2026-05-03

## What it detects

Flags every public function or type that lacks a documentation comment. The analyzer scans the `SemanticIndex` for items with `visibility == Public` and `doc.is_none()`, emitting one finding per undocumented public item. Doc comments are language-specific: `///` in Rust, docstrings in Python.

## Why it matters

Undocumented public APIs create friction for users and maintainers. Clear, minimal documentation of input, output, invariants, and error conditions is essential for code that is meant to be consumed by other modules or external users. See [ARCH_SPEC § 5.4](https://github.com/shubhamkaushal765/zuit/blob/main/.agent/ARCH_SPEC.md#54-semanticindex-cross-language-contract) for the `SemanticIndex` contract.

## Configuration

No configuration knobs in v1.

## Example — flagged

**Rust:**

```rust
pub fn undocumented(input: &str) -> usize {
    input.len()
}
```

**Python:**

```python
def undocumented_public_function(x, y):
    return x + y
```

## Example — not flagged

**Rust:**

```rust
/// Returns the length of the input string.
pub fn documented(input: &str) -> usize {
    input.len()
}
```

**Python:**

```python
def documented_public_function(x, y):
    """Return the sum of x and y."""
    return x + y
```

## Fix guidance

- **Write a summary line**: Start with a one-sentence description of what the item does, optimized for IDE hover tooltips.
- **Document parameters**: If the public item takes input, describe each parameter's purpose and constraints.
- **Document return value**: Describe what is returned and what it represents.
- **Note error conditions**: If the item can fail (e.g., return `Result` or raise an exception), document the failure modes.
- **Avoid duplication**: Link to narrative docs if a longer explanation exists elsewhere.

## Implementation

- Source: [crates/zuit-analyzers/src/public_api_undoc.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/public_api_undoc.rs)
- Severity / supported languages: see `RuleMeta` in source.

## References

- Rust: [Rust API Guidelines — Documentation](https://rust-lang.github.io/api-guidelines/documentation.html)
- Python: [PEP 257 — Docstring Conventions](https://peps.python.org/pep-0257/)
