---
title: DOC003 — Empty or Placeholder Documentation Comment
sidebar_label: DOC003
description: Flags empty or meaningless doc comments
---

# DOC003-empty-doc — Empty or Placeholder Documentation Comment

**Dimension:** Documentation
**Default severity:** Info
**Languages:** All
**Last reviewed:** 2026-05-06

## What it detects

Flags documentation comments (`///`, `//!`, `/** */`, docstrings) whose normalised content is:

1. **Empty** — no text after stripping markers and whitespace.
2. **Punctuation-only** — consists entirely of non-alphanumeric characters (e.g. `"."`, `"?"`).
3. **Name-echo** — identical (case-insensitively) to the name of the function or type the comment is attached to.

Placeholder comments give a false sense of documented code while providing no actual value to readers.

## Example — flagged

**Rust:**

```rust
///
pub fn empty_doc_fn() -> i32 { 42 }

/// .
pub fn punctuation_only() -> bool { true }
```

**Python:**

```python
def empty_doc_fn():
    """"""  # empty docstring — flagged
    return 42
```

## Example — not flagged

```rust
/// Returns the sum of `a` and `b`.
pub fn add(a: i32, b: i32) -> i32 { a + b }
```

## Fix guidance

Write a meaningful one-sentence summary describing what the item does, what it returns, or when it should be used. If the item is internal and self-explanatory, remove the doc comment entirely rather than leaving a placeholder.

## Implementation

- Source: [crates/zuit-analyzers/src/empty_doc.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/empty_doc.rs)
- Consumes `SemanticIndex::doc_comments` and cross-references with `FunctionLike::doc` / `TypeDecl::doc`.
