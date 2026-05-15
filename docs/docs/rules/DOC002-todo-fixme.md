---
title: DOC002-todo-fixme — TODO / FIXME marker inventory
sidebar_label: DOC002-todo-fixme
description: Inventories TODO and FIXME markers found in regular code comments.
---

# DOC002-todo-fixme — TODO / FIXME marker inventory

| Property         | Value         |
| ---------------- | ------------- |
| Dimension        | Documentation |
| Default severity | Info          |
| Languages        | All           |

## What it detects

Flags every occurrence of a `TODO` or `FIXME` marker found in code comments (not doc-comments / docstrings). Each match is reported once per comment; a single comment containing multiple markers produces multiple findings.

## Why it matters

TODO and FIXME markers indicate incomplete or deferred work that should be addressed before merge. Leaving them in the codebase creates technical debt and may obscure intended behavior. A complete inventory helps teams maintain visibility into outstanding work.

## Configuration

No configuration knobs in v1.

## Matching rules

- **Case-insensitive, whole-word match** on `TODO` or `FIXME` in the comment text.
- Regex: `(?i)\b(TODO|FIXME)\b`
- **Regular comments only**: `//` (Rust / JavaScript / TypeScript), `#` (Python), `/* */` (Rust / JavaScript / TypeScript).
- **Docstrings / doc-comments are excluded**: Rust `///` / `/** */`, Python `"""` / `'''`, JavaScript JSDoc.

## Examples — flagged

**Rust:**

```rust
// TODO: refactor this function
fn process_data(input: &str) -> Result<()> {
    // FIXME: handle empty strings
    todo!("implement this");
}
```

**Python:**

```python
# TODO: add error handling
def fetch_data(url):
    # FIXME: placeholder implementation
    return None
```

## Examples — not flagged

**Rust:**

```rust
/// TODO in a docstring is not flagged.
/// Use a regular comment instead.
fn documented() {}

fn clean() {
    // This function is complete.
}
```

**Python:**

```python
"""Module docstring with TODO is not flagged."""


def complete():
    """No markers here."""
    pass
```

## Fix guidance

- **Act immediately**: Address TODO and FIXME markers before code review / merge.
- **Extract to issues**: If a marker describes future work, open a separate tracking issue and remove the marker.
- **Add context**: Include the reason for the marker in the comment (e.g., `// TODO: wait for API redesign (issue #456)`).
- **Do not commit**: Mark the CI to fail on any remaining markers if they block production readiness.

## Implementation

- Source: [`crates/zuit-analyzers/src/todo_fixme.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/todo_fixme.rs)
- Comment extraction: [`crates/zuit-lang-rust/src/index.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/index.rs), [`crates/zuit-lang-python/src/index.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/index.rs)

## References

- [Code Smell: TODO Comments](https://wiki.c2.com/?TodoComments)
