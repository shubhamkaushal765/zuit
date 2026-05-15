---
title: DOC004-stale-doc — Stale Parameter Reference in Documentation
sidebar_label: DOC004-stale-doc
---
# DOC004-stale-doc — Stale Parameter Reference in Documentation

**Dimension:** Documentation
**Default severity:** Low
**Languages:** All
**Last reviewed:** 2026-05-07

## What it detects

Flags documentation comments that reference a parameter name which no longer
appears in the function's signature.  This happens when a function is
refactored (parameter renamed or removed) but the doc comment is not updated
to match.

The following doc-comment styles are supported:

- **`JSDoc` / `TSDoc`:** `@param {type} name` or `@param name`
- **Sphinx / reStructuredText:** `:param name:` or `:param type name:`
- **Google-style Python:** `Args:` section with `name:` or `name (type):` entries
- **Rustdoc:** `# Arguments` section with `` * `name` - desc `` bullets

The analyzer is conservative: if no recognised param-documentation markers are
found in the doc text, no finding is emitted.  Only `Function` and `Method`
kinds are checked; closures, lambdas, and arrow functions are skipped.

## Example — flagged

**Rust:**

```rust
/// Computes a result.
///
/// # Arguments
///
/// * `a` - the first input   ← wrong: actual param is `x`
/// * `b` - the second input  ← wrong: actual param is `y`
pub fn compute(x: i32, y: i32) -> i32 {
    x + y
}
```

**Python:**

```python
def add(x, y):
    """Add two numbers.

    :param a: the first operand   # wrong: actual param is `x`
    :param b: the second operand  # wrong: actual param is `y`
    """
    return x + y
```

**TypeScript:**

```typescript
/**
 * Adds two numbers.
 * @param foo - first operand  // wrong: actual param is `a`
 * @param bar - second operand // wrong: actual param is `b`
 */
export function add(a: number, b: number): number {
    return a + b;
}
```

## Example — not flagged

```rust
/// Computes a result.
///
/// # Arguments
///
/// * `x` - the first input
/// * `y` - the second input
pub fn compute(x: i32, y: i32) -> i32 {
    x + y
}
```

## Fix guidance

Update the doc comment to use the actual parameter names from the function
signature, or remove the `@param` / `:param` entry if the parameter no longer
exists.

## Implementation

- Source: `crates/zuit-analyzers/src/stale_doc.rs`
- Consumes `SemanticIndex::functions`, `SemanticIndex::doc_comments`, and the
  raw source bytes.  Cross-references `FunctionLike::doc` to find the
  associated `DocComment`, then scans the signature region
  (`func.span.start..func.body_span.start`) for each documented name.
- No CWE or OWASP mapping (documentation quality issue, not a security flaw).
