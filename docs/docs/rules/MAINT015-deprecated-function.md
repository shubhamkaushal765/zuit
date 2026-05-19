---
title: MAINT015-deprecated-function — Definition marked deprecated
sidebar_label: MAINT015-deprecated-function
description: Surfaces functions, methods, classes, and other items that mark themselves deprecated (CWE-477) so they can be scheduled for removal.
---

# MAINT015-deprecated-function — Definition marked deprecated

| Property   | Value                                |
| ---------- | ------------------------------------ |
| Dimension  | Maintainability                      |
| Severity   | Medium                               |
| Confidence | High                                 |
| CWE        | CWE-477                              |
| Languages  | Rust, Python, JavaScript/TypeScript  |

## What it detects

A function, method, class, or other item that announces itself as
deprecated. The rule **does not** flag callers — it flags the deprecated
definition itself so the codebase has an authoritative list of items
scheduled for removal.

Per language:

| Language | Trigger                                                                                                                 |
| -------- | ----------------------------------------------------------------------------------------------------------------------- |
| Rust     | Any item annotated with `#[deprecated]` or `#[deprecated(since = "…", note = "…")]`. Covers `fn`, impl methods, trait methods, `struct`, `enum`, `const`, `static`, type alias. |
| Python   | A `def`/`async def` decorated with `@deprecated` (PEP 702 / `typing_extensions.deprecated`), **or** a function whose body calls `warnings.warn(...)` with `DeprecationWarning` / `PendingDeprecationWarning` (as the second positional argument or `category=` keyword). |
| JavaScript / TypeScript | A `function`, `async function`, or `class` declaration (including `export …` and `export default …` forms) immediately preceded by a JSDoc block (`/** … */`) whose body contains the `@deprecated` tag. |

## Why it matters

CWE-477 (Use of Obsolete Function) documents the maintenance debt of carrying
deprecated APIs. Even when the language permits a soft deprecation (Rust's
`#[deprecated]` is a warning; Python's `DeprecationWarning` is silent by
default), each one represents a removal milestone the team needs to plan
for. Surfacing them gives reviewers a clear inventory rather than spreading
them across a hundred grep hits.

## Examples — flagged

**Rust**

```rust
#[deprecated(note = "use parse_v2 instead")]
pub fn parse(input: &str) -> Result<Value, Error> { … }

#[deprecated]
pub struct OldConfig;

impl Service {
    #[deprecated]
    pub fn shutdown_v1(&self) {}
}
```

**Python**

```python
from typing_extensions import deprecated
import warnings

@deprecated("use parse_v2() instead")
def parse(text): ...

def legacy():
    warnings.warn("legacy() is going away", DeprecationWarning, stacklevel=2)
    ...
```

**JavaScript / TypeScript**

```ts
/**
 * @deprecated use parseV2() instead
 */
export function parse(input: string) {
    return parseV2(input);
}

/** @deprecated */
export default class OldGateway {}
```

## Examples — not flagged

```rust
// Plain item — no #[deprecated] attribute.
pub fn parse(input: &str) -> Result<Value, Error> { … }

// `#[inline]`, `#[must_use]`, etc. are not deprecation markers.
#[must_use]
pub fn good() -> u32 { 1 }
```

```python
# Plain function — no decorator, no warnings.warn call.
def parse(text): ...

# warnings.warn with a different category (UserWarning) is not a deprecation marker.
import warnings
def maybe(): warnings.warn("careful", UserWarning)
```

```ts
// JSDoc without `@deprecated` is not a deprecation marker.
/** A documented function. */
function fine(x) { return x + 1; }

// Plain block comments and line comments are not JSDoc.
// @deprecated  ← not parsed
function alsoFine() {}
```

## Scope limitations (v1)

- **Rust modules and traits** themselves are not currently flagged when
  marked `#[deprecated]` — only their items. This is consistent with how
  the compiler surfaces the warning.
- **JavaScript** only inspects `function`, `async function`, and `class`
  declarations preceded by a JSDoc block. `const`/`let` exports, TypeScript
  `interface`/`type` aliases, and class members are not yet covered.
- The rule does **not** detect *callers* of deprecated APIs. That belongs
  to a separate forthcoming rule once symbol-resolution lands (see
  PLAN §4 #14).

## Fix guidance

Plan a removal milestone, migrate callers to the supported replacement,
then delete the deprecated definition. If the deprecation has not yet
been communicated, add a more descriptive `note` (Rust), `reason` string
(Python `@deprecated`), or JSDoc body (JS) pointing to the replacement
and the planned removal version.

## Implementation

- Rust: [`crates/zuit-lang-rust/src/analyzers/deprecated_function.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/deprecated_function.rs)
- Python: [`crates/zuit-lang-python/src/analyzers/deprecated_function.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/deprecated_function.rs)
- JavaScript/TypeScript: [`crates/zuit-lang-js/src/analyzers/deprecated_function.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/deprecated_function.rs)

## References

- [CWE-477: Use of Obsolete Function](https://cwe.mitre.org/data/definitions/477.html)
- [Rust `#[deprecated]` attribute](https://doc.rust-lang.org/reference/attributes/diagnostics.html#the-deprecated-attribute)
- [PEP 702 — Marking deprecations using the type system](https://peps.python.org/pep-0702/)
- [JSDoc `@deprecated`](https://jsdoc.app/tags-deprecated.html)
