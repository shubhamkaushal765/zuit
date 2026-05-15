---
title: MAINT013-empty-block — Empty control-flow block
sidebar_label: MAINT013-empty-block
description: Flags if/for/while/try/catch blocks whose body is empty.
---

# MAINT013-empty-block — Empty control-flow block

| Property  | Value                                         |
| --------- | --------------------------------------------- |
| Dimension | Maintainability                               |
| Severity  | Low                                           |
| Confidence | Medium                                       |
| CWE       | CWE-1071                                      |
| Languages | Rust, Python, JavaScript, TypeScript          |

## What it detects

Flags `if`, `for`, `while`, and `try`/`catch` statements whose body contains
no meaningful code — only a bare `pass` (Python), `...` (Python ellipsis),
or an empty `{}` block (Rust / JS/TS).

**Skips (intentional patterns are excluded):**

- Rust: empty `loop {}` — covered by `MAINT010-infinite-loop-no-exit`.
- Rust: empty function bodies — intentional stubs are acceptable.
- Python: methods decorated with `@abstractmethod` or `@overload`.
- Python: method bodies that are `...`-only inside a `Protocol`-derived class.
- JS/TS: `catch (_) {}` and bare `catch {}` — intentional error-swallow idiom.

## Why it matters

An empty block that is not a documented stub is almost always unfinished code:
a placeholder that was never filled in, a branch whose logic was deleted without
removing the condition, or a copy-paste error. Code reviewers and future
maintainers cannot tell whether the emptiness is intentional without reading the
surrounding context. Even if harmless today, empty blocks erode code clarity and
make the codebase harder to audit (CWE-1071).

## Examples — flagged

**Python:**

```python
# Empty if body — were you going to add something here?
if user.is_admin:
    pass

# Empty for loop — the loop iterates but does nothing
for item in queue:
    pass
```

**Rust:**

```rust
fn check(condition: bool) {
    if condition {}  // empty block — dead code?
}
```

**JavaScript / TypeScript:**

```ts
const x = getData();
if (x) {}  // no-op; the condition was meant to trigger something
```

## Examples — not flagged

**Python (stub methods are OK):**

```python
from abc import abstractmethod
from typing import Protocol, overload

class Printable(Protocol):
    def print(self) -> None:
        ...  # Protocol body — OK

class Base:
    @abstractmethod
    def render(self) -> str:
        pass  # abstractmethod stub — OK

class Formatter:
    @overload
    def format(self, x: int) -> str: ...
    @overload
    def format(self, x: str) -> str: ...
    def format(self, x):
        return str(x)
```

**Rust (empty loop is a separate rule):**

```rust
// Flagged by MAINT010-infinite-loop-no-exit, not by this rule.
fn spin() {
    loop {}
}
```

**JS/TS (intentional catch swallow):**

```ts
try {
    parseOptional();
} catch (_) {}  // intentional: silently ignore parse failures
```

## Fix guidance

- **Fill in the block:** Add the missing implementation.
- **Document the intent:** If the block is genuinely a no-op by design, add an
  explanatory comment (e.g. `// intentionally empty — caller handles this`).
- **Remove dead conditions:** If the condition no longer applies, remove both
  the condition and the empty block.

## Configuration

No configuration knobs in v1. The decorator skip list (Python) is hardcoded
to `@abstractmethod` and `@overload`.

## Implementation

- [`crates/zuit-lang-python/src/analyzers/empty_block.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/empty_block.rs)
- [`crates/zuit-lang-rust/src/analyzers/empty_block.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/empty_block.rs)
- [`crates/zuit-lang-js/src/analyzers/empty_block.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/empty_block.rs)

## References

- [CWE-1071: Code Written in a Language with an Unsafe Empty Block](https://cwe.mitre.org/data/definitions/1071.html)
