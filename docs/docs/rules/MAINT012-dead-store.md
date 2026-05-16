---
title: MAINT012-dead-store — dead local variable write
sidebar_label: MAINT012-dead-store
description: Detects local variables that are written but whose value is never read before going out of scope or being overwritten.
---

# MAINT012-dead-store — dead local variable write

| Property         | Value                       |
| ---------------- | --------------------------- |
| Dimension        | Maintainability             |
| Default severity | Low                         |
| CWE              | CWE-563                     |
| Languages        | Python, JavaScript/TypeScript |

## What it detects

A *dead store* is a write to a local variable whose value is never subsequently
read — either because the variable goes out of scope without being used, or
because it is overwritten before the first read.

Flagged patterns:

- `let x = compute();` / `const unused = 42;` where the name never appears
  in a later expression.
- `x = a + b;` followed immediately by `x = c;` (overwrite without read).
- `unused = fetch_data()` in Python where the value is never referenced again
  in the same function.

Not flagged:

- Names beginning with `_` (conventional "intentionally unused" marker).
- Loop iteration variables in `for x in ...` / `for (let x of ...)`.
- Destructuring patterns (`let (a, b) = pair()` in Rust; `const { a, b } = obj` in JS).
- `let mut` bindings in Rust (left to `rustc -W unused_variables`).
- Augmented assignments (`x += 1`) — these are reads as well as writes.
- Variables used in `try`/`except` clauses or `with` statements in Python.

**Rust note:** The Rust analyzer is shipped **disabled by default** because the
token-stream substring heuristic produces a high false-positive rate on files
that use macros heavily.  The Rust compiler's own `unused_variables` lint is
more accurate for this check.  The Python and JavaScript/TypeScript analyzers
are fully enabled.

## Why it matters

Dead stores indicate one of two problems:

1. **Wasted computation**: The assigned value (which may have been expensive to
   compute) is discarded without any benefit.
2. **Logic error**: The developer intended to use the value but accidentally
   referenced a different variable or forgot to wire up the result.

CWE-563 ("Assignment to Variable without Use") is classified under the
"Bad Coding Practices" category and is commonly associated with subtle bugs
that survive code review because the unused variable name looks plausible.

## Examples — flagged

```python
def process(data):
    result = expensive_transform(data)  # dead store — never read
    return data
```

```typescript
function calculate(a: number, b: number): number {
    const intermediate = a * 2;  // dead store — never read
    return a + b;
}
```

## Examples — not flagged

```python
def process(data):
    result = expensive_transform(data)
    return result  # result is read here — OK

def loop_example(items):
    for _item in items:  # _-prefix suppresses the check
        pass
```

```typescript
function calculate(a: number, b: number): number {
    const intermediate = a * 2;
    return intermediate + b;  // intermediate is read — OK
}

function skip(_unused: number): void {  // _-prefix suppresses
    // intentionally unused
}
```

## Configuration

No configuration knobs in v1.  Use a `_`-prefixed name to silence the warning
for intentionally unused bindings:

```python
_ = some_side_effect()       # suppressed
_result = debug_value()      # suppressed
```

```typescript
const _debug = computeDebugInfo();  // suppressed
```

## Fix

Choose one of:

1. **Delete** the dead assignment if the value is truly not needed.
2. **Use** the value — wire it into the return value or pass it to another
   function.
3. **Rename** with a `_` prefix to signal the variable is intentionally unused.

## References

- [CWE-563: Assignment to Variable without Use](https://cwe.mitre.org/data/definitions/563.html)
