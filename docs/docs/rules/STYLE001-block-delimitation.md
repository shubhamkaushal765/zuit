---
title: STYLE001-block-delimitation — ASI block-delimitation hazard
sidebar_label: STYLE001-block-delimitation
description: Flags ASI hazards where return, continue, or break without an argument/label is immediately followed by a statement that becomes unreachable or mis-parsed (CWE-483).
---

# STYLE001-block-delimitation — ASI block-delimitation hazard

| Property   | Value                  |
| ---------- | ---------------------- |
| Dimension  | Maintainability        |
| Severity   | Medium                 |
| Confidence | High                   |
| CWE        | CWE-483                |
| Languages  | JavaScript, TypeScript |

## What it detects

Flags three patterns where JavaScript's Automatic Semicolon Insertion (ASI) silently terminates a statement before a developer-intended continuation, with exactly one newline separating the keyword from the following statement:

- **ReturnExpr** — `return` (no argument) immediately followed by an `ExpressionStatement`. ASI inserts `;` after `return`, making the expression unreachable and the function return `undefined`.
- **ContinueLabel** — `continue` (no label) immediately followed by an `ExpressionStatement` containing an `Identifier`. ASI discards the intended label.
- **BreakLabel** — `break` (no label) immediately followed by an `ExpressionStatement` containing an `Identifier`. ASI discards the intended label.

## Examples — flagged

**ReturnExpr — function silently returns `undefined`:**

```js
function getResult() {
  return
    computedValue;  // unreachable — ASI fires after return
}
```

**ContinueLabel — label is discarded:**

```js
outer: for (const x of xs) {
  for (const y of ys) {
    continue
      outer;  // ASI fires; "outer;" becomes orphan expression
  }
}
```

**BreakLabel — label is discarded:**

```js
outer: for (const x of xs) {
  for (const y of ys) {
    break
      outer;  // ASI fires; "outer;" becomes orphan expression
  }
}
```

## Examples — not flagged

**Blank line between return and expression (carve-out):**

```js
function f() {
  return

  value;  // two newlines — blank line suppresses the finding
}
```

**Explicit argument on the return line:**

```js
function f() {
  return value;  // argument on same line — no ASI hazard
  extra;
}
```

**Next statement is not an ExpressionStatement:**

```js
function f() {
  return
  var x = 1;  // VariableDeclaration — not flagged
}
```

**Comment-intervening line (known v1 limit — suppressed):**

```js
function f() {
  return
  // hint about what follows
  value;  // >= 2 newlines counted; no finding emitted (see Known limits)
}
```

## Why it matters

JavaScript's ASI rules (ECMA-262 §12.9.2) automatically insert a semicolon after
`return`, `continue`, and `break` when a line terminator follows the keyword and
no argument/label begins on the same line. This is a *restricted production*: the
engine inserts `;` regardless of developer intent.

The result is silent misbehavior: functions return `undefined` instead of a value,
loop labels are silently dropped, and the "intended" expression executes as dead
code — or as a label-expression statement with no effect.

CWE-483 (Incorrect Block Delimitation) captures this class of defect: the logical
block boundary differs from what the developer intended, with no syntax error to
signal the problem.

## Fix guidance

**ReturnExpr:** Move the return value onto the same line as `return`, or open a
parenthesis on the `return` line:

```js
// Before (bug):
return
  computedValue;

// After — option A (same line):
return computedValue;

// After — option B (paren-wrapped):
return (
  computedValue
);
```

**ContinueLabel / BreakLabel:** Move the label to the same line as `continue` or
`break`:

```js
// Before (bug):
continue
  outer;

// After:
continue outer;
```

## Known limits

- **Comment-intervening line:** `return\n// comment\nexpr` is *not* flagged in v1.
  The newline counter sees ≥ 2 newlines and suppresses the finding. This is a
  documented false-negative; a future version may walk the byte range skipping
  comment tokens.
- **Brace-less control-flow body hazards** (`if (c) stmt1;\n  stmt2;` — Apple
  goto-fail style) are out of v1 scope; they require column heuristics and carry
  high false-positive risk.
- **Line-prefix hazards** (`x\n(...)`, `x\n[...]`) are out of v1 scope; deferred
  to a planned STYLE002 (Family B).

## Implementation

- [`crates/zuit-lang-js/src/analyzers/block_delimitation.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/block_delimitation.rs)
- [`crates/zuit-lang-js/src/parse.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/parse.rs)

## References

- [CWE-483: Incorrect Block Delimitation](https://cwe.mitre.org/data/definitions/483.html)
