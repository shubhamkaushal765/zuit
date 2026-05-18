---
title: BUG001-assignment-in-condition — Assignment in condition
sidebar_label: BUG001-assignment-in-condition
description: Flags assignment expressions in condition/test positions (CWE-480). Common mistake — `if (x = 1)` instead of `if (x == 1)`.
---

# BUG001-assignment-in-condition — Assignment in condition

| Property   | Value                                |
| ---------- | ------------------------------------ |
| Dimension  | Maintainability                      |
| Severity   | Medium                               |
| Confidence | High                                 |
| CWE        | CWE-480                              |
| Languages  | JavaScript, TypeScript               |

## What it detects

An assignment expression (`=`, `+=`, `-=`, `*=`, `/=`, etc.) that appears in
the **test** position of a conditional statement or expression:

- `if (x = 1) { … }` — almost always a typo for `if (x == 1)`
- `while (x = nextChunk()) { … }` — assignment in loop guard
- `do { … } while (x = next())`
- `for (let i = 0; x = step(); i++)` — the **test slot** only; the `i = 0`
  init is a `VariableDeclaration` and is not flagged
- Ternary test: `(x = 1) ? a : b`

## Carve-out

Following ESLint's `no-cond-assign` `"except-parens"` default, an assignment
wrapped in an **extra** pair of parentheses is **not** flagged.  The idiom
`if ((x = getValue()))` is the documented "I really mean it" pattern:

```js
// NOT flagged — intentional double-paren carve-out:
if ((x = getValue())) {
    use(x);
}
```

## Why it matters

CWE-480 (Use of Incorrect Operator) documents the `=` vs `==` confusion as a
source of real bugs.  The code compiles and runs, but the condition always
evaluates to the assigned value rather than a boolean comparison, silently
changing program logic.

```js
// Bug: assigns 0 (falsy) — body never executes
if (status = 0) { handleSuccess(); }

// Intended:
if (status === 0) { handleSuccess(); }
```

## Examples — flagged

```js
// Simple assignment instead of comparison
if (x = 1) {
    doSomething();
}

// Compound assignment in while guard
while (buf = readChunk()) {
    process(buf);
}

// do-while
do {
    process(x);
} while (x = next());

// for — test slot only
for (let i = 0; x = step(); i++) {
    // let i = 0  →  init, NOT flagged
    // x = step() →  test slot, flagged
    // i++        →  update, NOT flagged
}

// TypeScript cast does not suppress the finding
if (x = getValue() as number) {
    use(x);
}
```

## Examples — not flagged

```js
// Equality / strict equality — correct
if (x == 1) { … }
if (x === 1) { … }

// Assignment outside condition
let x = 1;
if (x) { … }

// Intentional assignment with extra parens (ESLint except-parens carve-out)
if ((x = getValue())) { use(x); }

// Assignment in ternary branch position (not the test)
cond ? (a = b) : c;
```

## Fix guidance

Replace the assignment with the intended comparison:

```js
// Before (bug):
if (result = compute()) { … }

// After (fix — comparison):
if (result === compute()) { … }

// After (fix — intentional assignment, explicit style):
result = compute();
if (result) { … }

// After (alternative — intentional assignment with carve-out):
if ((result = compute())) { … }
```

## Implementation

- [`crates/zuit-lang-js/src/analyzers/assignment_in_condition.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/assignment_in_condition.rs)
- Pre-extraction in [`crates/zuit-lang-js/src/parse.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/parse.rs)

## References

- [CWE-480: Use of Incorrect Operator](https://cwe.mitre.org/data/definitions/480.html)
- [ESLint `no-cond-assign` rule](https://eslint.org/docs/rules/no-cond-assign)
