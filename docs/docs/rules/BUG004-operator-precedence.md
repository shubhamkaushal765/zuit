---
title: BUG004-operator-precedence — Operator precedence trap
sidebar_label: BUG004-operator-precedence
description: Flags bitwise operators mixed with comparison operators without parentheses in JS/TS (CWE-783). Add parens to disambiguate.
---

# BUG004-operator-precedence — Operator precedence trap

| Property   | Value                  |
| ---------- | ---------------------- |
| Dimension  | Maintainability        |
| Severity   | Medium                 |
| Confidence | High                   |
| CWE        | CWE-783                |
| Languages  | JavaScript, TypeScript |

## What it detects

Bitwise operators (`&`, `|`, `^`) mixed with comparison operators (`==`, `===`, `!=`, `!==`, `<`, `<=`, `>`, `>=`) without parentheses, or bitwise operators combined with unary `!` in ways that may surprise.

**Pattern 1:** Bitwise operator at the outer level with comparison at inner level:

```js
a & b == c    // parses as  a & (b == c)  but looks like  (a & b) == c
a == b & c    // parses as  a == (b & c)
a | b != c    // parses as  a | (b != c)
```

**Pattern 2:** Unary negation `!` applied to an identifier or member expression, then combined with bitwise:

```js
!x & y        // parses as  (!x) & y  but `!` binds tighter than `&`
y & !x        // unary negation on right side
!obj.flag & MASK
```

In JavaScript and TypeScript, comparison operators bind **tighter** than bitwise operators. This almost never matches developer intent; the fix is to add parentheses.

## Why it matters

CWE-783 (Operator Precedence Logic Error) documents this as a real source of bugs.
The JavaScript operator precedence is counterintuitive compared to many other
languages. The expression parses and runs, but performs the wrong bitwise or
logical operation, silently changing behavior.

```js
// Bug: compares (b == c), then bitwise-ands with a
let mask = flags & ENABLED_FLAG == true;  // parses as  flags & (ENABLED_FLAG == true)
// true/false → 1/0, so this is flags & 0 or flags & 1, wrong

// Intended:
let mask = (flags & ENABLED_FLAG) == true;  // or check the bit first, then compare
```

## Examples — flagged

```js
// Bitwise AND with comparison on right
let r = a & b == c;

// Bitwise AND with comparison on left
let r = a == b & c;

// Bitwise OR with comparison
let r = a | b == c;

// Bitwise XOR with comparison
let r = a ^ b != c;

// Unary negation left — !identifier with bitwise
let r = !x & y;

// Unary negation right — symmetric pattern
let r = y & !x;

// Unary negation on member expression
let r = !obj.flag & MASK;
```

## Examples — not flagged

```js
// Parentheses disambiguate — bitwise wrapped
let r = (a & b) == c;

// Parentheses disambiguate — comparison wrapped
let r = a & (b == c);

// Bitwise wrapped in unary — outer is UnaryExpression
let r = !(x & y);

// Unary applied to function call — call not in allowlist
let r = !foo() & y;

// Unary applied to parenthesized comparison
let r = !(a == b) & c;

// Shift + comparison — shift binds tighter in JS, no flag
let r = a << b == c;  // parses as (a << b) == c

// Chained comparisons without bitwise
let r = a == b == c;
```

## Shift and comparison

Bitwise **shift** operators (`<<`, `>>`, `>>>`) are **not** flagged when combined with comparisons. In JavaScript, shift operators bind tighter than comparison operators, so `a << b == c` naturally parses as `(a << b) == c` — the intuitive reading. There is no precedence trap here, and flagging would be a false positive.

## Language notes

**JavaScript and TypeScript only.** Rust and Python both bind bitwise `&`, `|`, `^` **tighter** than comparison operators, so `a & b == c` naturally parses as `(a & b) == c` — the developer's intent. There is no equivalent footgun in those languages. BUG004 applies only to JS/TS.

## Fix guidance

Wrap the lower-precedence operation in parentheses to make intent explicit:

```js
// Before (bug):
let result = flags & MASK == expectedValue;

// After (fix):
let result = (flags & MASK) == expectedValue;

// Or, if the comparison was intended first:
let result = flags & (MASK == expectedValue);
```

For unary negation, either wrap the bitwise operation or reorder:

```js
// Before (bug):
let r = !flag & permission;

// After (fix — bitwise first, then negate):
let r = !(flag & permission);

// After (alternative — negate first, explicit):
let r = (!flag) & permission;
```

## Configuration

Add a `[rules."BUG004-operator-precedence"]` block to `zuit.toml` to override severity or enable per-glob:

```toml
[rules."BUG004-operator-precedence"]
severity = "high"

[[rules."BUG004-operator-precedence".overrides]]
glob = "**/*.test.ts"
severity = "warning"
```

See [per-rule configuration](../configuration/per-rule-config.md) for all options.

## Suppression

Suppress this rule using the `// zuit: ignore BUG004-operator-precedence` line directive:

```js
// zuit: ignore BUG004-operator-precedence
let r = a & b == c;
```

Or suppress at file level:

```js
// zuit: ignore-file BUG004-operator-precedence
```

See [suppression](suppression.md) for full details.

## Related rules

- `BUG001-assignment-in-condition` (CWE-480) — another JS/TS operator confusion trap.
- `BUG002-switch-fallthrough` (CWE-484) — another JS/TS structural Bug rule.

## References

- [CWE-783 — Operator Precedence Logic Error](https://cwe.mitre.org/data/definitions/783.html)
- [MDN — JavaScript operator precedence table](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Operator_precedence)
- [ESLint `no-mixed-operators`](https://eslint.org/docs/latest/rules/no-mixed-operators) — related lint
