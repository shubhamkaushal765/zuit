---
title: BUG002-switch-fallthrough — Switch case falls through
sidebar_label: BUG002-switch-fallthrough
description: Flags switch cases that silently fall through to the next case (CWE-484). Add `break`/`return`/`throw`/`continue`, or annotate with `// falls through`.
---

# BUG002-switch-fallthrough — Switch case falls through

| Property   | Value                  |
| ---------- | ---------------------- |
| Dimension  | Maintainability        |
| Severity   | Medium                 |
| Confidence | High                   |
| CWE        | CWE-484                |
| Languages  | JavaScript, TypeScript |

## What it detects

A `case` (or `default:`) clause inside a `switch` statement that:

1. Is **not** the last clause in its `switch`, **and**
2. Has at least one statement in its body, **and**
3. Does **not** end with a terminating statement (`break`, `return`, `throw`,
   `continue`), **and**
4. Has **no** ESLint-style fallthrough comment immediately before the next
   case label.

The control falls through to the next clause silently — almost always a typo
for a missing `break`.

## Carve-outs

### Empty case grouping

Empty consequents are the idiomatic way to apply the same body to multiple
case values and are **not** flagged:

```js
// NOT flagged — intentional grouping
switch (x) {
  case 1:
  case 2:
  case 3:
    doMulti();
    break;
}
```

### `// falls through` comment

Following ESLint `no-fallthrough`, a comment matching
`/falls?\s*through/i` on the line immediately before the next `case`
label silences the finding. Both line comments and block comments work:

```js
switch (x) {
  case 1:
    doA();
    // falls through
  case 2:
    doB();
    break;
}

switch (x) {
  case 1:
    doA();
    /* fallthrough */
  case 2:
    doB();
    break;
}
```

## Why it matters

CWE-484 (Omitted Break Statement in Switch) is a textbook source of bugs.
The omitted `break` is invisible and the code still compiles, but the
following case body runs anyway and silently changes behavior.

```js
// Bug: forgot break — `doB()` always runs when x === 1
switch (x) {
  case 1:
    doA();
  case 2:
    doB();
    break;
}
```

## Examples — flagged

```js
// Plain fallthrough
switch (x) {
  case 1:
    doA();
  case 2:
    doB();
    break;
}

// Multiple cascading falls
switch (x) {
  case 1:
    doA();
  case 2:
    doB();
  case 3:
    doC();
    break;
}

// `default:` in the middle, falling through
switch (x) {
  case 1:
    doA();
    break;
  default:
    doDefault();
  case 2:
    doB();
    break;
}

// Block body without terminator
switch (x) {
  case 1: {
    doA();
  }
  case 2:
    doB();
    break;
}
```

## Examples — not flagged

```js
// Terminators stop fallthrough
switch (x) {
  case 1:
    doA();
    break;
  case 2:
    return doB();
  case 3:
    throw new Error('c');
}

// Last case can't fall through
switch (x) {
  case 1:
    doA();
    break;
  case 2:
    doB();  // last case
}

// Empty grouping
switch (x) {
  case 1:
  case 2:
    doMulti();
    break;
}

// Comment carve-out
switch (x) {
  case 1:
    doA();
    // falls through
  case 2:
    doB();
    break;
}
```

## Fix guidance

Add a terminating statement at the end of the case body, or — if the
fallthrough is intentional — add a `// falls through` comment immediately
before the next case label.

```js
// Before (bug):
switch (x) {
  case 1:
    doA();
  case 2:
    doB();
    break;
}

// After (fix):
switch (x) {
  case 1:
    doA();
    break;
  case 2:
    doB();
    break;
}
```

## Implementation

- [`crates/zuit-lang-js/src/analyzers/switch_fallthrough.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/switch_fallthrough.rs)
- Pre-extraction in [`crates/zuit-lang-js/src/parse.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/parse.rs)

## References

- [CWE-484: Omitted Break Statement in Switch](https://cwe.mitre.org/data/definitions/484.html)
- [ESLint `no-fallthrough` rule](https://eslint.org/docs/rules/no-fallthrough)
