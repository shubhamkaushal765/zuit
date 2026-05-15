---
title: MAINT014-commented-out-code — commented-out code block
sidebar_label: MAINT014-commented-out-code
description: Detects contiguous comment blocks that look like commented-out source code rather than English prose.
---

# MAINT014-commented-out-code — commented-out code block

| Property         | Value             |
| ---------------- | ----------------- |
| Dimension        | Maintainability   |
| Default severity | Info              |
| CWE              | CWE-1085          |
| Languages        | All               |

## What it detects

Groups consecutive comment lines (no blank line between them) into blocks and
checks whether the block looks like commented-out source code rather than
human-readable prose.

A block fires when **all** of the following hold:

1. The block has **≥ 3 lines**.
2. **≥ 50% of non-blank lines** contain at least one code-like token marker:
   `{`, `}`, `;`, `=`, `(`, `)`, or a common keyword (`if`, `else`, `for`,
   `while`, `return`, `def`, `function`, `let`, `const`, `var`, `fn`, `pub`,
   `impl`, `class`).
3. **≥ 1 line** contains structural punctuation (`{`, `}`, `;`, `(`, or `)`).
4. **No line** matches the annotation pattern `^\s*[A-Z]+:` (e.g. `TODO:`,
   `FIXME:`, `NOTE:`) — those are already covered by `DOC002-todo-fixme`.

One finding is emitted **per block**, not per line.  Confidence is low:
consider this a hint to review, not an actionable defect.

## Why it matters

Commented-out code is a maintenance liability: it confuses readers, may
contain outdated logic, and inflates diff noise during code review.  Source
control already preserves history — dead code should be deleted, not hidden
behind comment markers.

## Examples — flagged

```python
# def old_calculate(x, y):
#     result = x * y
#     if result > 100:
#         return result - 100
#     return result
return x * x
```

```rust
// let old_result = x * 2;
// if old_result > 100 {
//     return old_result - 100;
// }
x * x
```

```typescript
// function oldCalculate(x: number, y: number) {
//   const result = x * y;
//   if (result > 100) {
//     return result - 100;
//   }
//   return result;
// }
```

## Examples — not flagged

```python
# This module provides utility functions.
# See the README for usage examples.
# NOTE: This is a simple implementation.
```

Single-line prose, annotation blocks (TODO/FIXME/NOTE), and blocks that
don't reach the minimum density threshold are all suppressed.

## Configuration

No configuration knobs in v1.  The rule fires at `Info` severity and
`Confidence: Low`; use `zuit: ignore MAINT014-commented-out-code` on the
first line of the block to suppress individual instances.

## Fix

Delete the commented-out code.  If you need to preserve context, replace it
with a brief prose explanation or a link to the relevant commit/PR.
