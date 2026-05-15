---
title: MAINT002 — Cognitive Complexity
sidebar_label: MAINT002
description: Flags functions with high cognitive complexity due to nested control flow
---

# MAINT002-cognitive — Cognitive Complexity

**Dimension:** Maintainability
**Default severity:** Medium
**CWE:** CWE-1121
**Languages:** All
**Last reviewed:** 2026-05-05

## What it detects

Flags functions whose cognitive complexity exceeds a configurable threshold (default 15). Cognitive complexity measures how difficult the control flow of a function is to *understand*, giving extra weight to structures that are already nested inside other control-flow constructs. Higher values indicate code that is harder to read and reason about, even when the cyclomatic complexity is moderate.

## Why it matters

A function with 10 branches at the top level is easier to comprehend than a function with 5 branches nested 4 levels deep. Cognitive complexity (the Sonar variant, introduced by G. Ann Campbell) captures this difference by adding a **nesting penalty**: each control-flow construct adds `1 + depth` rather than a flat `+1`. This makes the metric a more faithful proxy for the human cost of reading code.

High cognitive complexity typically signals that a function has grown too large or that nested logic should be extracted into helpers.

## Configuration

| Parameter | Type | Default | Notes |
|-----------|------|---------|-------|
| `threshold` | u32 | 15 | Functions at or below this value are not flagged. |

Set in `zuit.toml`:
```toml
[rules.MAINT002-cognitive]
threshold = 15
```

## Metric definition (Sonar variant)

The Sonar-style cognitive complexity differs from cyclomatic complexity in two key ways:

1. **Nesting penalty**: A control-flow construct that appears inside another adds `1 + current_depth` rather than a flat `+1`. Nesting is tracked separately from the score: entering an `if`, `while`, `for`, `loop`, or `match` (Rust) / `switch` (JS) increments the depth counter, which is restored on exit.

2. **Boolean operator chains**: A run of consecutive identical boolean operators (`&&` or `||`) counts as **one** `+1` for the whole chain, not per operator. (A `+1` for each `&&`/`||` is still added to *cyclomatic* complexity.)

### Per-language rules

Each frontend documents its exact counting rules in its `complexity.rs` module:

- **Rust**: see [crates/zuit-lang-rust/src/complexity.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/complexity.rs) — increments for `if` (incl. `if let`), `while`/`while let`, `for`, `loop`, `match`, closures, and boolean chains.
- **Python**: see [crates/zuit-lang-python/src/complexity.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/complexity.rs) — increments for `if`/`elif`/`else`, `for`/`async for`, `while`, `with`/`async with`, `try`/`except` blocks, nested functions, and `and`/`or` operators.
- **JS/TS**: see [crates/zuit-lang-js/src/complexity.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/complexity.rs) — increments for `if`, `while`/`do-while`, `for`/`for-in`/`for-of`, `switch`, `try`/`catch`, nested functions, arrow expressions, and `&&`/`||`/`??` operators.

## Example — flagged

**Rust** (cognitive ≈ 25):

```rust
pub fn high_cognitive(a: i32, b: i32, c: i32, d: i32, e: i32) -> &'static str {
    if a < 0 {           // +1 (depth 0)
        if b < 0 {       // +2 (depth 1)
            if c < 0 {   // +3 (depth 2)
                if d < 0 {   // +4 (depth 3)
                    if e < 0 {   // +5 (depth 4)
                        "all-negative"
                    } else {
                        "e-non-negative"
                    }
                } else if d > 10 {  // +4 (depth 3, else-if re-enters at depth 0 in Rust)
                    "d-large"
                } else {
                    "d-mid"
                }
            } else if c > 10 { // ...
                "c-large"
            } else { "c-mid" }
        } else if b > 10 { "b-large" } else { "b-mid" }
    } else if a > 10 { "a-large" } else { "a-mid" }
}
```

**Python** (cognitive ≈ 30):

```python
def complex_logic(a, b, c, d, e):
    if a < 0:           # +1 (depth 0)
        if b < 0:       # +2 (depth 1)
            if c < 0:   # +3 (depth 2)
                if d < 0:   # +4 (depth 3)
                    if e < 0:   # +5 (depth 4)
                        return "all-negative"
                    elif e > 10:  # +5 (depth 4)
                        return "e-large"
                elif d > 10:  # +4 (depth 3)
                    return "d-large"
            elif c > 10:  # +3 (depth 2)
                return "c-large"
        elif b > 10:  # +2 (depth 1)
            return "b-large"
    elif a > 10:  # +1 (depth 0)
        return "a-large"
    # Total ≈ 30
```

**JS/TS** (cognitive ≈ 30 — same logic as Python):

```typescript
export function complexLogic(a: number, b: number, c: number, d: number, e: number): string {
  if (a < 0) {         // +1
    if (b < 0) {       // +2
      if (c < 0) {     // +3
        if (d < 0) {   // +4
          if (e < 0) { return "all-negative"; }  // +5
          else if (e > 10) { return "e-large"; } // +5
        } else if (d > 10) { return "d-large"; } // +4
      } else if (c > 10) { return "c-large"; }   // +3
    } else if (b > 10) { return "b-large"; }     // +2
  } else if (a > 10) { return "a-large"; }       // +1
  return "a-mid";
}
```

## Example — not flagged

**Rust** (cognitive = 3):

```rust
pub fn classify(x: i32) -> &'static str {
    if x < 0 {         // +1
        "negative"
    } else if x == 0 { // +1 (re-enters at depth 0 in Rust's visitor)
        "zero"
    } else {
        "positive"
    }
}
// Total: 2 (below threshold 15)
```

**Python** (cognitive = 1):

```python
def simple_sum(a, b, c):
    return a + b + c
# Total: 0 (below threshold 15)
```

## Fix guidance

- **Extract helpers**: Move deeply-nested branches into separate, single-purpose functions. Each helper typically lowers the cognitive score of both the caller and the helper.
- **Early returns / guard clauses**: Replace nested `if-else` chains with early `return` / `raise` / `throw` at the top of the function to flatten the structure.
- **Inversion**: Instead of `if condition { long block } else { short block }`, invert and return early for the short block.
- **Decompose conditions**: Give complex boolean expressions a named variable so the nesting is replaced by a linear sequence of assignments.
- **Use polymorphism**: A large `match` (Rust) or `if-elif` (Python) dispatch can often become a trait/protocol with per-type implementations.

## Implementation

- Source: [crates/zuit-analyzers/src/cognitive.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/cognitive.rs)
- Complexity computation: see per-language `complexity.rs` modules linked in "Per-language rules" above.
- Severity / supported languages: see `RuleMeta` in source.

## References

- [G. Ann Campbell, "Cognitive Complexity: A New Way of Measuring Understandability"](https://www.sonarsource.com/docs/CognitiveComplexity.pdf) — original Sonar specification.
- [CWE-1121: Excessive McCabe Cyclomatic Complexity](https://cwe.mitre.org/data/definitions/1121.html) — the nearest CWE mapping (no dedicated CWE exists for cognitive complexity).
