---
title: MAINT005-deep-nesting — Deep nesting
sidebar_label: MAINT005-deep-nesting
description: Detects functions whose maximum nesting depth exceeds a configurable threshold.
---

# MAINT005-deep-nesting — Deep nesting

| Property         | Value           |
| ---------------- | --------------- |
| Dimension        | Maintainability |
| Default severity | Medium          |
| Languages        | All             |

## What it detects

Flags functions whose maximum nesting depth exceeds a configurable threshold. Nesting depth measures how deeply indented control structures are within a function: higher values indicate code that is harder to understand, test, and maintain. The default threshold is 4.

## Why it matters

Deep nesting makes code harder to follow, increases cognitive load, and can hide bugs. Functions with excessive nesting depth are candidates for refactoring into smaller, single-purpose helpers or rewritten with guard clauses and early returns. Research shows that nesting depth beyond 2–3 levels significantly impacts readability and maintenance costs.

## Configuration

| Parameter | Type | Default | Notes |
| --- | --- | --- | --- |
| `threshold` | u32 | 4 | Functions at or below this depth are not flagged. |

Set in `zuit.toml`:

```toml
[rules.MAINT005-deep-nesting]
threshold = 4
```

## How it's counted

### Rust

Nesting depth is the maximum level of indentation in any control structure:

- `if` expression: increases depth
- `else` / `else if`: same depth as `if`
- `while` / `while let` loop: increases depth
- `for` loop: increases depth
- `loop` with body: increases depth
- `match` expression: increases depth (each arm is the same depth)
- `block` (`{ }`) expressions: increases depth
- Nested function definitions: increases depth

```rust
pub fn nested_example(x: i32) -> i32 {
    // Depth 0
    if x > 0 {
        // Depth 1
        if x > 10 {
            // Depth 2
            if x > 100 {
                // Depth 3
                if x > 1000 {
                    // Depth 4 (at threshold)
                    if x > 10000 {
                        // Depth 5 (exceeds threshold of 4)
                        return x * 2;
                    }
                }
            }
        }
    }
    x
}
```

### Python

Nesting depth is the maximum indentation level in any control structure:

- `if` / `elif` / `else`: increases depth
- `for` / `async for` loop: increases depth
- `while` loop: increases depth
- `with` / `async with`: increases depth
- `try` / `except` / `finally`: increases depth
- List/set/dict comprehensions: increases depth
- Nested function definitions: increases depth
- Class definitions: increases depth

```python
def nested_example(x):
    # Depth 0
    if x > 0:
        # Depth 1
        if x > 10:
            # Depth 2
            if x > 100:
                # Depth 3
                if x > 1000:
                    # Depth 4 (at threshold)
                    if x > 10000:
                        # Depth 5 (exceeds threshold of 4)
                        return x * 2
    return x
```

## Examples — flagged

**Rust:**

```rust
pub fn deeply_nested(x: i32) -> i32 {
    if x > 0 {        // Depth 1
        if x > 10 {   // Depth 2
            if x > 100 {   // Depth 3
                if x > 1000 {   // Depth 4
                    if x > 10000 {   // Depth 5 (exceeds threshold of 4)
                        return x * 2;
                    }
                }
            }
        }
    }
    x
}
```

**Python:**

```python
def deeply_nested(x):
    if x > 0:        # Depth 1
        if x > 10:   # Depth 2
            if x > 100:   # Depth 3
                if x > 1000:   # Depth 4
                    if x > 10000:   # Depth 5 (exceeds threshold of 4)
                        return x * 2
    return x
```

## Examples — not flagged

**Rust:**

```rust
pub fn moderate_nesting(x: i32) -> i32 {
    if x > 0 {        // Depth 1
        if x > 10 {   // Depth 2
            if x > 100 {   // Depth 3
                if x > 1000 {   // Depth 4
                    return x * 2;
                }
            }
        }
    }
    x
}
// Maximum depth: 4 (at threshold, not flagged)
```

**Python:**

```python
def moderate_nesting(x):
    if x > 0:        # Depth 1
        if x > 10:   # Depth 2
            if x > 100:   # Depth 3
                if x > 1000:   # Depth 4
                    return x * 2
    return x
# Maximum depth: 4 (at threshold, not flagged)
```

## Fix guidance

- **Extract helper functions**: Move nested blocks into separate functions. Each helper should handle one concern.
- **Use guard clauses**: Replace deeply nested `if` chains with early returns at the top of the function.
- **Flatten with boolean conditions**: Combine multiple `if` checks into a single condition where appropriate.
- **Invert logic**: Use `if not condition: return` (guard) rather than `if condition: { do work }`.
- **Use polymorphism**: If a large `match` or `if`-`elif` tree governs behavior, consider a trait or protocol with implementations.
- **Loop refactoring**: Extract map/filter/reduce operations into helper functions.

## Implementation

- Source: [`crates/zuit-analyzers/src/deep_nesting.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/deep_nesting.rs)
- Nesting computation: [`crates/zuit-lang-rust/src/complexity.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/complexity.rs), [`crates/zuit-lang-python/src/complexity.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/complexity.rs)

## References

- [Cognitive Complexity: A new way of measuring understandability](https://www.sonarsource.com/docs/SonarSourceWhitePaper-CognitiveComplexity.pdf) — includes discussion of nesting depth and readability.
- [CMS Code Quality Guidance](https://digital.cms.gov/guides/code-quality/) — recommends limiting nesting depth to 2–3 levels.
- [Code Complete by Steve McConnell](https://www.oreilly.com/library/view/code-complete-2nd/0735619670/) — Chapter 32 discusses readability and nesting depth limits.
