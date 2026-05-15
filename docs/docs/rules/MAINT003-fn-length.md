---
title: MAINT003-fn-length — Function length
sidebar_label: MAINT003-fn-length
description: Detects functions whose body exceeds a configurable line-count threshold.
---

# MAINT003-fn-length — Function length

| Property         | Value           |
| ---------------- | --------------- |
| Dimension        | Maintainability |
| Default severity | Low             |
| Languages        | All             |

## What it detects

Flags functions whose body spans more than a configurable number of lines. The default threshold is 80 lines. Length is calculated as `end_line - start_line + 1`, where lines are obtained from the function's body source span. This rule encourages breaking long functions into smaller, more focused helpers.

## Why it matters

Long functions are harder to understand, test, and maintain. They often indicate mixed concerns — a function trying to do too much. By enforcing a reasonable line limit, you encourage developers to refactor early and keep functions focused on a single responsibility. Shorter functions also reduce cognitive load and make unit testing more straightforward.

## Configuration

| Parameter | Type | Default | Notes |
| --- | --- | --- | --- |
| `threshold` | u32 | 80 | Functions whose body exceeds this many lines are flagged. |

Set in `zuit.toml`:

```toml
[rules.MAINT003-fn-length]
threshold = 80
```

## How it's measured

Length is computed from the **body** of the function, not the entire declaration.

### Rust

For a Rust function, the body span begins at the opening brace `{` and ends at the closing brace `}`. Filler code, comments, and blank lines all count.

```rust
pub fn example(x: i32) -> i32 {
    // Line 1 of body
    let _ = 0;
    // Line 3
    x + 1
}
// The body is 5 lines long.
```

### Python

For a Python function, the body begins with the first statement after `def` and the colon, and includes all indented code up to the next unindented line.

```python
def example(x: int) -> int:
    # Line 1 of body
    _ = 0
    # Line 3
    return x + 1
# The body is 5 lines long.
```

## Examples — flagged

**Rust:**

```rust
pub fn long_processing(data: Vec<i32>) -> Vec<i32> {
    let mut result = Vec::new();
    for item in data {
        let processed = item * 2;
        result.push(processed);
    }
    // ... 75+ more lines of similar logic ...
    result
}
// Total body: 85+ lines → flagged
```

**Python:**

```python
def long_processing(data: list) -> list:
    result = []
    for item in data:
        processed = item * 2
        result.append(processed)
    # ... 75+ more lines of similar logic ...
    return result
# Total body: 85+ lines → flagged
```

## Examples — not flagged

**Rust:**

```rust
pub fn short_processing(x: i32) -> i32 {
    let result = x * 2;
    result + 1
}
// Total body: 3 lines → not flagged (below 80)
```

**Python:**

```python
def short_processing(x: int) -> int:
    result = x * 2
    return result + 1
# Total body: 3 lines → not flagged (below 80)
```

## Fix guidance

- **Extract cohesive helpers**: Identify distinct phases or concerns within the function and extract each into a separate, well-named helper function.
- **Use a builder or state machine**: If the function orchestrates a complex workflow, consider breaking it into a series of smaller steps, each with a clear contract.
- **Reduce nesting**: Flatten deeply nested blocks using guard clauses (early returns), which also improves readability.
- **Parameterize repeated blocks**: If the function contains similar logic repeated multiple times, extract it to a parameterized helper.
- **Consider data-driven approaches**: Replace long chains of conditionals with lookup tables or configuration-driven logic.

## Implementation

- Source: [`crates/zuit-analyzers/src/fn_length.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/fn_length.rs)
- Test fixtures: [`fixtures/rust/long_fn/`](https://github.com/shubhamkaushal765/zuit/blob/main/fixtures/rust/long_fn/) and [`fixtures/python/long_fn/`](https://github.com/shubhamkaushal765/zuit/blob/main/fixtures/python/long_fn/)

## References

- [Functions — Best Practices](https://en.wikipedia.org/wiki/Function_(computer_programming)#Best_practices)
- [Code Smell: Long Method](https://refactoring.guru/smells/long-method)
- [Single Responsibility Principle](https://en.wikipedia.org/wiki/Single-responsibility_principle)
