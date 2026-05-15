---
title: MAINT001-cyclomatic — Cyclomatic complexity
sidebar_label: MAINT001-cyclomatic
description: Detects functions whose cyclomatic complexity exceeds a configurable threshold.
---

# MAINT001-cyclomatic — Cyclomatic complexity

| Property         | Value           |
| ---------------- | --------------- |
| Dimension        | Maintainability |
| Default severity | Medium          |
| Languages        | All             |

## What it detects

Flags functions whose cyclomatic complexity exceeds a configurable threshold. Cyclomatic complexity measures the number of independent execution paths through a function: higher values indicate code that is harder to test, understand, and maintain. The default threshold is 10.

## Why it matters

High cyclomatic complexity correlates with both defect density and maintenance cost. Functions exceeding a reasonable threshold are candidates for refactoring into smaller, single-purpose helpers. See [Thomas J. McCabe, "A Complexity Measure"](https://www.microsoft.com/en-us/research/publication/a-complexity-measure/) for the foundational definition.

## Configuration

| Parameter | Type | Default | Notes |
| --- | --- | --- | --- |
| `threshold` | u32 | 10 | Functions at or below this value are not flagged. |

Set in `zuit.toml`:

```toml
[rules.MAINT001-cyclomatic]
threshold = 10
```

## How it's counted

### Rust

Starting baseline: **1** (every function has one path).

Add +1 for each of:

- `if` expression (including `if let`)
- `else if` arm (each additional `else if` is a separate `if` node)
- `while` / `while let` loop
- `for` loop
- `loop` with a conditional `break` expression (each `break <expr>` counts)
- Each `match` arm **beyond the first** (so a 3-arm match adds +2)
- `?` operator (try expressions; each `ExprTry` in the body)
- Short-circuit `&&` and `||` binary operators (each occurrence adds +1)

### Python

Starting baseline: **1** (every function has one path).

Add +1 for each of:

- `if` statement (the initial `if` test; each `elif` branch is a separate `If` node in the AST, so each also counts +1)
- `while` loop
- `for` loop (including `async for`)
- `with` statement (including `async with`)
- Each `except` handler **beyond the first** (first handler path is covered by baseline)
- `BoolOp` with operator `And` or `Or`: each **occurrence** of `and`/`or` adds one (e.g., `a and b and c` = +2)
- `if` clause inside a comprehension (e.g., `[x for x in y if cond]`)

## Examples — flagged

**Rust:**

```rust
pub fn complex_classify(x: i32, flag: bool, mode: u8) -> &'static str {
    if x < 0 {                 // +1
        if flag {              // +1
            "negative-flagged"
        } else {
            "negative"
        }
    } else if x == 0 {         // +1
        "zero"
    } else if mode == 1 {      // +1
        if x > 100 {           // +1
            "large-mode1"
        } else {
            "small-mode1"
        }
    } else if mode == 2 {      // +1
        match x % 3 {          // +2 (2 arms beyond first)
            0 => "div3-mode2",
            1 => "rem1-mode2",
            _ => "rem2-mode2",
        }
    } else if flag && x > 50 { // +1 for if, +1 for &&
        "flagged-large"
    } else {
        "other"
    }
}
// Total: 1 + 8 = 9 (or higher with all branches counted)
```

**Python:**

```python
def complex_logic(a, b, c, d, e):
    if a > 0:          # +1
        if b > 0:      # +1
            if c > 0:  # +1
                if d > 0:  # +1
                    if e > 0:  # +1
                        return "all positive"
                    elif e < -10:  # +1
                        return "e very negative"
                    else:
                        return "e small negative"
                elif d < 0:  # +1
                    return "d negative c positive"
            elif c < 0:  # +1
                return "c negative b positive"
        elif b < 0:  # +1
            return "b negative a positive"
    elif a < 0:  # +1
        return "a negative"
    return "default"
# Total: 1 + 10 = 11
```

## Examples — not flagged

**Rust:**

```rust
pub fn simple_classify(x: i32) -> &'static str {
    if x < 0 {         // +1
        "negative"
    } else if x == 0 { // +1
        "zero"
    } else {
        "positive"
    }
}
// Total: 1 + 2 = 3 (below threshold)
```

**Python:**

```python
def simple_sum(a, b, c):
    return a + b + c
# Total: 1 (baseline only)
```

## Fix guidance

- **Extract helpers**: Break the function into smaller, single-purpose functions. Each helper should handle one branch or concern.
- **Use guard clauses**: Replace deeply nested `if`-`else` chains with early returns or guard patterns to flatten the structure.
- **Consider polymorphism**: If a large `match` (Rust) or `if`-`elif` (Python) tree exists, consider a trait or protocol with multiple implementations.
- **Reduce conditionals**: Look for duplicate logic that can be parameterized or consolidated.
- **Test incrementally**: As you refactor, run tests to ensure correctness; smaller functions are easier to unit test.

## Implementation

- Source: [`crates/zuit-analyzers/src/cyclomatic.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/cyclomatic.rs)
- Complexity computation: [`crates/zuit-lang-rust/src/complexity.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/complexity.rs), [`crates/zuit-lang-python/src/complexity.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/complexity.rs)

## References

- [McCabe, T. J. (1976). "A Complexity Measure"](https://www.microsoft.com/en-us/research/publication/a-complexity-measure/) — foundational definition of cyclomatic complexity.
- [Cyclomatic complexity on Wikipedia](https://en.wikipedia.org/wiki/Cyclomatic_complexity)
