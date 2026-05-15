---
title: MAINT007 — Excessive Return Statements
sidebar_label: MAINT007
description: Flags functions with more return statements than a threshold
---

# MAINT007-return-complexity — Excessive Return Statements

**Dimension:** Maintainability
**Default severity:** Low
**Languages:** All
**CWE:** [CWE-1121](https://cwe.mitre.org/data/definitions/1121.html)
**Last reviewed:** 2026-05-06

## What it detects

Flags functions with more return statements than a configurable threshold (default 4). A high return count often signals a function that is trying to do too many things; restructuring with guard clauses or helper functions typically improves readability and testability.

## Configuration

```toml
[rules."MAINT007-return-complexity"]
threshold = 4   # default
```

## Example — flagged

**Rust:**

```rust
pub fn classify(x: i32, y: i32, z: i32) -> &'static str {
    if x < 0 { return "negative x"; }
    if y < 0 { return "negative y"; }
    if z < 0 { return "negative z"; }
    if x == y { return "equal xy"; }
    if y == z { return "equal yz"; }
    "default"
    // 5 effective returns → flagged at default threshold of 4
}
```

## Example — not flagged

```rust
pub fn check(x: i32) -> &'static str {
    if x < 0 { return "negative"; }
    "non-negative"
    // 2 returns → clean
}
```

## Fix guidance

- Extract early-exit guards into a validation helper.
- Use `match` / pattern-matching to collapse multiple branches.
- Split the function into smaller focused callables.

## Implementation

- Source: [crates/zuit-analyzers/src/return_complexity.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/return_complexity.rs)
- Threshold read via `Config::rule_threshold("MAINT007-return-complexity", 4)`.

## References

- [CWE-1121](https://cwe.mitre.org/data/definitions/1121.html)
- [Refactoring Guru — Replace Nested Conditional with Guard Clauses](https://refactoring.guru/replace-nested-conditional-with-guard-clauses)
