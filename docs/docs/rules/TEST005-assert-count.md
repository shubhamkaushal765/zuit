---
title: TEST005 — Too Many Assertions in One Test
sidebar_label: TEST005
description: Flags test functions with excessive assertion count
---

# TEST005-assert-count — Too Many Assertions in One Test

**Dimension:** TestSmell
**Default severity:** Low
**Languages:** All
**Last reviewed:** 2026-05-06

## What it detects

For every test function (`is_test == true`), counts assertion tokens in the function body using the same pattern as `TEST002-no-asserts`. If the count exceeds the threshold (default 10), a finding is emitted.

## Configuration

```toml
[rules."TEST005-assert-count"]
threshold = 10   # default
```

## Why it matters

A test that makes many unrelated assertions is hard to understand and diagnose on failure — you must read the entire test to determine which assertion failed and why. Each test should verify a single behaviour.

## Example — flagged

```python
def test_everything():
    assert 1 == 1
    assert 2 == 2
    # ... 9 more asserts
    assert 11 == 11   # ← 11 assertions > threshold, flagged
```

## Example — not flagged

```python
def test_addition():
    assert add(1, 2) == 3   # single focused assertion, clean
```

## Fix guidance

- Split the overloaded test into multiple smaller tests, each with a descriptive name indicating what it verifies.
- Group related assertions into a dedicated helper or use parameterised tests.

## Implementation

- Source: [crates/zuit-analyzers/src/assert_count.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/assert_count.rs)
- Reuses the assertion regex from `no_asserts.rs`.
- Threshold read via `Config::rule_threshold("TEST005-assert-count", 10)`.
