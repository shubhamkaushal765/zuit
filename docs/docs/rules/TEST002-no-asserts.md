---
title: TEST002 — Test File With No Assertions
sidebar_label: TEST002
description: Flags test files that lack any assertions
---

# TEST002-no-asserts — Test File With No Assertions

**Dimension:** TestSmell
**Default severity:** Medium
**Languages:** All
**Last reviewed:** 2026-05-05

## What it detects

Flags test files that contain at least one test function but no recognised assertion token anywhere in the source text.

A file is considered a "test file" when the [`SemanticIndex`] contains at least one `FunctionLike` entry with `is_test = true`. If the raw source text of such a file matches none of the assertion patterns listed below, one finding spanning the whole file is emitted.

## Recognised assertion tokens

The analyzer uses a single compiled regex with the following alternatives:

| Token | Language / Framework |
|---|---|
| `assert` | Python built-in, generic |
| `assert_eq!` | Rust standard macro |
| `assert_ne!` | Rust standard macro |
| `panic!` | Rust macro (counts as assertion of unreachability) |
| `assertEqual` | Python `unittest.TestCase` |
| `assertTrue` | Python `unittest.TestCase` |
| `assertFalse` | Python `unittest.TestCase` |
| `assertIn` | Python `unittest.TestCase` |
| `assertIs` | Python `unittest.TestCase` |
| `expect` | Jest, Chai, Vitest, generic |
| `should.` | Chai `should`-style |
| `chai.expect` | Chai explicit-import style |
| `sinon.assert` | Sinon.JS spy/stub assertions |
| `jest.` | Jest utility assertions (`jest.fn`, `jest.spyOn`, etc.) |

## Why it matters

A test that never asserts anything will always pass regardless of the code under test. These "vacuous" tests give a false sense of coverage and provide no regression protection.

## Configuration

No configuration knobs. The assertion pattern set is fixed.

## Example — flagged

**Python:**

```python
def test_thing():
    # No assertion → TEST002 will fire.
    x = 1
    _ = x + 1
```

**Rust:**

```rust
#[test]
fn test_thing() {
    // No assertion → TEST002 will fire.
    let _ = 1;
}
```

**JavaScript:**

```typescript
function test_thing(): void {
    // No assertion → TEST002 will fire.
    const x = 1;
}
```

## Example — not flagged

**Python:**

```python
def test_thing():
    x = 1
    assert x == 1   # ← assertion found; file is clean
```

**Rust:**

```rust
#[test]
fn test_thing() {
    let x = 1;
    assert_eq!(x, 1);  // ← assertion found; file is clean
}
```

## Fix guidance

- Add at least one `assert` / `expect` / `assertEqual` / `assert_eq!` call (or equivalent for your test framework) to every test function.
- Consider using a linter rule (e.g. `pytest`'s `--strict-markers`, `eslint-plugin-jest/no-standalone-expect`) to enforce assertions automatically.

## Implementation

- Source: [crates/zuit-analyzers/src/no_asserts.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/no_asserts.rs)
- Severity / supported languages: see `META` constant in source.

## References

- [OWASP Testing Guide: Test Coverage](https://owasp.org/www-project-testing/)
- [xUnit Patterns: Assertion-Free Test](http://xunitpatterns.com/Assertion-Free%20Test.html)
