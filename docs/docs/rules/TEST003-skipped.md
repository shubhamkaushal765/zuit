---
title: TEST003 — Skipped or Ignored Tests
sidebar_label: TEST003
description: Detects skip/ignore markers in test files
---

# TEST003-skipped — Skipped or Ignored Tests

**Dimension:** TestSmell
**Default severity:** Info
**Languages:** All
**Last reviewed:** 2026-05-05

## What it detects

Detects skip / ignore markers in test source files. One finding is emitted per marker, located at the byte range of the matched text on that line.

## Recognised markers

The analyzer uses a single compiled regex with the `(?m)` multiline flag to scan the entire file source in one pass:

### Rust

| Marker | Example |
|---|---|
| `#[ignore]` | `#[ignore]` |
| `#[ignore = "…"]` | `#[ignore = "not yet implemented"]` |

### Python

| Marker | Example |
|---|---|
| `@pytest.mark.skip` | `@pytest.mark.skip` |
| `@pytest.mark.skip(reason="…")` | `@pytest.mark.skip(reason="slow")` |
| `@unittest.skip` | `@unittest.skip` |
| `@skip` | `@skip` |

### JavaScript / TypeScript

| Marker | Example |
|---|---|
| `it.skip(` | `it.skip("should …", () => { … })` |
| `describe.skip(` | `describe.skip("suite …", () => { … })` |
| `xit(` | `xit("should …", () => { … })` |
| `xdescribe(` | `xdescribe("suite …", () => { … })` |
| `test.skip(` | `test.skip("should …", () => { … })` |

## Why it matters

Skipped tests that are never re-enabled become dead code. They give a false impression of coverage and often refer to bugs or features that were never finished. Long-lived skipped tests rot silently as the code they target changes.

## Configuration

No configuration knobs. All markers are always detected.

## Example — flagged

**Rust:**

```rust
#[test]
#[ignore]
fn test_plain_ignore() { assert_eq!(1, 1); }

#[test]
#[ignore = "not yet implemented"]
fn test_ignore_with_reason() { assert_eq!(2, 2); }
```

**Python:**

```python
@pytest.mark.skip
def test_with_pytest_skip():
    assert True

@unittest.skip
def test_with_unittest_skip():
    assert True
```

**JavaScript:**

```typescript
it.skip("should do something", () => {
    expect(true).toBe(true);
});

xit("should do something else", () => {
    expect(true).toBe(true);
});
```

## Fix guidance

- Re-enable the test and fix the underlying issue it was guarding.
- If the test is permanently obsolete, delete it so it stops appearing in coverage reports.
- Document *why* a test is skipped with a tracking issue number in the skip reason string (e.g. `#[ignore = "issue #123: flaky on CI"]`).

## Implementation

- Source: [crates/zuit-analyzers/src/skipped.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/skipped.rs)
- Severity / supported languages: see `META` constant in source.

## References

- [pytest: Skipping tests](https://docs.pytest.org/en/stable/how-to/skipping.html)
- [Rust: `#[ignore]` attribute](https://doc.rust-lang.org/reference/attributes/testing.html)
- [Jest: `test.skip`](https://jestjs.io/docs/api#testskipname-fn)
