---
title: TEST004 — Test Uses Time or Randomness
sidebar_label: TEST004
description: Flags test functions that depend on time or randomness
---

# TEST004-flaky-time — Test Uses Time or Randomness

**Dimension:** TestSmell
**Default severity:** Medium
**Languages:** All
**CWE:** [CWE-362](https://cwe.mitre.org/data/definitions/362.html)
**Last reviewed:** 2026-05-06

## What it detects

For every test function (`is_test == true`), scans the function body for tokens that indicate reliance on wall-clock time or non-deterministic randomness. One finding per unique token match is emitted.

### Detected tokens

| Token | Context |
|---|---|
| `sleep` | `time.sleep` (Python), `Thread::sleep` (Rust) |
| `setTimeout` | JavaScript / TypeScript |
| `Date.now()` | JavaScript / TypeScript |
| `SystemTime::now()` | Rust |
| `Instant::now()` | Rust |
| `time.time()` | Python |
| `time.sleep` | Python |
| `Math.random` | JavaScript / TypeScript |
| `random.random` | Python |
| `rand::random` | Rust |

## Why it matters

Tests that depend on elapsed time or random values can pass on one run and fail on another ("flaky tests"), eroding trust in the CI pipeline and wasting developer time investigating spurious failures.

## Example — flagged

**Python:**

```python
def test_delay():
    time.sleep(0.5)   # ← flagged
    assert do_work() is not None
```

**Rust:**

```rust
#[test]
fn test_timing() {
    let start = Instant::now();  // ← flagged
    assert!(start.elapsed().as_nanos() >= 0);
}
```

## Example — not flagged

```rust
#[test]
fn test_pure_logic() {
    assert_eq!(1 + 1, 2);  // ← no time/randomness, clean
}
```

## Fix guidance

- Use dependency injection to pass a clock or RNG into code under test.
- Replace `time.sleep` delays with event-driven synchronisation.
- For randomness, supply a fixed seed in tests.
- Use a test-specific fake / stub for time-sensitive operations.

## Implementation

- Source: [crates/zuit-analyzers/src/flaky_time.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/flaky_time.rs)
- Scans `body_span` of each test function; one finding per unique token match (deduped per function).

## References

- [CWE-362](https://cwe.mitre.org/data/definitions/362.html)
- [Google Testing Blog: Flaky Tests](https://testing.googleblog.com/2016/05/flaky-tests-at-google-and-how-we.html)
