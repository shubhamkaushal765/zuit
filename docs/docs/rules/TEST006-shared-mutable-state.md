---
title: TEST006-shared-mutable-state — Test Mutates Module-Level State Without Fixture Isolation
sidebar_label: TEST006-shared-mutable-state
---
# TEST006-shared-mutable-state — Test Mutates Module-Level State Without Fixture Isolation

**Dimension:** TestSmell
**Default severity:** Medium
**Languages:** All (Python, JavaScript/TypeScript, Rust)
**CWE:** CWE-820
**Last reviewed:** 2026-05-07

## What it detects

For every test function (`is_test == true`), the analyzer checks whether the
function body mutates a module-level (file-scope) mutable variable and whether
the file contains any setUp/tearDown or equivalent lifecycle hook.

A finding is emitted when **all** of the following hold:

1. The function is a test (`is_test == true`).
2. The function body contains a mutation of a module-scope mutable name:
   - **Python:** `global X` keyword, or `X =`, `X +=`, `X.append(`, `X.pop(`,
     `X.clear(`, `X[…]`, etc., where `X` is declared at column 0.
   - **JS/TS:** `X =`, `X +=`, `X++`, `X--`, `X.push(`, `X.pop(`, `X[…]`, etc.,
     where `X` is declared with `let` or `var` at column 0.
   - **Rust:** `unsafe {` block (the canonical wrapper for `static mut` writes),
     or direct assignment to a name declared with `static mut` at module scope.
3. The file has **no** setUp/tearDown/fixture hook (see below).

**Fixture suppression** — if the file contains any of the following, all
findings are suppressed (conservative approach to avoid false positives):

- A function named `setUp`, `tearDown`, `setup`, `teardown`, `before`, `after`,
  `beforeEach`, `afterEach`, `before_each`, `after_each`, `setup_method`,
  `teardown_method`.
- Source tokens `beforeEach(`, `afterEach(`, `before(`, `after(`,
  `pytest.fixture`, `@fixture`.

One finding is emitted per test function (the first mutated name is reported).

## Why it matters

When tests share mutable module-level state, one test's side effects bleed into
subsequent tests. This causes:

- **Order-dependent failures** — tests pass in isolation but fail when run
  together.
- **Flaky CI** — parallel test runners may interleave mutations unpredictably.
- **Hard-to-diagnose bugs** — the failing test may be blameless; the culprit
  mutated state in an earlier test.

CWE-820 ("Missing Synchronization") classifies shared mutable state accessed
without adequate protection as a defect, even in single-threaded contexts where
execution order is non-deterministic.

## Example — flagged

### Python

```python
COUNTER = 0          # module-level mutable

def test_increment():
    global COUNTER
    COUNTER += 1     # ← mutates shared state, no setUp/tearDown → flagged
    assert COUNTER > 0
```

### JavaScript / TypeScript

```typescript
let cache: Record<string, number> = {};   // module-level mutable

function test_mutates_cache(): void {
    cache["foo"] = 1;   // ← mutates shared state, no beforeEach → flagged
    expect(cache["foo"]).toBe(1);
}
```

### Rust

```rust
static mut TOTAL: i32 = 0;

#[test]
fn test_mutates_total() {
    unsafe { TOTAL += 1; }   // ← unsafe block on static mut, no fixture → flagged
    unsafe { assert!(TOTAL > 0); }
}
```

## Example — not flagged

### Python (setUp provides isolation)

```python
COUNTER = 0

class TestCounter:
    def setUp(self):       # ← lifecycle hook present → entire file suppressed
        global COUNTER
        COUNTER = 0

    def test_increment(self):
        global COUNTER
        COUNTER += 1
        assert COUNTER == 1
```

### JavaScript / TypeScript (beforeEach resets state)

```typescript
let cache: Record<string, number> = {};

beforeEach(() => { cache = {}; });   // ← lifecycle hook → entire file suppressed

function test_cache_mutation_safe(): void {
    cache["key"] = 42;
    expect(cache["key"]).toBe(42);
}
```

### Rust (no static mut)

```rust
#[test]
fn test_pure_local() {
    let local = 0;
    assert_eq!(local + 1, 1);   // only local state → not flagged
}
```

## Fix guidance

1. **Use setUp/tearDown (Python)** — reset module-level state in `setUp` and
   `tearDown` so every test starts with a known baseline.

2. **Use beforeEach/afterEach (JS/TS)** — reset shared objects before each test
   to prevent state leakage between tests.

3. **Use a Drop-based fixture (Rust)** — create a RAII guard that resets the
   `static mut` on drop, or — better — refactor to avoid `static mut` entirely
   by passing state as function arguments (dependency injection).

4. **Prefer dependency injection** — design functions to accept their
   dependencies as parameters rather than reading from global mutable state.
   This makes tests hermetic by construction.

5. **Use fresh-per-test state** — construct the object under test inside the
   test function body so each test gets its own independent instance.

## Implementation

- Source: `crates/zuit-analyzers/src/shared_mutable_state.rs`
- Fixtures:
  - `fixtures/python/shared_mutable_state/main.py` — Python positive
  - `fixtures/python/not_shared_mutable_state/main.py` — Python negative
  - `fixtures/js/shared_mutable_state/main.ts` — JS/TS positive
  - `fixtures/js/not_shared_mutable_state/main.ts` — JS/TS negative
  - `fixtures/rust/shared_mutable_state/lib.rs` — Rust positive
  - `fixtures/rust/not_shared_mutable_state/lib.rs` — Rust negative

## References

- [CWE-820: Missing Synchronization](https://cwe.mitre.org/data/definitions/820.html)
- [xUnit Patterns — Shared Fixture](http://xunitpatterns.com/Shared%20Fixture.html)
- [Martin Fowler — Test Isolation](https://martinfowler.com/articles/nonDeterminism.html)
