---
title: MAINT011-active-debug-code — Active debug code
sidebar_label: MAINT011-active-debug-code
description: Flags debug-code constructs (dbg!, debugger, breakpoint, console.log, etc.) that should be removed before production.
---

# MAINT011-active-debug-code — Active debug code

| Property   | Value                                        |
| ---------- | -------------------------------------------- |
| Dimension  | Maintainability                              |
| Severity   | Medium (debugger/dbg/breakpoint), Low (print macros) |
| Confidence | High                                         |
| CWE        | CWE-489                                      |
| Languages  | Rust, Python, JavaScript, TypeScript         |

## What it detects

Flags debug-code constructs that are almost never intentional in production builds:

**Rust:**
- `dbg!(…)` — always flagged (Severity::Medium)
- `println!(…)` / `eprintln!(…)` — flagged only when `MAINT011.flag_println = true`
  (default `false` because CLI tools legitimately use `println!` for output)

**Python:**
- `print(…)`, `pprint(…)`, `breakpoint()` — Severity::Medium
- `pdb.set_trace()` — Severity::Medium

**JavaScript / TypeScript:**
- `debugger;` statement — Severity::Medium
- `console.log(…)`, `console.debug(…)`, `console.trace(…)` — Severity::Low

**Not flagged (intentional production patterns):**
- Python: any of the above inside an `if __name__ == "__main__":` guard
- JS/TS: `console.error`, `console.warn`, `console.info` — legitimate error reporting

## Why it matters

Shipping debug-code to production exposes internal state in logs, slows down
execution, and can be a security vector (CWE-489). `debugger;` statements pause
execution in browsers; `dbg!` adds binary overhead; `pdb.set_trace()` halts
the process interactively.

## Examples — flagged

**Rust:**

```rust
fn compute(x: i32) -> i32 {
    dbg!(x);          // ← flagged: debug macro in production code
    x * 2
}
```

**Python:**

```python
def process(data):
    print(data)       # ← flagged
    breakpoint()      # ← flagged
    pdb.set_trace()   # ← flagged
    return data
```

**JavaScript / TypeScript:**

```ts
function fetchData(url: string) {
    debugger;                    // ← flagged (Severity::Medium)
    console.log("fetching", url); // ← flagged (Severity::Low)
    return fetch(url);
}
```

## Examples — not flagged

**Python (inside `__main__` guard):**

```python
if __name__ == "__main__":
    print("Running in dev mode")  # OK — guarded
```

**JS/TS (legitimate production logging):**

```ts
// These are NOT flagged:
console.error("Request failed:", err);
console.warn("Deprecated API used");
console.info("Server listening on :8080");
```

**Rust (test context):**

```rust
#[test]
fn my_test() {
    dbg!(my_value);  // still flagged — wrap in #[cfg(debug_assertions)] if needed
}
```

## Fix guidance

- **Remove** debug constructs before merging to main.
- **Replace** `println!` / `print()` / `console.log` with a structured logging
  library (`tracing`, `logging`, a proper logger).
- **Guard** development-only output with `#[cfg(debug_assertions)]` (Rust) or
  an `if __name__ == "__main__":` block (Python).

## Configuration

| Key | Default | Description |
| --- | ------- | ----------- |
| `MAINT011.flag_println` | `false` | When `true`, flag `println!` and `eprintln!` in Rust files |

> **Note:** `flag_println` defaults to `false` because many Rust CLI tools
> legitimately use `println!` for user-facing output. Set it to `true` for
> library crates where any stdout write is suspicious.

## Implementation

- [`crates/zuit-lang-python/src/analyzers/active_debug_code.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/active_debug_code.rs)
- [`crates/zuit-lang-rust/src/analyzers/active_debug_code.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/active_debug_code.rs)
- [`crates/zuit-lang-js/src/analyzers/active_debug_code.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/active_debug_code.rs)

## References

- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
