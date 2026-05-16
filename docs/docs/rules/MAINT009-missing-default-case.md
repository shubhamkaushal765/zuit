---
title: MAINT009-missing-default-case — Missing default/wildcard case
sidebar_label: MAINT009-missing-default-case
description: Flags match/switch constructs that lack a default or wildcard fallback arm.
---

# MAINT009-missing-default-case — Missing default/wildcard case

| Property  | Value                                         |
| --------- | --------------------------------------------- |
| Dimension | Maintainability                               |
| Severity  | Medium                                        |
| CWE       | CWE-478                                       |
| Languages | Rust, Python, JavaScript, TypeScript          |

## What it detects

Flags `match`/`switch` constructs that lack a fallback ("default", `_`) arm when the scrutinee is a value where enumerating all possibilities is unsafe to assume.

- **Rust:** `match` expressions where no arm pattern is `_` (wildcard) and the scrutinee is either a literal (e.g. `match 1 { … }`) or a lowercase-path expression (heuristic for local variables, not enum variants).
- **Python:** `match` statements whose `cases` contain no irrefutable arm (`case _:` or `case <name>:`).
- **JS/TS:** `switch` statements whose `cases` contain no `default:` clause.

**Skips (intentional exclusions):**

- Rust: `match` expressions whose scrutinee path ends with an uppercase letter (e.g. `match Color::Red { … }`) — these are enum matches where the compiler enforces exhaustiveness.
- Rust: `match` expressions whose scrutinee is a call expression, field access, or other non-trivial form — out of scope for this heuristic.
- Python: `case _:` and `case <name>:` are both treated as irrefutable and do not fire.

## Why it matters

A `switch` or `match` without a default/wildcard arm silently ignores unexpected values. When the set of possible values grows (a new enum variant, an API returning a new status code), the missing branch is never executed — the program continues with undefined or incorrect state (CWE-478). Adding a fallback arm makes the intent explicit and ensures unexpected values are handled, logged, or fail loudly.

## Examples — flagged

**Python:**

```python
match status:
    case 1:
        handle_ok()
    case 2:
        handle_error()
# Missing `case _:` — new status codes are silently ignored
```

**Rust:**

```rust
fn process(code: i32) {
    match code {
        0 => handle_ok(),
        1 => handle_error(),
        // Missing `_ => {}` — unexpected codes fall through silently
    }
}
```

**JavaScript / TypeScript:**

```ts
switch (event.type) {
    case "click":
        onClick();
        break;
    case "hover":
        onHover();
        break;
    // Missing `default:` — new event types are silently ignored
}
```

## Examples — not flagged

**Python (has irrefutable arm):**

```python
match status:
    case 1:
        handle_ok()
    case _:
        handle_default()
```

**Rust (enum match — compiler checks exhaustiveness):**

```rust
match color {
    Color::Red => {}
    Color::Blue => {}
    // Compiler error if Color gains a new variant — no finding needed
}
```

**Rust (has wildcard):**

```rust
match code {
    0 => handle_ok(),
    _ => handle_unknown(),
}
```

**JS/TS (has `default:`):**

```ts
switch (event.type) {
    case "click":
        onClick();
        break;
    default:
        logUnknown(event.type);
}
```

## Fix guidance

- **Add a wildcard/default arm:** Use `_ => {}` (Rust), `case _:` (Python), or `default:` (JS/TS).
- **Fail loudly:** Use `_ => unreachable!()` (Rust), `default: throw new Error(…)` (JS/TS), or `case _: raise ValueError(…)` (Python) when unexpected values indicate a programming error.
- **Log and continue:** If the new values should be silently ignored for now, add a log statement inside the wildcard arm to record the unexpected input.

## Configuration

No configuration knobs in v1. The uppercase-path heuristic for Rust enum exclusion is hardcoded.

## Implementation

- [`crates/zuit-lang-rust/src/analyzers/missing_default_case.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/missing_default_case.rs)
- [`crates/zuit-lang-python/src/analyzers/missing_default_case.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/missing_default_case.rs)
- [`crates/zuit-lang-js/src/analyzers/missing_default_case.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/missing_default_case.rs)

## References

- [CWE-478: Missing Default Case in Switch Statement](https://cwe.mitre.org/data/definitions/478.html)
