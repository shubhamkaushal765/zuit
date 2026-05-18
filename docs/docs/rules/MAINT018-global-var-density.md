---
title: MAINT018-global-var-density — Global variable density
sidebar_label: MAINT018-global-var-density
description: Flags files that declare too many mutable module-scope globals (pub static mut in Rust, global statements in Python).
---

# MAINT018-global-var-density — Global variable density

| Property   | Value                      |
| ---------- | -------------------------- |
| Dimension  | Maintainability             |
| Severity   | Low                        |
| Confidence | High                       |
| CWE        | CWE-1108                   |
| Languages  | Rust, Python               |

## What it detects

Fires **once per file** when the number of mutable file-scoped globals meets or
exceeds the configured threshold (default: 3).

**Rust:** counts `pub static mut NAME: T = …;` declarations.  Private
`static mut` and immutable `pub static` are intentionally excluded — the rule
targets the most hazardous pattern: mutable state that is both global and part
of the public API surface.

**Python:** counts names declared via `global` statements at module scope.
Each `global a, b, c` statement contributes 3 to the total.  Comments
containing the word `global` are not counted (the rule inspects the AST, not
raw text).

## Why it matters

High global-variable density (CWE-1108) is a reliability and concurrency
smell:

- Shared mutable state causes race conditions when accessed from multiple
  threads without synchronisation.
- Global state makes code hard to test in isolation — callers must reset
  globals between tests.
- Functions that read or write globals have hidden dependencies that are
  invisible from their signatures.

## Examples — flagged

**Rust (3 or more `pub static mut`):**

```rust
pub static mut COUNTER: u64 = 0;
pub static mut LAST_ERROR: &str = "";
pub static mut INITIALIZED: bool = false;
// ^ MAINT018 fires: 3 pub static mut globals
```

**Python (3 or more `global` names at module scope):**

```python
global db_conn
global cache
global config
# MAINT018 fires: 3 global names declared
```

or equivalently in one statement:

```python
global db_conn, cache, config
# MAINT018 fires: 3 names in one statement
```

## Examples — not flagged

**Rust — immutable statics (fine):**

```rust
pub static MAX_SIZE: usize = 1024;
pub static VERSION: &str = "1.0.0";
pub static LABEL: &str = "app";
// Not flagged — immutable, no data races possible
```

**Rust — private static mut (below the pub threshold):**

```rust
static mut INTERNAL_A: i32 = 0;
static mut INTERNAL_B: i32 = 0;
static mut INTERNAL_C: i32 = 0;
// Not flagged — private; consider flagging these separately if needed
```

**Python — two global names (below default threshold):**

```python
global db_conn
global cache
# Not flagged — count (2) is below threshold (3)
```

## Fix guidance

**Rust:**

- Wrap mutable state in a `Mutex` or `RwLock` behind a `static`:
  ```rust
  use std::sync::Mutex;
  static COUNTER: Mutex<u64> = Mutex::new(0);
  ```
- Use `thread_local!` for per-thread state that does not need to be shared.
- Refactor shared configuration into a struct passed by reference or via
  dependency injection.

**Python:**

- Encapsulate module-level state in a class or dataclass:
  ```python
  from dataclasses import dataclass, field

  @dataclass
  class AppState:
      db_conn: object = None
      cache: dict = field(default_factory=dict)
      config: dict = field(default_factory=dict)
  ```
- Pass state explicitly as function arguments instead of relying on `global`.

## Configuration

| Key | Default | Description |
| --- | ------- | ----------- |
| `threshold` | `3` | Minimum mutable-global count (inclusive) that triggers the rule |

```toml
[rules."MAINT018-global-var-density"]
threshold = 5   # raise threshold for legacy codebases
```

## Implementation

- [`crates/zuit-lang-rust/src/analyzers/global_var_density.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/global_var_density.rs)
- [`crates/zuit-lang-python/src/analyzers/global_var_density.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/global_var_density.rs)

## References

- [CWE-1108: Excessive Reliance on Global Variables](https://cwe.mitre.org/data/definitions/1108.html)
