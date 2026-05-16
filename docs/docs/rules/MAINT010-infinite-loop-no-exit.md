---
title: MAINT010-infinite-loop-no-exit — Infinite loop with no exit
sidebar_label: MAINT010-infinite-loop-no-exit
description: Flags unconditional infinite loops that have no reachable exit (break, return, throw, or panic).
---

# MAINT010-infinite-loop-no-exit — Infinite loop with no exit

| Property  | Value                                         |
| --------- | --------------------------------------------- |
| Dimension | Maintainability                               |
| Severity  | High                                          |
| CWE       | CWE-835                                       |
| Languages | Rust, Python, JavaScript, TypeScript          |

## What it detects

Flags unconditional infinite loops whose body, at the same nesting depth, contains no reachable exit statement.

- **Rust:** `loop {}` expressions where the body (excluding nested `loop {}`, `for`, `while`, and closure bodies) contains no `break`, `return`, or diverging macro (`panic!`, `unreachable!`, `todo!`, `unimplemented!`).
- **Python:** `while True:` statements where the body (excluding nested `while`, `for`, `async for`, function def, or class def bodies) contains no `break`, `return`, `raise`, or call to `sys.exit` / `exit` / `os._exit`.
- **JS/TS:** `while (true) {}` or `for (;;) {}` statements where the body (excluding nested loops and function bodies) contains no `break`, `return`, `throw`, or call to `process.exit`.

**Skips (intentional exclusions):**

- `break`/`return`/`throw` inside a nested loop or function body — these target the inner scope, not the outer loop.
- Closures in Rust — their `return` returns from the closure, not the enclosing loop.

## Why it matters

An unconditional infinite loop with no exit will spin forever, consuming 100% of a CPU core and preventing any other work from being scheduled. In server software this causes a denial-of-service. In embedded or real-time systems it can cause a watchdog reset. In single-threaded runtimes it locks the entire event loop (CWE-835).

## Examples — flagged

**Python:**

```python
def spin():
    while True:
        x += 1  # no break, return, or raise — spins forever
```

**Rust:**

```rust
fn spin() {
    loop {
        x += 1;  // no break, return, or panic! — spins forever
    }
}
```

**JavaScript / TypeScript:**

```ts
while (true) {
    x++;  // no break, return, or throw — spins forever
}

for (;;) {
    x++;  // same
}
```

## Examples — not flagged

**Python (has `break`):**

```python
while True:
    if condition:
        break
```

**Rust (has `return`):**

```rust
loop {
    return;
}
```

**JS/TS (has `throw`):**

```ts
for (;;) {
    throw new Error("unreachable");
}
```

**Rust (inner break does not count for outer loop):**

```rust
loop {
    for _ in 0..10 {
        break;  // this break targets the for loop
    }
    // outer loop still has no exit — DOES fire
}
```

## Fix guidance

- **Add a termination condition:** Use `if condition { break; }` (Rust/JS) or `if condition: break` (Python).
- **Return from the function:** If the loop is at the end of a function, `return` terminates both the loop and the function.
- **Throw or raise:** Use `throw new Error(...)` (JS/TS) or `raise RuntimeError(...)` (Python) if the loop reaching the end is a programmer error.
- **Document intentional infinite loops:** If the loop is genuinely intended to run forever (e.g. a server event loop), add a `// SAFETY: intentional server loop` comment (Rust) or `# intentional server loop` comment (Python/JS) to make the intent clear. Consider suppressing the finding with a `zuit-ignore` comment.

## Configuration

No configuration knobs in v1.

## Implementation

- [`crates/zuit-lang-rust/src/analyzers/infinite_loop_no_exit.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/infinite_loop_no_exit.rs)
- [`crates/zuit-lang-python/src/analyzers/infinite_loop_no_exit.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/infinite_loop_no_exit.rs)
- [`crates/zuit-lang-js/src/analyzers/infinite_loop_no_exit.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/infinite_loop_no_exit.rs)

## References

- [CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')](https://cwe.mitre.org/data/definitions/835.html)
