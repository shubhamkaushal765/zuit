# MAINT016 — Unreachable Code

| Property    | Value                           |
|-------------|---------------------------------|
| Rule ID     | `MAINT016-unreachable-code`     |
| Dimension   | Maintainability                 |
| Severity    | Low                             |
| CWE         | [CWE-561](https://cwe.mitre.org/data/definitions/561.html) |
| Languages   | Rust, Python, JavaScript/TypeScript |
| Since       | v0.4.0                          |

## Summary

Flags the **first statement** that follows a terminating statement in the same
block. Code that appears after a `return`, `throw` / `raise`, `break`, or
`continue` can never be executed at run time. One finding is emitted per block,
pointing at the first dead statement.

## Why this matters

Unreachable code is a maintenance hazard:

- It confuses readers and code reviewers who expect every line to have effect.
- It may hide logic errors (e.g. a `return` placed before the value it was
  supposed to return is calculated).
- It silently accumulates as code evolves, making diffs noisier and testing
  coverage metrics misleading.

## Terminating statements

| Language | Terminators |
|---|---|
| Rust | `return`, `break`, `continue`, `panic!()`, `unreachable!()`, `todo!()`, `unimplemented!()` |
| Python | `return`, `raise`, `break`, `continue` |
| JavaScript / TypeScript | `return`, `throw`, `break`, `continue` |

## Detection rule

Within a **single flat block**, the analyzer finds the index of the first
terminating statement. If at least one more statement follows it, a single
finding is emitted pointing at that first dead statement. Multiple dead
statements produce **one** finding, not many.

The rule does **not** fire when a terminator appears inside a nested block
(e.g. the body of an `if` branch) and the following statement is in the outer
block — that outer statement is reachable when the condition is false.

### Example — flagged (Rust)

```rust
fn f() -> i32 {
    return 1;
    let x = 2; // ← finding here
    x
}
```

### Example — not flagged (Rust)

```rust
fn f(cond: bool) -> i32 {
    if cond {
        return 1;  // inside nested block
    }
    let x = 2;    // reachable when !cond — no finding
    x
}
```

### Example — flagged (Python)

```python
def f():
    return 1
    x = 2   # ← finding here
```

`pass` after a terminator is **not** flagged — it is idiomatic (e.g. generated
stubs) and ruff already handles it.

### Example — flagged (JavaScript)

```js
function f() {
    throw new Error('fatal');
    console.log('done'); // ← finding here
}
```

## Nested blocks

The analyzer recurses into all nested function/method bodies, loop bodies, and
(for Python) class bodies. Each block is checked independently, so dead code
inside an inner function emits its own finding.

## Scope limitations (v1)

The following cases are **deferred** to a future release that includes a
control-flow graph (CFG):

- Rust: `!`-typed function calls (`std::process::exit(1)`) are not detected as
  terminators at the syntactic level — only the macro-based divergers listed
  above are checked.
- Cross-block reachability (e.g. unconditional `while true` loops) is not
  analysed.

## Configuration

This rule has no configuration options. Use
[suppression comments](./suppression.md) to silence specific findings when the
dead code is intentional.

## References

- [CWE-561: Dead Code](https://cwe.mitre.org/data/definitions/561.html)
