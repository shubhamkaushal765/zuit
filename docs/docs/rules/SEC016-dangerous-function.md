---
title: SEC016-dangerous-function — Inherently dangerous function call
sidebar_label: SEC016-dangerous-function
description: Flags calls to inherently dangerous functions (CWE-242) — libc string/format/scan helpers in Rust, eval/exec/os.system in Python.
---

# SEC016-dangerous-function — Inherently dangerous function call

| Property   | Value                  |
| ---------- | ---------------------- |
| Dimension  | Security               |
| Severity   | High (Rust), Medium (Python) |
| Confidence | High                   |
| CWE        | CWE-242                |
| OWASP      | A03:2021               |
| Languages  | Rust, Python           |

## What it detects

A call to a function that is **inherently dangerous by design** — input
validation cannot make it safe; it should be replaced with a length-checked
or otherwise safer counterpart.

| Language | Flagged callees                                                                                  |
| -------- | ------------------------------------------------------------------------------------------------ |
| Rust     | `gets`, `gets_s`, `strcpy`, `wcscpy`, `strcat`, `wcscat`, `sprintf`, `vsprintf`, `scanf`         |
| Python   | bare `eval(...)`, bare `exec(...)`, `os.system(...)`                                             |

Detection is on the **last** path segment for Rust, so `libc::gets(...)`,
`::libc::gets(...)`, and bare `gets(...)` all flag. Python matches bare
names and the specific `os.system` attribute pattern.

## Relationship to other rules

The Python coverage **deliberately overlaps** with:

- `SEC002-eval-sink` (CWE-94) — also flags `eval` and `exec`.
- `SEC003-shell-injection` (CWE-78) — also flags `os.system`.

CWE-242 ("Use of Inherently Dangerous Function") is the maintenance-focused
taxonomy: it asks the reviewer to remove the call entirely rather than
sanitize its inputs. Suppress one dimension with
`[rules."SEC016-dangerous-function"] severity = "ignore"` if the duplicate
is noisy in your codebase.

## Why it matters

CWE-242 documents functions that cannot be made safe through validation:

- `gets` / `strcpy` / `strcat` / `sprintf` / `scanf` perform unbounded
  copies and reads. A long enough input always overflows; no caller-side
  check fixes the API design.
- `eval` / `exec` execute arbitrary code with no realistic way to validate
  the input string short of writing your own parser.
- `os.system` spawns a shell with the given string; quoting is impossible
  to get right against adversarial inputs.

## Examples — flagged

**Rust**

```rust
unsafe fn read(buf: *mut std::os::raw::c_char) {
    libc::gets(buf);           // ← flagged
}

unsafe fn fmt(buf: *mut i8, s: *const i8) {
    libc::sprintf(buf, s);     // ← flagged
}
```

**Python**

```python
import os

result = eval(user_input)           # ← flagged
exec(compile(snippet, "<x>", "exec"))  # ← flagged
os.system("rm " + name)            # ← flagged
```

## Examples — not flagged

**Rust**

```rust
unsafe fn safe(buf: *mut std::os::raw::c_char, n: usize) {
    libc::fgets(buf, n as i32, stdin);     // length-checked
    libc::snprintf(buf, n, fmt);           // length-checked
    libc::strncpy(dst, src, n);
}

// Method call, not a free-function call — not flagged.
fn user() { x.gets(); }
```

**Python**

```python
import ast
import subprocess

result = ast.literal_eval("[1, 2, 3]")            # safe
subprocess.run(["rm", name], shell=False, check=True)  # safe

# Attribute access matters: model.eval() (PyTorch) is NOT bare `eval`.
model.eval()
```

## Fix guidance

| Flagged                         | Replace with                                                          |
| ------------------------------- | --------------------------------------------------------------------- |
| `gets` / `gets_s`               | `fgets` + explicit buffer length, or Rust `BufRead::read_line`.       |
| `strcpy` / `wcscpy`             | `strncpy_s`, owned `String`/`CString`.                                 |
| `strcat` / `wcscat`             | `strncat_s`, owned `String::push_str`.                                 |
| `sprintf` / `vsprintf`          | `snprintf` with buffer length, or Rust `format!`/`write!` macros.     |
| `scanf`                         | `fgets` + dedicated parser, or Rust `BufRead` + parse helpers.        |
| Python `eval` / `exec`          | `ast.literal_eval`, an explicit dispatch table, or a real parser.     |
| Python `os.system`              | `subprocess.run([...], shell=False)` with the command as a list.      |

## Scope limitations (v1)

- **Rust** matches on the **last** path segment only. A user-defined
  function named `strcpy` in your codebase will still flag — there is no
  symbol resolution in v1. Rename your function to avoid the clash.
- **Python** does not yet flag `subprocess.call(..., shell=True)` /
  `subprocess.run(..., shell=True)` (covered by `SEC003-shell-injection`),
  `pickle.loads` / `marshal.loads` (covered by `SEC005`), or
  `__import__` (covered by `SEC002`).
- **JavaScript/TypeScript** is intentionally not covered — `eval`,
  `Function`, and `document.write` are all handled by `SEC002-eval-sink`.

## Implementation

- Rust: [`crates/zuit-lang-rust/src/analyzers/dangerous_function.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/dangerous_function.rs)
- Python: [`crates/zuit-lang-python/src/analyzers/dangerous_function.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/dangerous_function.rs)

## References

- [CWE-242: Use of Inherently Dangerous Function](https://cwe.mitre.org/data/definitions/242.html)
- [SEI CERT C — STR07-C. Use the bounds-checking interfaces for string manipulation](https://wiki.sei.cmu.edu/confluence/display/c/STR07-C.+Use+the+bounds-checking+interfaces+for+string+manipulation)
- [Python `ast.literal_eval`](https://docs.python.org/3/library/ast.html#ast.literal_eval)
