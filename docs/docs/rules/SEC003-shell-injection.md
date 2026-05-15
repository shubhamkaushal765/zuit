---
title: SEC003 — Shell Injection Sink
sidebar_label: SEC003
description: Flags shell command construction combined with user input
---

# SEC003-shell-injection — Shell Injection Sink

**Dimension:** Security
**Default severity:** High
**Languages:** All
**Last reviewed:** 2026-05-05

## What it detects

A heuristic for likely shell-command construction sinks. The analyzer requires **both** of the following signals to be present in the same file before any finding is emitted. This two-signal requirement keeps false-positive rates low: a file that merely mentions `bash -c` in a doc-string without importing a shell-execution module will not be flagged.

### Signal 1 — Shell-exec import

At least one `Import.path` in the [`SemanticIndex`] contains (case-insensitively) one of the well-known shell-execution module names:

| Module substring | Language |
|---|---|
| `subprocess` | Python |
| `os.system` | Python |
| `os.popen` | Python |
| `commands.getoutput` | Python 2 |
| `child_process` | JavaScript / Node.js |
| `std::process::command` | Rust |
| `std.process` | Dart / Go-style |
| `shelljs` | JavaScript |
| `execa` | JavaScript |

### Signal 2 — Shell-prefix string literal

At least one string literal value matches the regex:

```
(?i)^(sh|bash|zsh|cmd|cmd\.exe|powershell|/bin/sh|/bin/bash|pwsh)\s+(-c|/c|/k)\b
```

This pattern matches the canonical injection sink: a shell interpreter called with the flag that causes it to execute its argument as a command string (`-c` for POSIX shells, `/c` or `/k` for `cmd.exe`, etc.).

One finding is emitted **per matching string literal**, located at the literal's byte span.

## Why it matters

Passing unsanitised user input to a shell interpreter is the definition of OS command injection (CWE-78). An attacker can break out of the intended command and execute arbitrary code on the host.

## Configuration

No configuration knobs. The two-signal heuristic is always enabled.

## Example — flagged

**Python:**

```python
import subprocess

def run(user_cmd: str) -> int:
    # String literal "sh -c " triggers signal 2; subprocess triggers signal 1.
    cmd = "sh -c " + user_cmd
    return subprocess.call(cmd, shell=True)
```

**JavaScript:**

```typescript
import { exec } from "child_process";

function run(userCmd: string): void {
    // "bash -c " triggers signal 2; child_process triggers signal 1.
    const cmd = "bash -c " + userCmd;
    exec(cmd);
}
```

**Rust:**

```rust
use std::process::Command;

fn run(payload: &str) {
    // "sh -c" triggers signal 2; std::process::Command triggers signal 1.
    let _shell_prefix = "sh -c";
    Command::new("sh").arg("-c").arg(payload);
}
```

## Example — not flagged

```python
# No shell-exec import — signal 1 absent; nothing is emitted even if a
# string happens to look like a shell prefix.
# cmd = "bash -c list_files"   ← NOT flagged without the import

import subprocess

# Signal 1 present but no shell-prefix string literal — signal 2 absent.
subprocess.run(["ls", "-la"])    # safe: argument list, not shell string
```

## Fix guidance

- **Use argument lists** instead of shell strings: `subprocess.run(["ls", "-la"])` in Python, `Command::new("ls").arg("-la")` in Rust, or pass an array to `child_process.spawn` in Node.js.
- **Never pass `shell=True`** (Python) or `shell: true` (Node.js) with user-controlled input.
- **Validate / quote untrusted input** if a shell string is unavoidable: use `shlex.quote()` in Python or an equivalent escaping helper in JS.
- **Principle of least privilege**: run child processes under a restricted user account or inside a container sandbox.

## Implementation

- Source: [crates/zuit-analyzers/src/shell_injection.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/shell_injection.rs)
- Severity / supported languages: see `META` constant in source.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [Python docs: `subprocess` security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
