---
title: SEC007 — Path Traversal via Unvalidated File Paths
sidebar_label: SEC007
description: Flags file operations with directory traversal or user input
---

# SEC007-path-traversal — Path Traversal via Unvalidated File Paths

**Dimension:** Security
**Default severity:** High
**CWE:** CWE-22
**OWASP:** A01:2021 – Broken Access Control
**Languages:** All (Python, JS/TS, Rust)
**Last reviewed:** 2026-05-06

## What it detects

Flags source lines where a file-operation call is combined with a path that contains a literal `..` (directory traversal) or with string interpolation in a file that also imports a web-framework module (indicating user-controlled input can reach the call).

A finding is emitted for each line satisfying **both** conditions:

1. **File-operation call** — the line matches one of:
   `open`, `read_file`, `write_file`, `readFile*`, `writeFile*`,
   `fs.read*`, `fs.write*`, `fs.open`, `std::fs::<fn>`,
   `Path::new`, `PathBuf::from`.

2. **Traversal signal** — the line contains EITHER:
   - A literal `..` substring (direct traversal indicator), OR
   - An interpolation marker (`${`, `f"…{`, `" + `, `' + `) **and** the file imports a web-framework module indicating user input exposure
     (`flask`, `fastapi`, `django`, `express`, `http`, `aiohttp`,
     `tornado`, `actix_web`, `axum`, `rocket`).

One finding is emitted per matching line.

## Why it matters

Path traversal vulnerabilities allow an attacker to read or write files outside the intended directory by inserting `../` sequences. This can expose sensitive configuration files, private keys, or allow overwriting system files. OWASP A01:2021 (Broken Access Control) covers this class of vulnerability.

## Configuration

This rule has no configurable threshold. Disable per project:

```toml
[rules.SEC007-path-traversal]
enabled = false
```

## Examples flagged

**Python** — opening a file whose path is built with `..`:

```python
from flask import request

@app.route("/file")
def serve_file():
    filename = request.args.get("name", "")
    with open("uploads/" + filename + "..") as f:  # flagged: '..' in path
        return f.read()
```

**JS/TS** — reading a file with `..` in the constructed path:

```typescript
import * as fs from "fs";
import * as http from "http";

export function serveFile(req: http.IncomingMessage, basePath: string): Buffer {
  const userPath = (req as any).query?.name ?? "";
  return fs.readFileSync(basePath + "/.." + userPath);  // flagged: '..' present
}
```

**Rust** — `std::fs::read` with a path containing `..`:

```rust
pub fn read_user_file(user_input: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(std::path::Path::new(&format!("../uploads/{}", user_input)))
    // flagged: '..' in path
}
```

## Examples not flagged

**Python** — reading a fixed file path with no traversal:

```python
with open("/etc/app/config.toml") as f:  # not flagged: no '..'
    config = f.read()
```

**JS/TS** — using `path.resolve` and checking the result (no `..`):

```typescript
import * as path from "path";
import * as fs from "fs";

export function readSafe(base: string, name: string): Buffer {
  const resolved = path.resolve(base, name);
  if (!resolved.startsWith(base)) throw new Error("Path traversal");
  return fs.readFileSync(resolved);  // not flagged: no '..'
}
```

## Fix guidance

- Call **`path.canonicalize()`** (Rust), **`os.path.realpath()`** (Python), or **`path.resolve()`** (Node.js) on any user-supplied path before use.
- After resolving, **assert** the result starts with the intended base directory.
- **Reject** any input that contains `..` before even resolving it.
- Use allow-lists of permitted filenames where possible.

## Implementation

- Source: [crates/zuit-analyzers/src/path_traversal.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/path_traversal.rs)
- Severity / supported languages: see `RuleMeta` in source.

## References

- [OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
