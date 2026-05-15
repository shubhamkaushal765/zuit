---
title: SEC004 — Weak Cryptographic Hash Algorithm
sidebar_label: SEC004
description: Flags MD5 and SHA-1 hash algorithms
---

# SEC004-weak-crypto — Weak Cryptographic Hash Algorithm

**Dimension:** Security
**Default severity:** Medium
**CWE:** CWE-327
**OWASP:** A02:2021 – Cryptographic Failures
**Languages:** All
**Last reviewed:** 2026-05-05

## What it detects

Flags uses of deprecated or weak cryptographic hash algorithms — specifically **MD5** and **SHA-1** — via two complementary heuristics:

1. **String-literal scan**: string literals whose value is `md5`, `sha1`, or `sha-1` (case-insensitive, whole-token match using regex word boundaries) are flagged. This catches dynamic algorithm selection patterns such as `hashlib.new("md5", data)` or `crypto.createHash("sha1")`.

2. **Import scan**: import paths that contain known weak-crypto module identifiers are flagged. Recognised substrings (case-insensitive) include:

   | Language | Recognised import substrings |
   |----------|------------------------------|
   | Python   | `hashlib.md5`, `hashlib.sha1`, `Crypto.Hash.MD5`, `Crypto.Hash.SHA1` |
   | JS/TS    | `crypto-js/md5`, `crypto-js/sha1` |
   | Rust     | `md-5`, `sha-1`, `sha1` |

Both heuristics may produce findings for the same algorithm use (e.g. `from hashlib import md5` triggers the import scan, and passing `"md5"` as an argument triggers the string scan). This is intentional: the overlap errs on the side of recall over precision.

## Why it matters

MD5 and SHA-1 are collision-vulnerable and should not be used for any security-sensitive purpose:

- **MD5** has practical collision attacks (Wang & Yu, 2004); full preimage resistance is also weakened.
- **SHA-1** was broken in practice with the SHAttered collision in 2017. Major browsers, CAs, and operating systems have removed SHA-1 support.

Using these algorithms for integrity verification, digital signatures, or password storage creates exploitable vulnerabilities. The OWASP Top 10 2021 lists "Cryptographic Failures" (A02) as the second most critical category.

## Configuration

This rule has no configurable threshold. It can be disabled per project:

```toml
[rules.SEC004-weak-crypto]
enabled = false
```

## Examples — flagged

**Python** — string-literal match (`"md5"`) + import match (`hashlib.md5`):

```python
import hashlib
from hashlib import md5          # flagged: import path contains "hashlib.md5"

def hash_password(pw: bytes) -> str:
    return hashlib.new("md5", pw).hexdigest()  # flagged: literal "md5"

def hash_data(data: bytes) -> str:
    return hashlib.new("sha1", data).hexdigest()  # flagged: literal "sha1"
```

**JS/TS** — string-literal match:

```typescript
import crypto from "crypto";

const algo = "sha1";  // flagged: literal "sha1"

export function hashWithSha1(data: string): string {
  return crypto.createHash(algo).update(data).digest("hex");
}
```

**Rust** — import-path match (`sha1` contained in `sha1::Sha1`):

```rust
use sha1::Sha1;  // flagged: import path "sha1::Sha1" contains "sha1"
use md5::Md5;    // flagged: import path "md5::Md5" contains "md5" — matched via "sha1" or "md-5" substring
```

## Examples — not flagged

**Python** — using SHA-256 (not a weak algorithm):

```python
import hashlib

def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()  # not flagged
```

**JS/TS** — using SHA-512:

```typescript
const algo = "sha512";  // not flagged ("sha512" has no word-boundary match for "sha1")
```

**Rust** — using SHA-256:

```rust
use sha2::Sha256;  // not flagged ("sha2::Sha256" does not contain "sha1" or "md5" or "sha-1")
```

## Avoiding false positives

The string-literal regex uses `\b` word boundaries:

- `"sha1"` → matched (`sha1` is a whole token).
- `"sha512"` → **not** matched (`sha1` does not appear at a word boundary inside `sha512`).
- `"SHA-1"` → matched (case-insensitive, dash treated as boundary).
- `"sha256"` → **not** matched.

## Fix guidance

- **Replace MD5 / SHA-1** with SHA-256 (`sha2::Sha256` in Rust, `hashlib.sha256` in Python, `crypto.createHash("sha256")` in Node.js) or stronger (SHA-384, SHA-512, SHA-3).
- **For password storage**, use a memory-hard KDF: **Argon2** (preferred), **bcrypt**, or **scrypt**. Never use a general-purpose hash (even SHA-256) directly for passwords.
- **For file integrity** / checksums where collision-resistance is not a security requirement and backwards compatibility is needed, note that MD5/SHA-1 remain acceptable for *non-security* checksums. Suppress the finding only when the use is clearly non-security-sensitive.

## Implementation

- Source: [crates/zuit-analyzers/src/weak_crypto.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/weak_crypto.rs)
- Severity / supported languages: see `RuleMeta` in source.

## References

- [OWASP A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [SHAttered — practical SHA-1 collision (2017)](https://shattered.io/)
- [Wang & Yu (2004) — MD5 collision paper](https://www.iacr.org/archive/crypto2004/31520288/ec.pdf)
