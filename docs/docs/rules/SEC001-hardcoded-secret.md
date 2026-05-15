---
title: SEC001-hardcoded-secret — Hardcoded secrets
sidebar_label: SEC001-hardcoded-secret
description: Detects credentials and high-entropy secrets embedded in string literals.
---

# SEC001-hardcoded-secret — Hardcoded secrets

| Property         | Value    |
| ---------------- | -------- |
| Dimension        | Security |
| Default severity | High     |
| Languages        | All      |

## What it detects

Detects credentials and high-entropy secrets embedded in string literals. Two heuristics are applied in order to each string literal found in the `SemanticIndex::string_literals`:

1. **Pattern matching** against a catalogue of known secret shapes.
2. **Shannon entropy** — strings of length ≥ 24 bytes with entropy ≥ 4.5 bits/byte.

Doc-comment text is stored separately in `SemanticIndex::doc_comments` and is automatically excluded from both heuristics.

## Why it matters

Hardcoded secrets in source code are a critical vulnerability ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)). Secrets belong in environment variables, configuration files (not tracked), or managed secrets stores.

:::warning
Once secrets are committed to a repository, they are permanently exposed to anyone with repository access and should be considered compromised. Rotate them immediately.
:::

## Configuration

No configuration knobs in v1. Both heuristics are enabled by default and cannot be independently disabled.

## Pattern catalogue

The analyzer recognizes the following secret patterns via regex:

| Pattern | Regex | Notes |
| --- | --- | --- |
| AWS access key ID | `AKIA[0-9A-Z]{16}` | Matches AWS access key format. |
| JSON Web Token (JWT) | `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` | Matches JWT structure (header.payload.signature). |
| Slack API token | `xox[abp]-[A-Za-z0-9-]{10,}` | Matches Slack bot, app, and user tokens. |
| PEM private key | `-----BEGIN [A-Z ]*PRIVATE KEY-----` | Matches PEM headers for RSA, DSA, EC, etc. |

## Entropy heuristic

Strings that do not match any known pattern are evaluated for entropy as a fallback:

- **Minimum length:** 24 bytes
- **Entropy threshold:** 4.5 bits/byte (Shannon entropy)
- **Formula:** `H = −Σ p_i × log₂(p_i)` where `p_i` is the frequency of byte `i` divided by total length.

A Base64-encoded 16-byte secret (128 bits) typically yields ~5.9 bits/byte and will be flagged.

## Examples — flagged

**Rust:**

```rust
pub fn aws_key() -> &'static str {
    "AKIAIOSFODNN7EXAMPLE"  // Pattern match: AWS access key ID
}

let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1Nzc0ZDVkYmJiMmFjZTAxMDAwMWEwMzAifQ.pK1JqNVjkGWUg8r8jvHmECCahz0V0wI1r_kJFhzVMdU";
// Pattern match: JSON Web Token

let slack = "xoxb-" + "EXAMPLE" + "-EXAMPLE-EXAMPLE-EXAMPLE";
// Pattern match: Slack bot token (literal in source would still be flagged)

let random = "aB9$Xq2#mK@L!nP7^wE&uI*vY%cZ(dF)jH-oS+rT_gB5";
// Entropy match: 24+ chars, entropy ≥ 4.5 bits/byte
```

**Python:**

```python
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Pattern match: AWS access key ID
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1Nzc0ZDVkYmJiMmFjZTAxMDAwMWEwMzAifQ.pK1JqNVjkGWUg8r8jvHmECCahz0V0wI1r_kJFhzVMdU"
# Pattern match: JSON Web Token
```

## Examples — not flagged

```rust
// Low entropy: only two distinct characters
let hex = "00000000111111112222222233333333";

// English text: low Shannon entropy
let message = "Hello, this is a secret message.";

// Short random string: below minimum length
let short = "aB9$Xq2#mK";
```

## Fix guidance

- **Move to environment variables:** Use `std::env::var()` (Rust) or `os.getenv()` (Python) to read secrets from the environment at runtime.
- **Use a secrets manager:** Deploy AWS Secrets Manager, HashiCorp Vault, or similar to store and rotate credentials.
- **Separate config files:** Use untracked (`.gitignore`) local config files or `.env` files during development; never commit them.
- **Rotate compromised secrets:** If a secret is ever committed, assume it has been exposed. Rotate it immediately.
- **Use short-lived credentials:** Prefer temporary credentials (AWS STS, OAuth tokens with expiry) over long-lived static secrets.

## Implementation

- Source: [`crates/zuit-analyzers/src/hardcoded_secret.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/hardcoded_secret.rs)
- Entropy calculation: Shannon entropy function in the same file.

## References

- [CWE-798: Use of Hard-Coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Secrets Management](https://owasp.org/www-community/Sensitive_Data_Exposure)
