---
title: SEC012-hardcoded-security-constant — Hardcoded security constant
sidebar_label: SEC012-hardcoded-security-constant
description: Flags assignments where the LHS identifier is a security keyword (password, token, api_key, etc.) and the RHS is a string, bytes, or integer literal.
---

# SEC012-hardcoded-security-constant — Hardcoded security constant

| Property         | Value                                    |
| ---------------- | ---------------------------------------- |
| Dimension        | Security                                 |
| Default severity | High                                     |
| Confidence       | Medium                                   |
| CWE              | CWE-547                                  |
| Languages        | Rust, Python, JavaScript, TypeScript     |

## What it detects

Flags assignments where the **left-hand-side identifier** contains a
security keyword — `secret`, `password`, `passwd`, `token`, `api_key`,
`apikey`, `auth`, `salt`, `private_key`, `privatekey`, `client_secret`,
`consumer_secret` — **and** the right-hand side is a literal value (string,
bytes, or integer).

Detection is **name-based** rather than value-based. This means it catches
low-entropy values like `admin_password = "admin"` or `api_key = "test"`
that entropy-based tools such as SEC001 would miss.

### Negative-case guards

The rule does **not** fire when:

- The last underscore-separated segment of the identifier is an excluded
  suffix: `count`, `field`, `handler`, `type`, `name`, `url`, `path`,
  `class`, `dict`, `list`, `set`, `map`. This prevents false positives on
  names like `password_count`, `token_type`, `auth_handler`.
- The RHS is a function call (e.g. `os.getenv("X")`, `process.env.X`,
  `std::env::var("X")`).
- The RHS is `None` / `null` / an empty string `""`.

## Relationship with SEC001-hardcoded-secret

**SEC001** fires on high-entropy string values and known secret patterns
(AWS keys, JWTs, Slack tokens, etc.) regardless of the variable name.

**SEC012** fires on security-keyword variable names regardless of the
entropy of the value.

These two rules are **complementary** and may both fire on the same
assignment when the variable name is a security keyword *and* the value is
also high-entropy or pattern-matched (e.g.
`api_key = "AKIAIOSFODNN7EXAMPLE"`). This overlap is intentional — the
rules have different `rule_id` values so users can disable one independently
via `[rules.SEC001-hardcoded-secret]` or `[rules.SEC012-hardcoded-security-constant]`
in `zuit.toml`.

## Examples — flagged

**Python:**

```python
password = "admin"            # FLAGGED — security keyword + string literal
api_key = "test"              # FLAGGED — low-entropy but named like a key
private_key = "abc"           # FLAGGED
session_token = 1234          # FLAGGED — integer literal
MY_SECRET_KEY = "value"       # FLAGGED — case-insensitive match
```

**Rust:**

```rust
let api_key = "test";                // FLAGGED
static API_KEY: &str = "test";       // FLAGGED — module-level static
const MY_SECRET: &str = "hardcoded"; // FLAGGED — module-level const
let password = "admin";              // FLAGGED
```

**JavaScript/TypeScript:**

```ts
const SECRET = "x";          // FLAGGED
let api_key = "test";         // FLAGGED
var password = "admin";       // FLAGGED
const private_key = "abc";    // FLAGGED
```

## Examples — not flagged

**Python:**

```python
# RHS is an environment-variable lookup — not a literal
password = os.environ["PASSWORD"]
api_key = os.getenv("API_KEY")

# Excluded suffixes
total_password_count = 0      # suffix: count
secret_handler = None         # suffix: handler
token_type = "bearer"         # suffix: type

# Empty string
password_hash = ""
```

**Rust:**

```rust
// RHS is a function call
let api_key = std::env::var("API_KEY").unwrap();

// Excluded suffix
let token_type = "bearer";       // suffix: type
let total_password_count = 0;    // suffix: count
```

**JavaScript/TypeScript:**

```ts
// RHS is a member expression — not a literal
const api_key = process.env.API_KEY;

// Excluded suffixes
const token_type = "bearer";          // suffix: type
const total_password_count = 0;       // suffix: count
const secret_handler = new Object();  // suffix: handler
```

## Fix guidance

1. **Load from the environment:** Replace the literal with an environment
   variable read (`os.environ["NAME"]`, `process.env.NAME`,
   `std::env::var("NAME")`).
2. **Use a secret manager:** Store secrets in AWS Secrets Manager, HashiCorp
   Vault, sops, or a similar system. Retrieve them at start-up, not at
   compile time.
3. **Rotate if exposed:** If the secret has ever been committed to source
   control, assume it is compromised and rotate it immediately.

## References

- [CWE-547: Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)
- [OWASP: Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)

## Implementation

- Rust: [`crates/zuit-lang-rust/src/analyzers/hardcoded_security_constant.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/hardcoded_security_constant.rs)
- Python: [`crates/zuit-lang-python/src/analyzers/hardcoded_security_constant.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/hardcoded_security_constant.rs)
- JavaScript: [`crates/zuit-lang-js/src/analyzers/hardcoded_security_constant.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/hardcoded_security_constant.rs)
