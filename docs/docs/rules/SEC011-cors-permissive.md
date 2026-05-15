---
title: SEC011-cors-permissive — Overly Permissive CORS Configuration
sidebar_label: SEC011-cors-permissive
---
# SEC011-cors-permissive — Overly Permissive CORS Configuration

**Dimension:** Security
**Default severity:** Medium
**CWE:** CWE-942
**OWASP:** A05:2021 – Security Misconfiguration
**Languages:** All (Python, JS/TS, Rust)
**Last reviewed:** 2026-05-08

## What it detects

Flags source lines that configure Cross-Origin Resource Sharing (CORS) in an
overly permissive manner.

A finding is emitted for each non-comment source line matching any of:

- **`Access-Control-Allow-Origin: *`** — the line contains both
  `Access-Control-Allow-Origin` and `*`.
- **Express `cors()` wildcard** — the line contains `cors(` **and** `origin`
  **and** (`"*"` or `'*'` or `: true`).
- **FastAPI/Starlette `CORSMiddleware`** — the line contains `allow_origins`
  **and** `"*"`.
- **Rust `CorsLayer::permissive` / `CorsLayer::very_permissive`** — the line
  contains `CorsLayer::permissive()`, `CorsLayer::very_permissive()`, or
  `Cors::permissive()`.
- **Django `CORS_ORIGIN_ALLOW_ALL`** — the line contains
  `CORS_ORIGIN_ALLOW_ALL` or `CORS_ALLOW_ALL_ORIGINS` with the value `True`.

Comment lines (trimmed start begins with `//`, `#`, `*`, `/*`) are skipped.

## Why it matters

A wildcard `Access-Control-Allow-Origin: *` allows any origin on the web to
read responses from the API.  If the API also sets
`Access-Control-Allow-Credentials: true` (the combination is rejected by
browsers, but misconfigurations creep in), or if the API returns sensitive
data without credential checks, cross-origin attacks can exfiltrate data.
OWASP A05:2021 (Security Misconfiguration) covers CORS misconfiguration as a
common, high-impact category.

## Configuration

This rule has no configurable threshold.  Disable per project:

```toml
[rules.SEC011-cors-permissive]
enabled = false
```

## Examples flagged

**Python** — FastAPI with `allow_origins=["*"]`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(CORSMiddleware, allow_origins=["*"])  # flagged
```

**JS/TS** — Express with `cors({ origin: "*" })`:

```typescript
import cors from "cors";

app.use(cors({ origin: "*" }));  // flagged
```

**Rust** — Axum with `CorsLayer::permissive()`:

```rust
use tower_http::cors::CorsLayer;

let cors = CorsLayer::permissive();  // flagged
```

## Examples not flagged

**Python** — origin restricted to known domains:

```python
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"])  # not flagged
```

**JS/TS** — cors with explicit allow-list:

```typescript
app.use(cors({ origin: ["https://app.example.com", "https://admin.example.com"] }));  // not flagged
```

## Fix guidance

- **Enumerate allowed origins explicitly**: replace `"*"` with a list of the
  exact origins your front-end runs on
  (e.g. `["https://app.example.com", "https://staging.example.com"]`).
- **Never combine `allow_credentials=True` with `allow_origins=["*"]`**:
  browsers block this combination, but the configuration is still a security
  hazard for future changes.
- **Use environment-specific configuration**: production and staging may need
  different allow-lists; read them from environment variables rather than
  hard-coding.
- **Review preflight handling**: ensure that `OPTIONS` responses are also
  gated on the same allow-list.

## Implementation

- Source: `crates/zuit-analyzers/src/cors_permissive.rs`
- Severity / supported languages: see `RuleMeta` in source.

## References

- [OWASP A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-942: Overly Permissive Cross-domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)
- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#access-control-allow-origin)
