---
title: SEC008-csrf-missing — State-Changing HTTP Handler Without CSRF Protection
sidebar_label: SEC008-csrf-missing
---
# SEC008-csrf-missing — State-Changing HTTP Handler Without CSRF Protection

**Dimension:** Security
**Default severity:** Medium
**CWE:** CWE-352
**OWASP:** A01:2021 – Broken Access Control
**Languages:** All (Python, JS/TS, Rust)
**Last reviewed:** 2026-05-07

## What it detects

Flags handler functions in recognised web-framework files that accept
state-changing HTTP methods (POST, PUT, DELETE, PATCH) when no CSRF protection
token is present anywhere in the file.

A finding is emitted for each handler function satisfying **all three** conditions:

1. **Recognised web framework import** — the file imports at least one of:
   `express`, `koa`, `fastify`, `body-parser` (JS/TS);
   `flask`, `fastapi`, `django` (Python);
   `axum`, `actix_web`, `rocket`, `warp` (Rust).

2. **State-changing handler marker** in the source region surrounding the
   function declaration:
   - **JS/TS:** `app.post(`, `app.put(`, `app.delete(`, `app.patch(`,
     `router.post(`, `router.put(`, `router.delete(`, `router.patch(`
   - **Python:** `@app.post(`, `@app.put(`, `@app.delete(`, `@app.patch(`,
     `@app.route(`, `@router.post(`, `@router.put(`, `@blueprint.route(`
   - **Rust:** `Router::new()`, `.route(`, `#[post`, `#[put`, `#[delete`,
     `#[patch`, `web::post()`, `web::put()`, `web::delete()`

3. **No CSRF protection** — none of the following tokens appear in imports or
   non-comment source lines: `csrf`, `csurf`, `csrf_protect`, `CSRFProtect`,
   `flask_wtf`, `csrf_token`, `XSRF`, `xsrf`.

One finding is emitted per matching handler function.

## Why it matters

Cross-Site Request Forgery (CSRF) exploits the trust a web application has in
the user's browser.  An attacker can trick an authenticated user into
involuntarily submitting a state-changing request (fund transfer, password
change, account deletion) by embedding a hidden form or image on a malicious
page.  OWASP A01:2021 (Broken Access Control) covers this class of
vulnerability.

Stateless REST APIs using `Authorization` headers are not vulnerable; traditional
session-cookie applications and SPAs that rely on cookies for authentication are.
Being conservative, the analyzer only emits findings when the file both imports a
recognised web framework **and** lacks any CSRF token in its source.

## Configuration

This rule has no configurable threshold.  Disable per project:

```toml
[rules.SEC008-csrf-missing]
enabled = false
```

## Examples flagged

**Python** — Flask handler with no CSRF protection:

```python
from flask import Flask, request

app = Flask(__name__)

@app.post("/transfer")
def transfer():  # flagged: state-changing handler, no CSRF protection
    amount = request.json.get("amount", 0)
    return {"status": "ok", "amount": amount}
```

**JS/TS** — Express handler without `csurf` middleware:

```typescript
import express from "express";

const app = express();
app.use(express.json());

app.post("/withdraw", (req, res) => {  // flagged: no csurf middleware
    const amount = req.body.amount;
    res.json({ status: "ok", amount });
});
```

**Rust** — Axum router without CSRF middleware:

```rust
use axum::Router;
use axum::routing::post;

pub async fn transfer_handler() -> &'static str { "transferred" }

pub fn app() -> Router {  // flagged: .route( with post handler, no csrf layer
    Router::new().route("/transfer", post(transfer_handler))
}
```

## Examples not flagged

**Python** — Flask-WTF `CSRFProtect` present:

```python
from flask import Flask, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)  # not flagged: CSRFProtect in imports

@app.post("/transfer")
def transfer():
    return {"status": "ok"}
```

**JS/TS** — `csurf` middleware applied:

```typescript
import express from "express";
import csurf from "csurf";  // not flagged: csurf import present

const app = express();
app.use(csurf());

app.post("/withdraw", (req, res) => {
    res.json({ status: "ok" });
});
```

**Rust** — CSRF layer from `tower_csrf`:

```rust
use axum::Router;
use axum::routing::post;
use tower_csrf::CsrfLayer;  // not flagged: tower_csrf import present

pub async fn transfer_handler() -> &'static str { "transferred" }

pub fn app() -> Router {
    Router::new()
        .route("/transfer", post(transfer_handler))
        .layer(CsrfLayer::new())
}
```

## Fix guidance

- **Express / Node.js**: install `csurf` and apply it as middleware before
  state-changing routes: `app.use(csurf({ cookie: true }))`.
- **Flask / Python**: use `Flask-WTF`; call `CSRFProtect(app)` and include
  `{{ form.csrf_token }}` in every HTML form.
- **Axum / Rust**: add the `axum-csrf` or `tower_csrf` crate and register the
  CSRF layer: `.layer(CsrfLayer::new())`.
- For **JSON APIs** that do not use cookies, ensure the API requires an
  `Authorization` header (Bearer token) so browser-initiated cross-origin
  requests cannot automatically include credentials.

## Implementation

- Source: `crates/zuit-analyzers/src/csrf_missing.rs`
- Severity / supported languages: see `RuleMeta` in source.

## References

- [OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Express csurf middleware](https://github.com/expressjs/csurf)
- [Flask-WTF CSRF Protection](https://flask-wtf.readthedocs.io/en/stable/form.html#security)
