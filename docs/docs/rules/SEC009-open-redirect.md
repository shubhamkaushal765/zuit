---
title: SEC009-open-redirect — Open Redirect via User-Controlled URL
sidebar_label: SEC009-open-redirect
---
# SEC009-open-redirect — Open Redirect via User-Controlled URL

**Dimension:** Security
**Default severity:** Medium
**CWE:** CWE-601
**OWASP:** A01:2021 – Broken Access Control
**Languages:** All (Python, JS/TS, Rust)
**Last reviewed:** 2026-05-08

## What it detects

Flags source lines that both issue an HTTP redirect **and** incorporate
user-controlled input into the redirect target URL without validation.

A finding is emitted for each source line satisfying **both** conditions:

1. **Redirect call** — the line matches one of:
   `redirect(`, `res.redirect(`, `response.redirect(`, `Response.redirect(`,
   `HttpResponseRedirect(`, `RedirectResponse(`, `Redirect::to(`,
   `Redirect::permanent(`, `Redirect::temporary(`, or a `Location:` header
   assignment via `set_header(…Location…)`, `headers["Location"] =`, or
   `location =`.

2. **Untrusted-input signal** — the line contains at least one of:
   - An interpolation marker: `${`, f-string `{`, `" + `, `' + `, `+ "`,
     `+ '`, `format!(`, `.format(`, `%s`.
   - A known untrusted-source token: `req.query`, `req.params`, `req.body`,
     `request.args`, `request.form`, `request.GET`, `request.POST`,
     `request.json`, `params[`, `query[`.

Comment lines (trimmed start begins with `//`, `#`, `*`, `/*`) are skipped.

## Why it matters

An open redirect allows an attacker to craft a legitimate-looking URL that
redirects the victim to a malicious site.  The victim trusts the domain in the
initial URL (e.g. `https://app.example.com/go?url=https://evil.example.com`)
and may disclose credentials or be phished.  CWE-601 / OWASP A01:2021 (Broken
Access Control) covers this class.

## Configuration

This rule has no configurable threshold.  Disable per project:

```toml
[rules.SEC009-open-redirect]
enabled = false
```

## Examples flagged

**Python** — Flask redirect to a query-parameter URL:

```python
from flask import Flask, redirect, request

app = Flask(__name__)

@app.get("/login")
def login_redirect():
    return redirect(request.args.get("next"))  # flagged: user input in redirect
```

**JS/TS** — Express redirect to a query-string URL:

```typescript
import express from "express";

const app = express();

app.get("/go", (req, res) => {
    res.redirect(req.query.url as string);  // flagged: user input in redirect
});
```

**Rust** — Axum redirect with formatted user input:

```rust
use axum::response::Redirect;

pub async fn redirect_handler(user_input: String) -> Redirect {
    Redirect::to(&format!("{}", user_input))  // flagged: user input in redirect
}
```

## Examples not flagged

**Python** — redirect to a fixed path:

```python
from flask import redirect

def home():
    return redirect("/dashboard")  # not flagged: static target
```

**JS/TS** — redirect to a hardcoded URL:

```typescript
res.redirect("https://app.example.com/home");  // not flagged: no user input
```

## Fix guidance

- **Maintain an allow-list** of safe redirect targets (relative paths or a
  small set of known-good domains).  Reject anything not on the list.
- **Prefer relative paths** (`/dashboard`, `/account`) rather than absolute
  URLs to eliminate cross-domain redirects entirely.
- **Validate the scheme and host** if absolute URLs are needed: ensure the
  resulting URL's hostname is on your allow-list before redirecting.
- For OAuth / SSO `next` parameters, store the intended destination
  server-side (e.g. in the session) keyed to an opaque token, and look it up
  after authentication completes.

## Implementation

- Source: `crates/zuit-analyzers/src/open_redirect.rs`
- Severity / supported languages: see `RuleMeta` in source.

## References

- [OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
