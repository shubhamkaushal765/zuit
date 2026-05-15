---
title: SEC010-ssrf — Server-Side Request Forgery via User-Controlled URL
sidebar_label: SEC010-ssrf
---
# SEC010-ssrf — Server-Side Request Forgery via User-Controlled URL

**Dimension:** Security
**Default severity:** High
**CWE:** CWE-918
**OWASP:** A10:2021 – Server-Side Request Forgery
**Languages:** All (Python, JS/TS, Rust)
**Last reviewed:** 2026-05-08

## What it detects

Flags source lines that issue an outbound HTTP request using a URL derived
from user-supplied input without validation.

A finding is emitted for each source line satisfying **both** conditions:

1. **HTTP-client call** — the line matches one of:
   `requests.get(`, `requests.post(`, `requests.put(`, `requests.delete(`,
   `requests.request(`, `urllib.request.urlopen(`, `urlopen(`,
   `httpx.get(`, `httpx.post(`, `aiohttp.ClientSession`, `fetch(`,
   `axios.get(`, `axios.post(`, `axios.request(`, `axios(`,
   `http.get(`, `http.request(`, `node-fetch`, `reqwest::get(`,
   `reqwest::Client::new()`, `Client::new().get(`, `ureq::get(`,
   `ureq::post(`, `hyper::Client`.

2. **Untrusted-input signal** — the line contains at least one of:
   - An interpolation marker: `${`, f-string `{`, `" + `, `' + `, `+ "`,
     `+ '`, `format!(`, `.format(`, `%s`.
   - A known untrusted-source token: `req.query`, `req.params`, `req.body`,
     `request.args`, `request.form`, `request.GET`, `request.POST`,
     `request.json`, `params[`, `query[`.

Comment lines (trimmed start begins with `//`, `#`, `*`, `/*`) are skipped.

## Why it matters

Server-Side Request Forgery (SSRF) lets an attacker instruct the server to
make requests to internal services, cloud metadata endpoints
(e.g. `169.254.169.254`), or other infrastructure that is not accessible from
the public internet.  This can lead to credential theft, lateral movement, or
data exfiltration.  OWASP A10:2021 is dedicated to this class of vulnerability
because cloud deployments make it particularly dangerous.

## Configuration

This rule has no configurable threshold.  Disable per project:

```toml
[rules.SEC010-ssrf]
enabled = false
```

## Examples flagged

**Python** — Flask proxy that forwards to a user-supplied host:

```python
import requests
from flask import request

def proxy():
    host = request.args.get("host")
    resp = requests.get(f"https://{host}/api")  # flagged: user-controlled host
    return resp.text
```

**JS/TS** — Express proxy using `fetch` with a template literal:

```typescript
app.get("/proxy", async (req, res) => {
    const result = await fetch(`${req.query.url}/data`);  // flagged
    res.send(await result.text());
});
```

**Rust** — Axum handler passing user input to `reqwest::get`:

```rust
pub async fn ssrf_handler(user_input: String) -> String {
    let resp = reqwest::get(&format!("https://{}/api", user_input))  // flagged
        .await.unwrap();
    resp.text().await.unwrap()
}
```

## Examples not flagged

**Python** — request to a fixed URL:

```python
resp = requests.get("https://api.example.com/data")  # not flagged: static URL
```

**Rust** — request without user input interpolation:

```rust
let resp = reqwest::get("https://api.example.com/v1/status").await?;  // not flagged
```

## Fix guidance

- **Allow-list destinations** — maintain an explicit set of permitted hosts;
  reject any URL whose hostname is not on that list.
- **Block internal ranges** — before issuing the request, resolve the hostname
  to an IP and reject loopback (`127.0.0.1`, `::1`), link-local
  (`169.254.0.0/16`), and RFC1918 private ranges.
- **Use DNS rebinding protection** — re-verify the resolved IP after connection
  establishment (or use an SSRF-safe HTTP client library such as
  `ssrf_filter` / `ssrf-req-filter`).
- **Avoid forwarding raw user-supplied URLs** — if a proxy is truly required,
  proxy only a limited, pre-validated set of paths or content types.

## Implementation

- Source: `crates/zuit-analyzers/src/ssrf.rs`
- Severity / supported languages: see `RuleMeta` in source.

## References

- [OWASP A10:2021 – Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger: SSRF](https://portswigger.net/web-security/ssrf)
