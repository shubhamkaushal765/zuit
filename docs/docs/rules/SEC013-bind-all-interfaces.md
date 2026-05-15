---
title: SEC013-bind-all-interfaces — Server binds to all network interfaces
sidebar_label: SEC013-bind-all-interfaces
description: Flags server-bind calls that use "0.0.0.0" or "::" as the bind address, exposing the service on every network interface.
---

# SEC013-bind-all-interfaces — Server binds to all network interfaces

| Property         | Value                                    |
| ---------------- | ---------------------------------------- |
| Dimension        | Security                                 |
| Default severity | Medium                                   |
| Confidence       | Medium                                   |
| CWE              | CWE-1327                                 |
| Languages        | Rust, Python, JavaScript, TypeScript     |

## What it detects

Flags call sites where a server or socket is bound to `"0.0.0.0"` (all IPv4
interfaces) or `"::"` (all IPv6 interfaces). Both of these "any-address" values
expose the listening service on every network interface — including public-facing
ones — which is rarely the correct behaviour in production.

The rule also recognises the `host:port` forms: `"0.0.0.0:8080"` and
`"[::]:8080"` are treated the same as the bare any-address strings.

Detection is **syntactic only**: the rule checks whether a string literal passed
to a known bind callee equals or starts with an any-address value.  It does not
perform data-flow analysis, so if the address is built dynamically the rule will
not fire.

## Why it matters

A service bound to `0.0.0.0` or `::` accepts inbound connections on **every**
network interface on the host, including the public internet-facing interface.
If the service is intended to be reachable only from `localhost` (e.g. a
health-check endpoint, an admin API, or a development server) this can expose
it to unauthorised access.

Restricting the bind address to `127.0.0.1` or `::1` at the code level is a
simple defence-in-depth measure that does not rely on firewall rules being
correctly applied.

## Examples — flagged

**Python (Flask):**

```python
app.run("0.0.0.0", port=5000)      # FLAGGED — any IPv4 interface
uvicorn.run(app, host="0.0.0.0")   # FLAGGED — any IPv4 interface (kwarg)
socket.bind(("0.0.0.0", 8080))     # FLAGGED — any IPv4 interface (tuple)
```

**Rust:**

```rust
TcpListener::bind("0.0.0.0:8080")  // FLAGGED — any IPv4 interface
TcpListener::bind("::")             // FLAGGED — any IPv6 interface
```

**JavaScript/TypeScript:**

```ts
app.listen("0.0.0.0", 3000);       // FLAGGED — any IPv4 interface
server.listen("::");                // FLAGGED — any IPv6 interface
```

## Examples — not flagged

**Python:**

```python
app.run("127.0.0.1", port=5000)           # OK — loopback only
uvicorn.run(app, host="::1", port=8000)   # OK — IPv6 loopback
```

**Rust:**

```rust
TcpListener::bind("127.0.0.1:8080")  // OK — loopback only
TcpListener::bind("[::1]:8080")       // OK — IPv6 loopback
```

**JavaScript/TypeScript:**

```ts
app.listen("127.0.0.1", 3000);  // OK — loopback only
app.listen(3000);               // OK — port-only, no all-interface string
```

## Configuration

No configuration knobs in v1. The bind-callee allowlist is hard-coded to the
most common server-construction function names in each language:

| Language             | Recognized callees                                                               |
| -------------------- | -------------------------------------------------------------------------------- |
| Rust                 | `bind`, `bind_addr`, `new` (last path segment)                                   |
| Python               | `bind`, `run`, `listen` (bare name or attribute method)                          |
| JavaScript/TypeScript | `listen`, `bind` (bare name or member-expression method)                         |

## Fix guidance

1. **Use loopback:** Replace `"0.0.0.0"` with `"127.0.0.1"` (or `"::"` with
   `"::1"`) when the service is intended to be localhost-only.
2. **Use an environment variable:** If the bind address needs to be configurable
   (e.g. `0.0.0.0` in a container), read it from an environment variable so the
   policy is enforced at deployment time, not in source code.
3. **Add a firewall rule as defence-in-depth:** Even when `0.0.0.0` is
   intentional, ensure that the port is firewalled from public access at the
   infrastructure level.

## References

- [CWE-1327: Binding to an Unrestricted IP Address](https://cwe.mitre.org/data/definitions/1327.html)
- [OWASP: Network Segmentation](https://owasp.org/www-project-developer-guide/draft/implementation/documentation/network-segmentation/)

## Implementation

- Rust: [`crates/zuit-lang-rust/src/analyzers/bind_all_interfaces.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/bind_all_interfaces.rs)
- Python: [`crates/zuit-lang-python/src/analyzers/bind_all_interfaces.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/bind_all_interfaces.rs)
- JavaScript: [`crates/zuit-lang-js/src/analyzers/bind_all_interfaces.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/bind_all_interfaces.rs)
