---
title: SEC015-log-injection — Log Injection
sidebar_label: SEC015-log-injection
description: Flags logging calls that pass unsanitized user-controlled input, enabling log injection attacks (CWE-117).
---

# SEC015-log-injection — Log Injection

| Property         | Value                                    |
| ---------------- | ---------------------------------------- |
| Dimension        | Security                                 |
| Default severity | Medium                                   |
| Confidence       | Medium                                   |
| CWE              | CWE-117                                  |
| Languages        | Rust, Python, JavaScript, TypeScript     |

## What it detects

Flags logging calls that pass **user-controlled input** without sanitization
into log format strings. An attacker who can inject newlines or CRLF sequences
into logs can:

- Forge or spoof log entries.
- Inject new log lines that look like legitimate events.
- Confuse log aggregation and alerting tools.
- Potentially exploit log parsers or SIEM systems.

A finding fires when **all** of:

1. The call is a known logging function (`logger.info`, `logging.debug`,
   `console.log`, `log::warn!`, `tracing::info!`, etc.).
2. The first argument is a format string containing a placeholder (`{}`,
   `%s`, `%d`, `%r`, `%v`) or is a template literal with at least one
   substitution expression (`${...}`).
3. A subsequent argument's leading identifier is either in the request-style
   allowlist (`req`, `request`, `params`, `body`, `query`, `ctx`, `context`,
   `input`, `user_input`, `payload`, `headers`, `cookies`, `args`, `kwargs`,
   `event`, `data`) or appears in the immediately enclosing function's
   parameter list.

## Examples — flagged

**Python:**

```python
def view(req):
    logger.info("user said {}".format(req.body))   # FLAGGED

def handle(req):
    logger.info("user: %s", req.body)              # FLAGGED

def run(user_input):
    logging.debug("received: %s", user_input)      # FLAGGED
```

**Rust:**

```rust
fn handler(req: Request) {
    log::info!("user: {}", req);    // FLAGGED (macro-body regex parse)
}

fn view(req: Request) {
    info!("received: {}", req);     // FLAGGED (macro-body regex parse)
}
```

**JavaScript/TypeScript:**

```ts
function view(req) {
    logger.info(`user: ${req.body}`);       // FLAGGED
}

function handle(req) {
    console.log("user: %s", req.body);      // FLAGGED
}
```

## Examples — not flagged

**Python:**

```python
def startup():
    logger.info("startup complete")         # no placeholder, no user arg

def report():
    total = 42
    logger.info("user count: %d", total)   # total is not request-style or a param
```

**Rust:**

```rust
fn startup() {
    log::info!("startup complete");         // no placeholder
}

fn report() {
    let total = 42;
    log::info!("count: {}", total);        // total is not request-style or a param
}
```

**JavaScript/TypeScript:**

```ts
function startup() {
    logger.info("startup complete");        // no placeholder, no user arg
}

function report() {
    logger.info("user count", 42);          // no placeholder + non-user arg
}
```

## Fix guidance

1. **Sanitize before logging:** Strip or escape newlines (`\n`, `\r`) and
   other control characters from user-supplied values before passing them to
   logging calls.
2. **Use structured logging:** Pass user data as structured key-value fields
   rather than interpolating it into format strings (e.g., `slog`, `tracing`,
   Python's `extra={}` parameter, or a JSON logger).
3. **Validate input early:** Enforce format and character-set constraints on
   input at the entry point so malformed data is rejected before reaching
   logging code.

## Limitation — Rust (macro-body regex parse)

For Rust, the macro body is parsed via regex over the token-string rather than
via a full syntactic AST. This is a known limitation — the finding message
includes the phrase `(macro-body regex parse)` to make this explicit. Complex
macro invocations (e.g., using `target:` labels or nested macros) may produce
false positives or negatives.

## References

- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [OWASP: Log Injection](https://owasp.org/www-community/attacks/Log_Injection)

## Implementation

- Rust: [`crates/zuit-lang-rust/src/analyzers/log_injection.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/log_injection.rs)
- Python: [`crates/zuit-lang-python/src/analyzers/log_injection.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/log_injection.rs)
- JavaScript: [`crates/zuit-lang-js/src/analyzers/log_injection.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/analyzers/log_injection.rs)
