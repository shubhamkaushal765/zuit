---
title: SEC014-redos-regex — ReDoS-vulnerable regular expression
sidebar_label: SEC014-redos-regex
description: Detects regular expressions with nested quantifiers or duplicate alternation branches that may cause catastrophic backtracking (ReDoS).
---

# SEC014-redos-regex — ReDoS-vulnerable regular expression

| Property         | Value                                    |
| ---------------- | ---------------------------------------- |
| Dimension        | Security                                 |
| Default severity | High                                     |
| CWE              | CWE-1333                                 |
| Languages        | Rust, Python, JavaScript, TypeScript     |

## What it detects

Flags regular expression patterns that contain structures known to cause
**catastrophic backtracking** in backtracking-based regex engines:

1. **Nested repetition** — a quantifier (`+`, `*`, `?`, `{n,m}`) whose body
   itself contains a quantifier. The canonical example is `(a+)+`: on input
   like `"aaaaab"`, a backtracking engine explores an exponential number of
   paths. More subtle variants include `(.*)*`, `(\w+)+end`, and `((a|b)+)+`.

2. **Alternation with duplicate branches** — an `Alternation` node where two
   or more branches stringify identically (e.g. `(a|a)+`, `(foo|foo)`).
   Combined with an outer repetition this produces polynomial or exponential
   work.

The check uses `regex_syntax` to parse the pattern and walk the AST. Patterns
that fail to parse are **silently skipped** — they cannot be executed by a
regex engine and flagging them would be a false positive.

### Negative-case guards

The rule does **not** fire when:

- The pattern fails to parse (e.g. unbalanced `(`).
- The repetition is over a character class (`[a-z]+`) with no nested
  quantifier.
- The repetition is bounded (`\d{1,5}`) with no nested quantifier.
- All alternation branches are distinct (e.g. `(foo|bar)+`).

## Examples — flagged

**Python:**

```python
import re

re.compile(r"(a+)+")      # FLAGGED — nested repetition
re.compile(r"(.*)*")      # FLAGGED — nested repetition
re.match(r"(\w+)+end", s) # FLAGGED — nested repetition
```

**Rust:**

```rust
use regex::Regex;

Regex::new("(a+)+").unwrap();   // FLAGGED — nested repetition
Regex::new("(.*)*").unwrap();   // FLAGGED — nested repetition
```

**JavaScript/TypeScript:**

```ts
const r1 = /(a+)+/;              // FLAGGED — nested repetition
const r2 = new RegExp("(.*)*");  // FLAGGED — nested repetition
```

## Examples — not flagged

**Python:**

```python
import re

re.compile(r"[a-z]+")    # OK — no nested quantifiers
re.compile(r"\d{1,5}")   # OK — bounded, no nesting
re.compile(r"^abc$")     # OK — no quantifiers
re.compile(r"(foo|bar)") # OK — distinct alternation branches
```

**Rust:**

```rust
use regex::Regex;

Regex::new("[a-z]+").unwrap();  // OK
Regex::new(r"\d{1,5}").unwrap(); // OK
```

## Fix guidance

1. **Rewrite to avoid nested quantifiers.** Instead of `(a+)+`, use `a+` or
   anchor the pattern with `^…$` so the engine cannot retry partial matches.
2. **Use atomic groups or possessive quantifiers** if your engine supports them
   (Python's `re2` / `regex` crate with the `(?atomic:…)` extension, PCRE
   `(?>…)` or `++` / `*+`).
3. **Limit input length at the call site** before passing user-controlled data
   to the regex engine. Short inputs bound the worst case.
4. **Switch to a linear-time engine.** The Rust `regex` crate and Google's RE2
   guarantee `O(n)` matching and reject patterns that could catastrophically
   backtrack.

## References

- [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- [OWASP: ReDoS (Regular Expression Denial of Service)](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [regex-syntax crate](https://docs.rs/regex-syntax/) — AST library used for detection

## Implementation

- Cross-language: [`crates/zuit-analyzers/src/redos.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/redos.rs)
- `SemanticIndex.regex_literals` populated by:
  - Rust: [`crates/zuit-lang-rust/src/index.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/index.rs) — detects `Regex::new` / `RegexBuilder::new`
  - Python: [`crates/zuit-lang-python/src/index.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/index.rs) — detects `re.compile`, `re.match`, `re.search`, etc.
  - JavaScript: [`crates/zuit-lang-js/src/index.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-js/src/index.rs) — detects `/pattern/flags` literals and `new RegExp(…)`
