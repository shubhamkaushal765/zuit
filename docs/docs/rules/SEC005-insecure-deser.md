---
title: SEC005 — Insecure Deserialization
sidebar_label: SEC005
description: Flags insecure deserialization of untrusted data
---

# SEC005-insecure-deser — Insecure Deserialization

**Dimension:** Security
**Default severity:** High
**CWE:** CWE-502
**OWASP:** A08:2021 – Software and Data Integrity Failures
**Languages:** All (Python, JS/TS; Rust skipped — bincode/serde are not unsafe by default)
**Last reviewed:** 2026-05-06

## What it detects

Flags use of insecure deserialization APIs that can execute arbitrary code when fed untrusted input. Detection uses two complementary signals per file:

1. **Import scan** — at least one import path contains (case-insensitively) a known insecure-deser module substring:

   | Language | Recognised import substrings |
   |----------|------------------------------|
   | Python   | `pickle`, `cpickle`, `marshal`, `yaml` |
   | JS/TS    | `node-serialize`, `serialize-javascript` |

2. **Source scan** — the raw file text is scanned for insecure call-site patterns:
   - `pickle.load(`, `pickle.loads(`
   - `cPickle.load(`, `cPickle.loads(`
   - `marshal.load(`, `marshal.loads(`
   - `yaml.load(` — **suppressed** when `Loader=yaml.SafeLoader`, `Loader=SafeLoader`, or `Loader=yaml.CSafeLoader` appears within 120 bytes
   - `yaml.unsafe_load(`
   - `unserialize(` — only when `node-serialize` is imported

If Signal 1 (import) is absent the file is skipped immediately. One finding is emitted per matching call site.

## Why it matters

Deserializing untrusted data with `pickle`, `marshal`, or `node-serialize` allows an attacker to execute arbitrary code on the server. These formats embed executable Python/JS code directly in the serialized byte stream — loading a crafted payload is equivalent to running arbitrary code. OWASP A08:2021 lists insecure deserialization as a top-10 risk.

## Configuration

This rule has no configurable threshold. Disable per project:

```toml
[rules.SEC005-insecure-deser]
enabled = false
```

## Examples flagged

**Python** — `pickle.loads` on user-supplied data:

```python
import pickle

def load_user_data(data: bytes):
    return pickle.loads(data)   # flagged: insecure deserialization
```

**Python** — `yaml.load` without a safe loader:

```python
import yaml

def load_config(stream):
    return yaml.load(stream)    # flagged: yaml.load without safe Loader=
```

**JS/TS** — `node-serialize.unserialize`:

```typescript
import serialize from "node-serialize";

export function loadData(data: string): unknown {
  return serialize.unserialize(data);  // flagged: insecure deserialization
}
```

## Examples not flagged

**Python** — `yaml.load` with a safe loader:

```python
import yaml

def load_config(stream):
    return yaml.load(stream, Loader=yaml.SafeLoader)  # not flagged
```

**Python** — `json.loads` (always safe):

```python
import json

def load_data(s: str):
    return json.loads(s)  # not flagged
```

## Fix guidance

- **Python**: replace `pickle.loads` with `json.loads`; replace `yaml.load` with `yaml.safe_load` or pass `Loader=yaml.SafeLoader`.
- **JS/TS**: replace `node-serialize.unserialize` with `JSON.parse` on validated input.
- Never deserialize data from untrusted sources using pickle, marshal, or node-serialize regardless of any other validation.

## Implementation

- Source: [crates/zuit-analyzers/src/insecure_deser.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/insecure_deser.rs)
- Severity / supported languages: see `RuleMeta` in source.

## References

- [OWASP A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Python pickle security warning](https://docs.python.org/3/library/pickle.html)
