---
title: CHAIN004 — unmaintained-transitive
sidebar_label: CHAIN004
---
# CHAIN004 — unmaintained-transitive

| Property | Value |
|----------|-------|
| **Rule ID** | `CHAIN004-unmaintained-transitive` |
| **Dimension** | `supply_chain` |
| **Severity** | Medium |
| **Analyzer kind** | `ProjectLevel` |
| **Languages** | JavaScript / TypeScript (npm) |
| **CWE** | — |
| **OWASP** | — |

## What it detects

`CHAIN004` flags transitive dependencies in `package-lock.json` (v3 format)
whose `time` field is older than **18 months** relative to the current date.

A dependency that has not been updated in 18+ months may be unmaintained,
meaning security vulnerabilities are unlikely to be patched.

### Data source

The `packages` map in a `package-lock.json` v3 file may contain a `time` field
with an ISO-8601 timestamp indicating when that version was published. When this
field is absent the entry is silently skipped. No network call is ever made.

### Lock-file version

Only `lockfileVersion: 3` is processed. v1 and v2 schemas use a different layout
(`dependencies` map vs `packages` map) and are skipped silently.

## Why it matters

Unmaintained dependencies are a supply-chain risk: known CVEs go unpatched,
security researchers stop reviewing the code, and the package may eventually be
abandoned or taken over by a malicious actor.

## Example — flagged

A `package-lock.json` v3 entry with a `time` field more than 18 months in
the past:

```json
{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/some-old-lib": {
      "version": "1.2.3",
      "time": "2022-01-15T10:00:00.000Z"
    }
  }
}
```

## How to fix

Update the dependency to a maintained version:

```sh
npm update some-old-lib
```

If no maintained version exists, consider migrating to an actively-maintained
alternative or forking the package.

## Suppression

Add the rule to the engine's global ignore list in `zuit.toml`:

```toml
[ignore]
rules = ["CHAIN004-unmaintained-transitive"]
```

## References

- [npm package-lock.json documentation](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json)
- [OpenSSF Scorecard — Maintained check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained)
