---
title: CHAIN003 — provenance-bundle-missing
sidebar_label: CHAIN003
---
# CHAIN003 — provenance-bundle-missing

| Property | Value |
|----------|-------|
| **Rule ID** | `CHAIN003-provenance-bundle-missing` |
| **Dimension** | `supply_chain` |
| **Severity** | Low |
| **Analyzer kind** | `ProjectLevel` |
| **Languages** | JavaScript / TypeScript (npm) |
| **CWE** | — |
| **OWASP** | — |

## What it detects

`CHAIN003` fires when a `dist/` directory exists in the project root but contains
no Sigstore provenance attestation file (`.sigstore` or `.sigstore.json`) as an
immediate child.

Only immediate children of `dist/` are inspected (v1 behaviour). Recursive
search is deferred.

**Note:** this rule performs a **presence-only** check. It does **not** parse,
verify, or validate the sigstore bundle contents.

## Why it matters

npm provenance (via Sigstore) lets consumers verify that a published package was
built from a specific source commit in a trusted CI environment. When a `dist/`
directory is present but no provenance file accompanies it, consumers cannot
distinguish an artifact produced by the official pipeline from one that has been
tampered with or replaced.

## How to fix

Publish with provenance enabled via npm:

```sh
npm publish --provenance
```

This generates a Sigstore attestation alongside the published bundle. The
attestation is transparent-logged and verifiable by consumers.

Alternatively, you can sign manually using the `sigstore` CLI and place the
resulting `.sigstore` or `.sigstore.json` file inside `dist/`.

## Suppression

Add the rule to the engine's global ignore list in `zuit.toml`:

```toml
[ignore]
rules = ["CHAIN003-provenance-bundle-missing"]
```

## References

- [npm provenance documentation](https://docs.npmjs.com/generating-provenance-statements)
- [Sigstore documentation](https://www.sigstore.dev/)
- [OpenSSF SLSA provenance](https://slsa.dev/provenance/)
