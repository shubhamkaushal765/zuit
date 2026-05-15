---
title: PKG005-engines-missing
sidebar_label: PKG005-engines-missing
---
# PKG005-engines-missing

**Dimension:** `packaging`
**Default severity:** Low
**Languages:** JavaScript / TypeScript (npm)
**Kind:** ProjectLevel
**CWE:** (none)
**OWASP:** —

## What it detects

Fires when `package.json` does not declare an `engines.node` field.

Without this field, consumers cannot know which Node.js versions are supported,
leading to silent runtime failures when the package is installed on an
incompatible runtime.

## Why it matters

Node.js releases frequently introduce and deprecate APIs, change behaviour of
built-ins, and alter module resolution. A package that silently installs on Node
10 but was written for Node 20 will produce confusing runtime errors for
consumers on older runtimes — failures that are hard to diagnose without the
engines constraint.

## Example — flagged

```json
{
  "name": "my-lib",
  "version": "1.0.0",
  "main": "index.js"
}
```

No `engines` field.

## Example — not flagged

```json
{
  "name": "my-lib",
  "version": "1.0.0",
  "main": "index.js",
  "engines": {
    "node": ">=18.0.0"
  }
}
```

## How to fix

Add an `engines.node` field specifying the minimum (and optionally maximum)
supported Node.js version:

```json
{
  "engines": {
    "node": ">=18.0.0"
  }
}
```

To enforce this at install time (rather than just as documentation), you can
also add:

```json
{
  "engines": {
    "node": ">=18.0.0"
  },
  "engineStrict": true
}
```

Or configure npm to enforce engine ranges:

```sh
npm config set engine-strict true
```

## Suppression

```toml
[ignore]
rules = ["PKG005-engines-missing"]
```

## References

- [npm package.json `engines` field](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines)
- [Node.js LTS release schedule](https://nodejs.org/en/about/previous-releases)
