---
title: PKG002-missing-types
sidebar_label: PKG002-missing-types
---
# PKG002-missing-types

**Dimension:** `packaging`
**Default severity:** Low
**Languages:** JavaScript / TypeScript (npm)
**Kind:** ProjectLevel
**CWE:** (none)
**OWASP:** —

## What it detects

Fires when an npm package provides no TypeScript type declarations — specifically
when **all** of the following are true:

1. `package.json` has no `types` or `typings` field.
2. No `.d.ts` file exists adjacent to the entry point.

**Entry point heuristic:** the `main` field in `package.json` is used as the
entry point; if `main` is absent, `index.js` is assumed. The companion `.d.ts`
is checked by swapping the file extension.

## Why it matters

A package with no type declarations provides no type information to TypeScript
consumers. This causes `noImplicitAny` errors in strict codebases and worsens
the developer experience for all TypeScript users.

## Example — flagged

```json
{
  "name": "my-lib",
  "main": "dist/index.js"
}
```

No `types` field and no `dist/index.d.ts` file present.

## Example — not flagged

```json
{
  "name": "my-lib",
  "main": "dist/index.js",
  "types": "dist/index.d.ts"
}
```

Or: `package.json` has no `types` field but `dist/index.d.ts` exists on disk.

## How to fix

**Option 1 — generate declarations from TypeScript source:**

Add `"declaration": true` to `tsconfig.json` and set the `types` field in
`package.json`:

```json
{
  "types": "dist/index.d.ts"
}
```

**Option 2 — hand-author a declaration file:**

Create `index.d.ts` (or `dist/index.d.ts`) and declare your public API.

**Option 3 — use `@types` package:**

If you maintain a companion `@types/my-lib` package, reference it in your
`README.md` but add a `types` field pointing to the stub:

```json
{
  "types": "./index.d.ts"
}
```

## Suppression

```toml
[ignore]
rules = ["PKG002-missing-types"]
```

## References

- [TypeScript — Publishing declaration files](https://www.typescriptlang.org/docs/handbook/declaration-files/publishing.html)
- [package.json `types` field — TypeScript docs](https://www.typescriptlang.org/docs/handbook/declaration-files/publishing.html#including-declarations-in-your-npm-package)
