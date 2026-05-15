---
title: PKG003-dual-package-hazard
sidebar_label: PKG003-dual-package-hazard
---
# PKG003-dual-package-hazard

**Dimension:** `packaging`
**Default severity:** Medium
**Languages:** JavaScript / TypeScript (npm)
**Kind:** ProjectLevel
**CWE:** (none)
**OWASP:** —

## What it detects

Fires when a `package.json` exposes both CommonJS and ESM entry points without
a proper conditional exports map. Specifically, the rule fires when either of
these conditions holds:

1. Both `main` (CJS) and `module`/`exports` (ESM) are declared, but no
   `exports` map covers at least both `import` and `require` conditions.
2. `type: "module"` is declared alongside `.cjs` files at the project root
   (a common mis-configuration where the CJS build was not isolated).

## Why it matters

Dual CJS+ESM packages can cause two copies of the same package to be loaded in
the same process — one by `require`, one by `import`. This breaks:

- **Singleton assumptions** (e.g. React context, store instances).
- **`WeakMap` keys** — two copies means two sets of prototype chains.
- **`instanceof` checks** — objects from one copy fail checks against the other.

## Example — flagged

```json
{
  "main": "dist/index.cjs",
  "module": "dist/index.esm.js"
}
```

Both `main` (CJS) and `module` (ESM) are declared, but no `exports` map provides
`import`/`require` conditions.

## Example — not flagged

```json
{
  "exports": {
    ".": {
      "import": "./dist/index.esm.js",
      "require": "./dist/index.cjs"
    }
  }
}
```

The `exports` map covers both `import` and `require` conditions — consumers load
the correct variant.

## How to fix

Add a conditional `exports` map that explicitly routes `import` and `require` to
their respective builds:

```json
{
  "main": "dist/index.cjs",
  "module": "dist/index.esm.js",
  "exports": {
    ".": {
      "import": "./dist/index.esm.js",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    }
  }
}
```

## Suppression

```toml
[ignore]
rules = ["PKG003-dual-package-hazard"]
```

## References

- [Node.js — Dual CommonJS/ES module packages](https://nodejs.org/api/esm.html#dual-commonjses-module-packages)
- [Rollup — output.exports](https://rollupjs.org/configuration-options/#output-exports)
- [The Dual Package Hazard (blog)](https://joyeecheung.github.io/blog/2024/03/18/dual-package-hazard/)
