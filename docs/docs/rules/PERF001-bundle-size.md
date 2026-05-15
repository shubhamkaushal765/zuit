---
title: PERF001-bundle-size
sidebar_label: PERF001-bundle-size
---
# PERF001-bundle-size

**Dimension:** `performance`
**Default severity:** Low
**Languages:** JavaScript / TypeScript (npm)
**Kind:** ProjectLevel
**CWE:** (none)

## What it detects

Fires when the `dist/` directory's total byte size recursively exceeds **1 MiB**
(1,048,576 bytes).

A large unminified bundle suggests the package has not been tree-shaken or split
into smaller chunks. Consumers who install the package will download and parse
all of it, increasing page-load and startup latency.

### Detection algorithm

Recursively sums the byte sizes of every regular file under
`<project_root>/dist/`. If the total exceeds 1 MiB, one `PERF001-bundle-size`
Low finding is emitted pointing at the `dist/` directory. If `dist/` does not
exist the rule is skipped silently.

## Example — flagged

A `dist/` directory containing large, unminified files totalling more than 1 MiB:

```
dist/
  index.js        (800 KiB — unminified)
  helpers.js      (400 KiB — unminified)
```

## Example — not flagged

```
dist/
  index.min.js    (120 KiB — minified and tree-shaken)
  helpers.min.js   (40 KiB — minified)
```

## How to fix

- Enable minification in your bundler (Rollup, webpack, esbuild, Vite).
- Enable tree-shaking by using ES module (`import`/`export`) syntax and setting
  `"sideEffects": false` in `package.json`.
- Split large entry points into smaller chunks using code-splitting.
- Audit and remove unused dependencies.

```sh
# Check current bundle size
du -sh dist/

# Analyse what is contributing to bundle size (example with source-map-explorer)
npx source-map-explorer dist/index.js
```

## Configuration

There is no configuration knob in v1 — the 1 MiB threshold is fixed. A
configurable threshold will be available when `Config` gains a `[javascript.perf]`
section.

## Suppression

```toml
[ignore]
rules = ["PERF001-bundle-size"]
```

## References

- [web.dev — Reduce JavaScript payloads with tree shaking](https://web.dev/articles/reduce-javascript-payloads-with-tree-shaking)
- [Rollup tree-shaking guide](https://rollupjs.org/introduction/#tree-shaking)
