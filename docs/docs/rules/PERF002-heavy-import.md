---
title: PERF002-heavy-import
sidebar_label: PERF002-heavy-import
---
# PERF002-heavy-import

**Dimension:** `performance`
**Default severity:** Medium
**Languages:** JavaScript / TypeScript
**Kind:** FileLevel
**CWE:** (none)

## What it detects

Fires when a file contains a top-level import of a known-heavy npm package:
`lodash`, `moment`, `underscore`, or `jquery`.

Importing the entire package at the top level prevents bundlers from
tree-shaking unused code, resulting in unnecessarily large bundles. Both ES
module `import` declarations and CommonJS `require()` calls at module scope are
detected.

**Only bare package names are flagged.** A sub-path import like
`"lodash/cloneDeep"` is not flagged because it allows tree-shaking.

## Example — flagged

```js
import _ from "lodash";               // PERF002: entire lodash pulled in
import moment from "moment";          // PERF002: moment is ~300 KiB
const $ = require("jquery");          // PERF002: full jquery bundle
```

## Example — not flagged

```js
import cloneDeep from "lodash/cloneDeep";   // sub-path import: tree-shakeable
import { format } from "date-fns";          // lighter alternative to moment
```

## Heavy package list

| Package | Approx. minified size | Preferred alternative |
|---------|----------------------|----------------------|
| `lodash` | ~24 KiB (individual methods) | Deep imports (`lodash/cloneDeep`) or `lodash-es` |
| `moment` | ~300 KiB | `date-fns` or `dayjs` |
| `underscore` | ~17 KiB | Native `Array`/`Object` methods or `lodash/fp` |
| `jquery` | ~87 KiB (min+gzip) | Native DOM APIs or smaller utilities |

## How to fix

Use deep imports that only bundle the functions you need:

```js
// Before:
import _ from "lodash";
const result = _.cloneDeep(obj);

// After:
import cloneDeep from "lodash/cloneDeep";
const result = cloneDeep(obj);
```

Or switch to a lighter alternative:

```js
// Replace moment with date-fns
import { format } from "date-fns";
```

## Configuration

The heavy-package list is hardcoded in v1. A configurable list will be
available when `Config` gains a `[javascript.perf]` section.

## Suppression

```js
// zuit: ignore PERF002-heavy-import
import _ from "lodash";
```

## References

- [You might not need lodash](https://youmightnotneed.com/lodash/)
- [You don't need Moment.js](https://github.com/you-dont-need/You-Dont-Need-Momentjs)
- [Bundlephobia — compare bundle sizes](https://bundlephobia.com/)
