---
title: CPLX001 — Module Fan-Out
sidebar_label: CPLX001
description: Flags files whose distinct import count exceeds a configurable threshold
---

# CPLX001-fan-out — Module Fan-Out

**Dimension:** Complexity
**Default severity:** Low
**CWE:** (none)
**OWASP:** (none)
**Languages:** All
**Last reviewed:** 2026-05-05

## What it detects

Flags files whose **distinct import count** exceeds a configurable threshold (default 20). Fan-out is the per-file out-degree in the module dependency graph: the number of distinct modules a file directly depends on. A high fan-out indicates that the file has too many responsibilities and is coupled to too many external concerns.

## Why it matters

High fan-out correlates with:

- **Low cohesion**: a file that imports 30+ modules is likely doing many unrelated things.
- **High coupling**: every additional import is a dependency that can change independently, increasing the risk of breakage.
- **Maintainability cost**: more imports mean more context the reader must hold in mind.

Robert C. Martin's "afferent and efferent coupling" metrics (Ca/Ce) formalise this intuition for package-level design. The rule extends the idea to the file level.

## Configuration

| Parameter | Type | Default | Notes |
|-----------|------|---------|-------|
| `threshold` | u32 | 20 | Files at or below this value are not flagged. |

Set in `zuit.toml`:

```toml
[rules.CPLX001-fan-out]
threshold = 20
```

## Counting methodology

The analyzer collects all `Import.path` values from `SemanticIndex::imports` for the file and deduplicates them using a `HashSet`. This means:

- **Python**: `from os import path, getcwd` records two imports (`os.path` and `os.getcwd`) but both share the same `os.*` namespace, so they count as 2 distinct paths.
- **Rust**: `use std::collections::{HashMap, HashSet};` records two distinct paths (`std::collections::HashMap` and `std::collections::HashSet`).
- **JS/TS**: `import { x, y } from 'lodash';` records one import with path `lodash`; only one distinct path is counted.

If this count exceeds the threshold, **exactly one finding** is emitted per file (at byte offset 0, spanning the whole file — the same as MAINT004-file-length).

## Examples — flagged

**Python** (>20 bare imports):

```python
import os
import sys
import re
import json
import csv
import math
import time
import datetime
import pathlib
import shutil
import tempfile
import hashlib
import logging
import typing
import collections
import itertools
import functools
import io
import struct
import threading
import subprocess  # 21 distinct modules — threshold exceeded
```

**JS/TS** (>20 import statements):

```typescript
import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import http from "http";
import https from "https";
import url from "url";
import util from "util";
import stream from "stream";
import events from "events";
import buffer from "buffer";
import process from "process";
import readline from "readline";
import zlib from "zlib";
import net from "net";
import dns from "dns";
import child_process from "child_process";
import timers from "timers";
import assert from "assert";
import querystring from "querystring";
import string_decoder from "string_decoder";  // 21 — threshold exceeded
```

**Rust** (>20 `use` lines, each counting as one import):

```rust
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
// … 17 more distinct paths …  ← threshold exceeded
```

## Example — not flagged

A focused module with 3 imports:

```python
import os
import json
from pathlib import Path
```

## Fix guidance

When a file's fan-out is high, consider:

1. **Split the file** into smaller, focused modules (one per responsibility). Each module then has a lower fan-out naturally.
2. **Remove transitively unused imports** — many IDEs and linters can detect and remove them automatically (`pyflakes`, `eslint no-unused-vars`, `cargo +nightly unused-imports`).
3. **Aggregate imports into a facade**: create a module that re-exports related items so consumers import from one place instead of five.
4. **Raise the threshold** if the file is a legitimate "glue layer" (e.g. a top-level `main.rs` or an `__init__.py` that re-exports many public items). This is better than suppressing the finding silently.

## Implementation

- Source: [crates/zuit-analyzers/src/fan_out.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/fan_out.rs)
- Severity / supported languages: see `RuleMeta` in source.

## References

- [Robert C. Martin — Agile Software Development, Principles, Patterns, and Practices](https://www.informit.com/store/agile-software-development-principles-patterns-and-9780135974445) — introduces afferent (Ca) and efferent (Ce) coupling metrics.
- [Coupling on Wikipedia](https://en.wikipedia.org/wiki/Coupling_(computer_programming))
