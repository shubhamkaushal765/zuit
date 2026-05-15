---
title: PERF003-import-side-effect
sidebar_label: PERF003-import-side-effect
---
# PERF003-import-side-effect

**Dimension:** Performance
**Severity:** Medium
**Kind:** FileLevel (Python only)

## Description

Detects top-level statements in Python modules that execute side-effectful code at
import time. When a library module is imported, Python executes every top-level
statement. Side effects (network calls, file I/O, logging setup, database
connections, print statements) at module level impose hidden costs on all consumers
of the library, even when the feature is never used.

## Allowed top-level forms (not flagged)

- `import …` / `from … import …`
- `def` / `async def` / `class` definitions
- `if __name__ == "__main__":` guard blocks
- Simple constant assignments: `NAME = <literal value>`
- `__all__` assignments
- Bare annotations: `x: int`

## Examples

### Flagged

```python
print("mylib loaded")          # PERF003: side effect at import time
setup_logging()                # PERF003: function call at import time
db = connect_to_database()     # PERF003: I/O at import time
for x in range(100):           # PERF003: loop at import time
    register(x)
```

### Not flagged

```python
import os
from typing import Optional

VERSION = "1.0"           # simple constant — allowed
__all__ = ["MyClass"]     # __all__ — always allowed

class MyClass:
    pass

def setup():
    setup_logging()       # side effect inside a function — fine

if __name__ == "__main__":
    print("running directly")  # guarded — not executed on import
```

## Entry-point carve-out

This rule is **automatically suppressed** for all files in a project that declares
`[project.scripts]` entries in `pyproject.toml`. Entry-point scripts (e.g. CLI
tools) are expected to execute top-level code when run directly.

```toml
[project.scripts]
mycli = "myapp.cli:main"   # PERF003 suppressed for all files in this project
```

## Fix

Move side-effectful code into functions:

```python
# Before (flagged)
setup_logging()

# After (not flagged)
def main():
    setup_logging()
    ...

if __name__ == "__main__":
    main()
```

Or defer initialization to an explicit `init()` function that consumers call
when they opt in to the feature.

## Suppression

```python
# zuit: ignore PERF003-import-side-effect
_registry = build_default_registry()  # justified: cached at module load for performance
```
