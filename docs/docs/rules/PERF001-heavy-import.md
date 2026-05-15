---
title: PERF001-heavy-import
sidebar_label: PERF001-heavy-import
---
# PERF001-heavy-import

**Dimension:** Performance
**Severity:** Medium
**Kind:** FileLevel (Python only)

## Description

Detects top-level `import` or `from ... import` statements for heavyweight packages
(`numpy`, `pandas`, `tensorflow`, `torch`, `scipy`, `matplotlib`, `cv2`, `sklearn`)
in Python library files.

Importing a Python module executes all top-level statements in that module at
`import` time. When a library imports a heavyweight package at the top level, every
consumer of that library must wait for the heavyweight package to initialize — even
if the feature that requires it is never called. For packages like `tensorflow` or
`torch`, this load time can be hundreds of milliseconds to several seconds.

## Examples

### Flagged

```python
import pandas           # PERF001: imposes ~100ms+ load on every import of this lib
import torch            # PERF001: imposes ~1s+ load on every import of this lib

def compute(df):
    return df.sum()
```

### Not flagged

```python
def compute(data):
    import pandas as pd  # lazy import — cost paid only when compute() is called
    df = pd.DataFrame(data)
    return df.sum()
```

## Affected packages

| Package | Typical load time |
|---------|------------------|
| `tensorflow` | 1–5 s |
| `torch` | 0.5–2 s |
| `numpy` | 100–300 ms |
| `pandas` | 200–500 ms |
| `scipy` | 200–400 ms |
| `matplotlib` | 200–400 ms |
| `cv2` (OpenCV) | 100–300 ms |
| `sklearn` (scikit-learn) | 200–500 ms |

## Fix

Move the import inside the function or method that uses it (lazy-import pattern):

```python
def train_model(data):
    import torch          # imported only when train_model() is called
    ...
```

Or use `TYPE_CHECKING` for type-annotation-only imports:

```python
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd   # not executed at runtime
```

## Suppression

```python
# zuit: ignore PERF001-heavy-import
import numpy  # justified: this module is always used with numpy
```
