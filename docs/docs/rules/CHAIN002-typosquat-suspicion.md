---
title: CHAIN002 — typosquat-suspicion
sidebar_label: CHAIN002
---
# CHAIN002 — typosquat-suspicion

| Property | Value |
|----------|-------|
| **Rule ID** | `CHAIN002-typosquat-suspicion` |
| **Dimension** | `supply_chain` |
| **Severity** | High |
| **Analyzer kind** | `ProjectLevel` |

## What it detects

`CHAIN002` fires when a dependency name in `pyproject.toml` is within
Damerau-Levenshtein distance 1–`threshold` (default **2**) of a name in the
bundled top-50 PyPI list, **excluding exact matches** and the project's own
package name.

Distance is computed after normalisation: both names are lowercased and hyphens
are replaced with underscores before comparison.

## Why it matters

Typosquatting attacks register packages with names one or two keystrokes away
from popular packages (e.g. `requessts` instead of `requests`).  A developer
who miskeys a dependency name may accidentally install malicious code.

## Configuration

The threshold is configurable (range 1–4, default 2).  At distance 1 only
single-character mistakes are caught; at distance 2 two-character mistakes are
also caught.  Raising the threshold beyond 2 significantly increases false
positives.

## Bundled top-PyPI list

The list of popular names is a static `&[&str]` constant at
`crates/zuit-lang-python/src/analyzers/chain/typosquat.rs`.

**Snapshot date:** 2026-05.

Current seed (50 names): `requests`, `numpy`, `pandas`, `scipy`, `matplotlib`,
`scikit-learn`, `tensorflow`, `torch`, `keras`, `django`, `flask`, `fastapi`,
`sqlalchemy`, `pytest`, `pytest-cov`, `click`, `pyyaml`, `jinja2`, `lxml`,
`beautifulsoup4`, `urllib3`, `idna`, `certifi`, `charset-normalizer`, `six`,
`setuptools`, `wheel`, `pip`, `packaging`, `tomli`, `attrs`,
`typing-extensions`, `importlib-metadata`, `more-itertools`, `python-dateutil`,
`pytz`, `cryptography`, `bcrypt`, `passlib`, `redis`, `celery`, `gunicorn`,
`uvicorn`, `httpx`, `aiohttp`, `websockets`, `pillow`, `opencv-python`,
`transformers`, `langchain`.

### Future Maintenance

The list must be refreshed periodically to track changes in PyPI popularity
rankings.  This is a manual, infrequent task — see `.agent/PYTHON_PLAN.md §8`
for the refresh policy.  False positives for legitimate packages not in the list
are expected; the rule is intentionally conservative.

## Known false positives

- Packages whose names are legitimately close to a popular package name
  (e.g. `sklearn` vs `scikit-learn`).
- The project's own package name is automatically excluded from checks.

## How to fix

Verify the dependency name in your `pyproject.toml`:

```toml
[project]
# Wrong (potential typo):
dependencies = ["requessts>=2.0"]

# Correct:
dependencies = ["requests>=2.0"]
```

## Suppression

Pyproject-anchored inline suppression is not currently parsed by the engine for
`ProjectLevel` rules.  To suppress, add the rule to the engine's global ignore
list:

```toml
[ignore]
rules = ["CHAIN002-typosquat-suspicion"]
```

## References

- [PyPI typosquatting](https://pypi.org/help/#suspicious-distributions)
- [Damerau-Levenshtein distance](https://en.wikipedia.org/wiki/Damerau%E2%80%93Levenshtein_distance)
