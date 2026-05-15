---
title: PKG004-unpinned-deps
sidebar_label: PKG004-unpinned-deps
---
# PKG004-unpinned-deps

**Dimension:** `packaging`
**Default severity:** Medium (`dependencies`) / Low (`devDependencies`)
**Languages:** JavaScript / TypeScript (npm)
**Kind:** ProjectLevel
**CWE:** (none)
**OWASP:** —

## What it detects

Fires for each dependency in `package.json` whose version range is unpinned.
A range is considered unpinned if it:

- Is the empty string `""`
- Is `"*"` (any version)
- Is `"latest"` (always resolves to tip)
- Starts with `">"` (unbounded upward range)

### Severity by section

| Section | Severity | Rationale |
|---------|----------|-----------|
| `dependencies` | Medium | Affects consumers who install the package |
| `devDependencies` | Low | Only affects the developer machine |

## Why it matters

Unpinned ranges accept arbitrary future versions, including:

- Versions that introduce breaking API changes.
- Versions that introduce security vulnerabilities.
- Versions that contain malicious code (supply-chain compromise via a hijacked package).

Using `*` or `latest` in published packages is especially dangerous because it
pulls in whatever happens to be the current version at install time, which can
change at any point after you publish.

## Example — flagged

```json
{
  "dependencies": {
    "some-lib": "*",
    "another-lib": "latest",
    "bad-range": ">1.0.0"
  }
}
```

## Example — not flagged

```json
{
  "dependencies": {
    "some-lib": "^1.2.3",
    "another-lib": "~2.0.0",
    "exact-pin": "3.1.4"
  }
}
```

## How to fix

Replace unpinned ranges with semver constraints:

```json
{
  "dependencies": {
    "some-lib": "^1.2.3"
  }
}
```

Use `npm install some-lib` to automatically add the current version with a
compatible caret range, or `npm install --save-exact some-lib` for an exact pin.

## Suppression

```toml
[ignore]
rules = ["PKG004-unpinned-deps"]
```

## References

- [npm semver documentation](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#dependencies)
- [OpenSSF Scorecard — Pinned dependencies](https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies)
