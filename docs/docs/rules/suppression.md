---
title: Finding Suppression
description: How to suppress zuit findings using inline comments
---

# Finding Suppression

zuit supports inline suppression of specific findings via special comment directives. This lets you adopt zuit in CI on an existing codebase without having to fix every pre-existing finding upfront.

## Syntax

| Language  | Comment style |
|-----------|--------------|
| Rust      | `// zuit: ignore RULE_ID` |
| JavaScript / TypeScript | `// zuit: ignore RULE_ID` |
| Python    | `# zuit: ignore RULE_ID` |

## Scope

A suppression directive covers findings at **two positions**:

- The same line as the comment (inline suppression).
- The line **immediately below** the comment (annotation on the line above the offending code).

## Comma-separated multi-rule suppression

Multiple rule IDs can be listed in a single directive, separated by commas (with optional surrounding spaces):

```rust
// zuit: ignore MAINT003-fn-length, MAINT006-too-many-params
pub fn complex_legacy_function(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 {
    // ...
}
```

## Whole-file suppression

Use `ignore-file` instead of `ignore` to suppress a rule for every finding in the entire file. Place the directive near the top of the file:

```rust
// zuit: ignore-file SEC001-hardcoded-secret
```

```python
# zuit: ignore-file SEC001-hardcoded-secret
```

```typescript
// zuit: ignore-file SEC001-hardcoded-secret
```

## Report summary

When findings are suppressed, the summary line in all output formats reflects the count:

- Terminal: `  5 files scanned, 0 parse failures, 12ms (3 suppressed)`
- Markdown: `_Scanned 5 file(s) &mdash; 0 parse failure(s) &mdash; 12ms &mdash; 3 suppressed_`
- JSON: `"stats": { ..., "suppressed": 3 }`

When `suppressed == 0`, the suffix is omitted entirely.

## Examples

### Rust — inline suppression

```rust
fn process(  // zuit: ignore MAINT003-fn-length
    data: &[u8],
) -> Result<(), Error> {
    // long function body ...
}
```

### Rust — suppress on the line above

```rust
// zuit: ignore MAINT001-cyclomatic
fn complex_parser(input: &str) -> Vec<Token> {
    // many branches ...
}
```

### Python — inline suppression

```python
def _legacy_handler(a, b, c, d, e, f):  # zuit: ignore MAINT006-too-many-params
    pass
```

### JavaScript / TypeScript — whole-file suppression

```typescript
// zuit: ignore-file DOC001-public-api-undoc
export function undocumentedButKnown(): void { /* ... */ }
```

## Configuration

The `[suppressions]` section in `zuit.toml` is reserved for future options (e.g. `require_justification = true` to mandate an explanatory comment after the rule ID). No options are active in this release.
