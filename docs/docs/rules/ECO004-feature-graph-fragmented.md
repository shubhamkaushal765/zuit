---
title: ECO004-feature-graph-fragmented
sidebar_label: ECO004-feature-graph-fragmented
---
# ECO004-feature-graph-fragmented

**Dimension:** `ecosystem`
**Default severity:** Low
**Languages:** Rust (project-level)
**CWE:** (none)

## What it detects

Fires when the `[features]` table contains:

1. A feature whose enabled list contains a value starting with `"!"` (a disabled/negated dependency).
2. A feature name starting with `dep:` without the `?` optional qualifier.

These patterns indicate non-additive feature designs that can break downstream consumers combining multiple feature sets.

## Why it matters

Cargo features are supposed to be *additive*: enabling more features should never break code that enabled fewer features. Non-additive features violate this contract and make the crate harder to use in workspaces where multiple consumers enable different feature subsets.

## Heuristic limitations

This is a **conservative heuristic** with a known false-positive risk:

- The `dep:` prefix is valid in Cargo for optional dependency aliasing — `dep:serde` means "enable the optional `serde` dependency". Not all `dep:` usages are non-additive.
- Some intentionally non-additive features (e.g. mutually exclusive backends) are valid design choices. Suppress the rule if this is intentional.

Always review findings manually.

## Example — flagged

```toml
[features]
no-default = ["!default"]  # negated feature — non-additive
```

## Example — not flagged

```toml
[features]
default = ["std"]
std = []
async = ["tokio"]
```

## Fix guidance

- Redesign non-additive features as separate crates or as documented mutually exclusive options.
- Use `dep:?<name>` syntax for optional dependency features.
- See the [Cargo book on features](https://doc.rust-lang.org/cargo/reference/features.html).

## Suppression

```toml
# Cargo.toml
# zuit: ignore ECO004-feature-graph-fragmented
[features]
no-default = ["!default"]
```

## References

- [Cargo features — optional dependencies](https://doc.rust-lang.org/cargo/reference/features.html#optional-dependencies)
- [Cargo RFC: weak dependency features](https://github.com/rust-lang/rfcs/blob/master/text/3143-cargo-weak-namespaced-features.md)
