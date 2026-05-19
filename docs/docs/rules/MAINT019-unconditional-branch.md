---
title: MAINT019-unconditional-branch — Long branch dispatch
sidebar_label: MAINT019-unconditional-branch
description: Flags match expressions and if/else if chains with more branches than a configurable threshold.
---

# MAINT019-unconditional-branch — Long branch dispatch

| Property | Value |
| --- | --- |
| Rule ID | `MAINT019-unconditional-branch` |
| Dimension | Maintainability |
| Default severity | Low |
| CWE | [CWE-1119](https://cwe.mitre.org/data/definitions/1119.html) |
| Languages | Rust |
| Analyzer kind | FileLevel |
| Default threshold | 11 (fires when count ≥ 11) |

## What it detects

Fires when a `match` expression has arms that meet or exceed the configured threshold
(default: 11), or when an `if`/`else if` chain has conditional branches meeting or
exceeding the threshold.

**Match expressions:** Counts all arms, including the wildcard `_ =>` arm.

**If/else if chains:** Counts the number of conditional rungs. Note that `if let` 
expressions count as rungs in a chain. The trailing bare `else` block does NOT count 
toward the chain length — only the conditional branches (`if` and `else if`) are counted.

## Why it matters

Long dispatch chains (CWE-1119) create maintainability burden:

- More branches increase cyclomatic complexity and testing effort.
- Each new branch raises the risk of missing a case or introducing logic errors.
- Refactoring becomes error-prone because changes to one branch can affect others.
- Pattern-matching tables become harder to reason about at a glance.

## Examples — flagged

**Match with 11 arms:**

```rust
match status {
    StatusCode::OK => handle_ok(),
    StatusCode::CREATED => handle_created(),
    StatusCode::ACCEPTED => handle_accepted(),
    StatusCode::NO_CONTENT => handle_no_content(),
    StatusCode::BAD_REQUEST => handle_bad_request(),
    StatusCode::UNAUTHORIZED => handle_unauthorized(),
    StatusCode::FORBIDDEN => handle_forbidden(),
    StatusCode::NOT_FOUND => handle_not_found(),
    StatusCode::CONFLICT => handle_conflict(),
    StatusCode::SERVER_ERROR => handle_server_error(),
    StatusCode::SERVICE_UNAVAILABLE => handle_unavailable(),
}
// ^ MAINT019 fires: 11 arms ≥ threshold (11)
```

**If/else if chain with 11 rungs:**

```rust
if code < 100 {
    handle_info();
} else if code < 200 {
    handle_success();
} else if code < 300 {
    handle_redirect();
} else if code < 400 {
    handle_client_error();
} else if code < 500 {
    handle_server_error();
} else if code == 502 {
    handle_bad_gateway();
} else if code == 503 {
    handle_unavailable();
} else if code == 504 {
    handle_timeout();
} else if code == 505 {
    handle_unsupported();
} else if code == 511 {
    handle_auth_required();
} else {
    handle_unknown();  // This does NOT count
}
// ^ MAINT019 fires: 11 conditional branches ≥ threshold (11)
```

## Examples — not flagged

**Match with 10 arms (below threshold):**

```rust
match direction {
    Direction::North => move_up(),
    Direction::South => move_down(),
    Direction::East => move_right(),
    Direction::West => move_left(),
    Direction::NorthEast => move_diagonal_ne(),
    Direction::NorthWest => move_diagonal_nw(),
    Direction::SouthEast => move_diagonal_se(),
    Direction::SouthWest => move_diagonal_sw(),
    Direction::Center => do_nothing(),
    Direction::Unknown => handle_unknown(),
}
// Not flagged — 10 arms < threshold (11)
```

**Simple if/else (no chain):**

```rust
if user.is_admin() {
    grant_permissions();
} else {
    deny_permissions();
}
// Not flagged — standalone if/else, not a chain
```

## How to fix

- **HashMap or phf mapping:** Replace long matches with a lookup table when branches 
  are deterministic mappings:
  ```rust
  use phf::phf_map;
  static HANDLERS: phf::Map<&'static str, fn()> = phf_map! {
      "ok" => handle_ok,
      "created" => handle_created,
      // ...
  };
  ```

- **Extract helper functions:** Group related branches into smaller helper functions.

- **Convert if/else chains to match:** If logic is order-dependent, consider 
  extracting ranges or conditions into a match guard.

- **Trait dispatch:** Use polymorphism when branches represent different behaviors 
  for different types.

## Configuration

| Key | Default | Description |
| --- | ------- | ----------- |
| `threshold` | `11` | Minimum branch count (inclusive) that triggers the rule |

```toml
[rules."MAINT019-unconditional-branch"]
threshold = 15   # raise threshold for highly branching code
```

## Implementation

- [`crates/zuit-lang-rust/src/analyzers/unconditional_branch.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-rust/src/analyzers/unconditional_branch.rs)

## References

- [CWE-1119: Excessive Branching](https://cwe.mitre.org/data/definitions/1119.html)
