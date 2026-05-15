---
title: MAINT008-large-impl-block — Large `impl` Block or Class
sidebar_label: MAINT008-large-impl-block
---
# MAINT008-large-impl-block — Large `impl` Block or Class

**Dimension:** Maintainability
**Default severity:** Low
**Languages:** All (Rust `impl` blocks, Python classes; JS/TS produce no findings)
**CWE:** (none)
**Last reviewed:** 2026-05-07

## What it detects

Flags `impl` blocks (Rust) and classes (Python) that contain more methods than
a configurable threshold (default 30). A type with a very large number of
methods is a common code-smell that signals a violation of the Single
Responsibility Principle — the type is likely doing too many things.

## Configuration

```toml
[rules."MAINT008-large-impl-block"]
threshold = 30   # default; method count strictly > threshold triggers the rule
```

## Example — flagged

**Rust (31 methods, default threshold 30):**

```rust
pub struct God;

impl God {
    pub fn do_thing_1(&self) {}
    pub fn do_thing_2(&self) {}
    // … 29 more methods …
    pub fn do_thing_31(&self) {}
}
// Finding: `God` has 31 methods (threshold 30); consider splitting into smaller types
```

**Python (31 methods, default threshold 30):**

```python
class GodClass:
    def do_thing_1(self): pass
    def do_thing_2(self): pass
    # … 29 more methods …
    def do_thing_31(self): pass
# Finding: `GodClass` has 31 methods (threshold 30); consider splitting into smaller types
```

## Example — not flagged

```rust
pub struct Focused;

impl Focused {
    pub fn step_1(&self) {}
    pub fn step_2(&self) {}
    // … up to 30 methods total — at or below threshold → clean
}
```

## Fix guidance

- Extract a logically cohesive subset of methods into a dedicated helper type
  or trait.
- Separate I/O concerns from pure business logic.
- Use the Facade pattern: keep a thin public surface and delegate to smaller
  focused types.

## Implementation

- Source: `crates/zuit-analyzers/src/large_impl_block.rs`
- Threshold read via `Config::rule_threshold("MAINT008-large-impl-block", 30)`.
- One finding is emitted per exceeding group, located at the span of the first
  method (best available proxy for the block header).
- Languages without `parent_name` support (JS/TS) produce no findings.

## References

- [Martin Fowler — God Object](https://martinfowler.com/bliki/TwoHardThings.html)
- [Refactoring Guru — Large Class smell](https://refactoring.guru/smells/large-class)
