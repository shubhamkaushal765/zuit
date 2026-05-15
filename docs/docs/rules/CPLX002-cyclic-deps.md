---
title: CPLX002 — Cyclic Imports
sidebar_label: CPLX002
description: Flags files that participate in an import cycle
---

# CPLX002-cyclic-deps — Cyclic Imports

**Dimension:** Complexity
**Default severity:** High
**Languages:** All
**Last reviewed:** 2026-05-05

## What it detects

Flags files that participate in an import cycle — a set of modules that mutually depend on each other, forming a cycle in the import graph.

A cycle of N modules means that module A imports B, B imports C, … and eventually some module imports A again. The rule emits one finding per detected cycle, anchored at the lexicographically-smallest file in the cycle.

## Why it matters

Import cycles:

- Prevent many build tools from processing files in a clean topological order.
- Create **initialisation-order bugs**: when module A's top-level code runs it may find module B's exports not yet fully initialised.
- Make the codebase harder to reason about because a change to any member of the cycle can ripple arbitrarily.
- Make individual modules harder to test in isolation.
- Block tree-shaking / dead-code elimination in JavaScript bundlers.

## Algorithm

### 1. Node assignment

Each `ParsedFile` path becomes a node. Nodes are assigned stable integer indices by sorting paths lexicographically before indexing.

### 2. Module-key map

For each file path a set of lookup keys is derived by stripping the file extension and joining path components with `::`. For example:

| File path                | Keys registered                                    |
|--------------------------|----------------------------------------------------|
| `src/utils/fmt.py`       | `src::utils::fmt`, `utils::fmt`, `fmt`             |
| `crates/foo/src/lib.rs`  | `crates::foo::src::lib`, …, `lib`                  |

All suffix variants (longest to shortest) are inserted into a `HashMap<String, usize>`. The **first** registration wins, which — because nodes are processed in lexicographic path order — gives predictable, deterministic results when two files share a short suffix.

### 3. Edge building

For each `Import.path` in each file the resolver tries:

1. An exact match in the key map (covers Python `import b` where `b` is a key).
2. A JS/TS relative-import stem extraction: `./b` → `b`, `../utils/fmt` → `fmt`, then looked up in the key map.

Imports that don't resolve to any in-project file are silently skipped.

### 4. Tarjan SCC

A hand-rolled Tarjan Strongly-Connected-Component algorithm identifies all SCCs. An SCC of size > 1, or size 1 with a self-loop, is a cycle.

### 5. Finding emission

One finding per non-trivial SCC, placed at the lexicographically-smallest file. The message lists all module keys in the cycle (sorted) so output is deterministic.

## Resolver limitations

- **Cross-language imports** (e.g. Python calling a compiled extension) will never link; only `SemanticIndex.imports` entries are considered.
- **Standard-library and third-party imports** are silently skipped — they don't match any in-project file path.
- **Alias matching is heuristic**: a short key like `fmt` may resolve to the wrong file if two project files have the same stem. The lex-first file wins.
- **Rust cycle detection is limited**: `use crate::…` paths and `mod` declarations require a full build graph that is not available at the `SemanticIndex` level. The analyzer works with whatever `syn` surfaces in `index.imports` (top-level `use` items).

  > **TODO (future work):** A Rust-specific pass that resolves `mod foo;` edges and `use crate::` paths against the file tree would enable reliable Rust cycle detection without requiring a `cargo check` build.

## Configuration

No thresholds — any cycle is always flagged.

## Example — flagged (Python)

**Fixture:** `fixtures/python/cyclic_deps/`

```python
# a.py
import b          # a → b

# b.py
import c          # b → c

# c.py
import a          # c → a  ← closes the cycle
```

Finding emitted for `a.py` (lex-smallest):

```
CPLX002-cyclic-deps [High]
fixtures/python/cyclic_deps/a.py:1:1
file is part of an import cycle of 3 modules: fixtures::python::cyclic_deps::a,
fixtures::python::cyclic_deps::b, fixtures::python::cyclic_deps::c
```

## Example — not flagged

A healthy set of files where imports flow in one direction only (A → B → C, no back edge) produces an empty SCC set and no findings.

## Fix guidance

- **Extract a shared dependency**: identify the code that both sides need and move it into a new module that neither side defines but both can import.
- **Invert a dependency**: redesign so that the lower-level module exposes an abstract interface (trait / protocol / interface), and the higher-level module provides the concrete implementation.
- **Merge**: if two modules are always used together and can't be decoupled, merge them into a single file to make the coupling explicit.
- **Dependency injection**: pass a value or callback at call time instead of importing a module at the top level.

## Implementation

- Source: [crates/zuit-analyzers/src/cyclic_deps.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/cyclic_deps.rs)
- Tarjan SCC: inline implementation in the same file (`tarjan_sccs` / `tarjan_visit`).
- Fixtures: `fixtures/python/cyclic_deps/`, `fixtures/js/cyclic_deps/`.

## References

- [Tarjan, R. E. (1972). "Depth-first search and linear graph algorithms."](https://doi.org/10.1137/0201010)
- [Acyclic dependencies principle — Robert C. Martin, "Clean Architecture"](https://www.oreilly.com/library/view/clean-architecture-a/9780134494272/)
- [Circular dependency — Wikipedia](https://en.wikipedia.org/wiki/Circular_dependency)
