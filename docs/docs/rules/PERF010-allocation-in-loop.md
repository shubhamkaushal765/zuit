---
title: PERF010-allocation-in-loop
sidebar_label: PERF010-allocation-in-loop
---
# PERF010-allocation-in-loop

| Property | Value |
|---|---|
| Dimension | performance |
| Default severity | Low |
| Languages | Rust (file-level) |
| CWE | CWE-1050 |
| Analyzer kind | FileLevel |

## What it detects

A heap-allocating expression appears inside a `for`, `while`, or `loop` body.
The rule flags the following allocating patterns:

| Pattern | Example |
|---|---|
| `Vec::new()` / `Vec::with_capacity(…)` | `let v = Vec::new();` |
| `vec![…]` macro | `let v = vec![1, 2, 3];` |
| `String::new()` / `String::with_capacity(…)` / `String::from(…)` | `let s = String::new();` |
| `.to_string()` / `.to_owned()` | `let s = x.to_string();` |
| `format!(…)` macro | `let s = format!("{}", x);` |
| `Box::new(…)` | `let b = Box::new(val);` |
| `HashMap::new()` / `HashMap::with_capacity(…)` | `let m = HashMap::new();` |
| `BTreeMap::new()` | `let m = BTreeMap::new();` |
| `HashSet::new()` | `let s = HashSet::new();` |
| `BTreeSet::new()` | `let s = BTreeSet::new();` |

Closures defined **inside** loop bodies are also scanned — they execute once per
outer iteration, so allocations inside them carry the same per-iteration cost.

Nested `fn` item definitions inside loop bodies are **not** flagged because they
only run when explicitly called, not inline on every iteration.

## Why it matters

Allocating heap memory on every loop iteration creates unnecessary GC pressure
and cache misses.  In hot paths this can dominate execution time.  The pattern
is especially common when building `String`s or `Vec`s inside tight loops where
a single pre-allocated buffer would suffice.

## Example — flagged

```rust
// Vec::new() inside a for loop → PERF010
fn collect_lengths(items: &[&str]) -> Vec<usize> {
    let mut out = Vec::new();
    for item in items {
        let mut tmp = Vec::new(); // ← flagged
        tmp.push(item.len());
        out.extend(tmp);
    }
    out
}

// format!() inside a while loop → PERF010
fn build_labels(n: u32) -> Vec<String> {
    let mut labels = Vec::new();
    let mut i = 0;
    while i < n {
        labels.push(format!("item-{}", i)); // ← flagged
        i += 1;
    }
    labels
}
```

## Example — not flagged

```rust
// Allocation is outside the loop
fn collect_lengths(items: &[&str]) -> Vec<usize> {
    let mut out = Vec::with_capacity(items.len()); // outside loop ✓
    for item in items {
        out.push(item.len());
    }
    out
}

// .to_string() is not inside any loop
fn label(n: u32) -> String {
    n.to_string() // outside loop ✓
}
```

## Fix guidance

1. **Hoist the allocation.** Move the `Vec::new()` / `String::new()` before the
   loop and reuse the buffer:

   ```rust
   let mut buf = Vec::with_capacity(n);
   for item in items {
       buf.clear();          // reset without deallocating
       buf.push(item.len());
       // … use buf …
   }
   ```

2. **Use `.with_capacity(N)` once** when the final size is known before the
   loop starts.

3. **Collect with an iterator** instead of a manual loop:

   ```rust
   let lengths: Vec<usize> = items.iter().map(|s| s.len()).collect();
   ```

## Known false-positives

- Allocations that are semantically necessary on every iteration (e.g. building
  a `String` that is sent to a network socket each time).  Review findings
  manually and suppress with `// zuit: ignore PERF010-allocation-in-loop` where
  appropriate.

## Suppression

```rust
// zuit: ignore PERF010-allocation-in-loop
for item in items {
    let label = format!("{}", item); // intentional per-iteration alloc
    send(label);
}
```

## References

- [CWE-1050: Excessive Platform Resource Consumption within a Loop](https://cwe.mitre.org/data/definitions/1050.html)
- [The Rust Performance Book — Heap Allocations](https://nnethercote.github.io/perf-book/heap-allocations.html)
- [Rust `Vec::with_capacity`](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.with_capacity)
