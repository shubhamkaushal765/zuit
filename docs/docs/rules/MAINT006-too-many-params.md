---
title: MAINT006 — Too Many Parameters
sidebar_label: MAINT006
description: Flags functions with more parameters than a configurable threshold
---

# MAINT006-too-many-params — Too Many Parameters

**Dimension:** Maintainability
**Default severity:** Low
**Languages:** All
**Last reviewed:** 2026-05-05

## What it detects

Flags functions, methods, and closures whose parameter count exceeds a configurable threshold. The default threshold is 5. The count excludes the `self`/`this` receiver; language frontends do not include the receiver in `FunctionLike::param_count`.

## Why it matters

Functions with many parameters are harder to call correctly, harder to test, and often indicate a function that tries to do too much. Callers must remember the meaning and order of every argument; a single-character transposition can pass type-checking while silently producing wrong results. Long parameter lists are also a signal that the function may violate the Single Responsibility Principle.

Grouping logically related parameters into a dedicated struct (the "Parameter Object" refactoring) makes intent explicit, makes additional future parameters free (just add a field), and makes testing easier (build one struct value per test scenario).

## Configuration

| Parameter | Type | Default | Notes |
|-----------|------|---------|-------|
| `threshold` | u32 | 5 | Functions with **more than** this many parameters are flagged. |

Set in `zuit.toml`:
```toml
[rules.MAINT006-too-many-params]
threshold = 5
```

## Example — flagged

**Rust:**

```rust
pub fn create_user(
    first_name: &str,
    last_name: &str,
    email: &str,
    age: u32,
    role: Role,
    is_active: bool,  // 6 parameters → flagged
) -> User {
    // ...
}
```

**Python:**

```python
def create_user(first_name, last_name, email, age, role, is_active, department):
    # 7 parameters → flagged
    pass
```

**TypeScript:**

```typescript
export function createUser(
    firstName: string,
    lastName: string,
    email: string,
    age: number,
    role: Role,
    isActive: boolean,   // 6 parameters → flagged
): User {
    // ...
}
```

## Example — not flagged / refactored

**Rust — parameter object:**

```rust
pub struct CreateUserRequest {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub age: u32,
    pub role: Role,
    pub is_active: bool,
}

pub fn create_user(req: CreateUserRequest) -> User {
    // 1 parameter → not flagged
}
```

**Python — dataclass or TypedDict:**

```python
from dataclasses import dataclass

@dataclass
class CreateUserRequest:
    first_name: str
    last_name: str
    email: str
    age: int
    role: str
    is_active: bool
    department: str

def create_user(req: CreateUserRequest) -> User:
    # 1 parameter → not flagged
    pass
```

## Fix guidance

- **Introduce a Parameter Object**: Group the parameters into a named struct, dataclass, or interface. This makes the call site self-documenting and allows future fields to be added without changing the signature.
- **Split the function**: If the parameters fall into distinct groups that serve different sub-tasks, consider splitting the function into smaller helpers, each with fewer responsibilities.
- **Use a Builder**: For complex object construction, a builder pattern separates the construction steps and eliminates long constructor signatures.
- **Default parameters / keyword arguments**: In languages that support them (Python, TypeScript with optional fields), use default values to reduce the number of required arguments at the call site.

## Implementation

- Source: [crates/zuit-analyzers/src/too_many_params.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/too_many_params.rs)
- Parameter count source: `FunctionLike::param_count` in [crates/zuit-core/src/index.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-core/src/index.rs)
- Severity / supported languages: see `RuleMeta` in source.

## References

- [Refactoring: Introduce Parameter Object](https://refactoring.guru/introduce-parameter-object)
- [Clean Code — Function Arguments (Robert C. Martin)](https://www.oreilly.com/library/view/clean-code-a/9780136083238/)
- [CWE-1121: Excessive Complexity of Variables, Methods, or Classes](https://cwe.mitre.org/data/definitions/1121.html)
