---
title: SEC002-eval-sink — Unsafe code execution
sidebar_label: SEC002-eval-sink
description: Detects calls to eval, exec, and Function constructor in Python and JavaScript.
---

# SEC002-eval-sink — Unsafe code execution

| Property         | Value                       |
| ---------------- | --------------------------- |
| Dimension        | Security                    |
| Default severity | High                        |
| Languages        | Python, JavaScript / TypeScript |

## What it detects

Flags bare calls to `eval()`, `exec()`, and `__import__()` in Python source code, and `Function(...)` constructor and `eval()` in JavaScript / TypeScript. These builtins execute arbitrary code at runtime and are a severe code-injection vector when fed user-controlled input.

:::note
The analyzer matches **bare name** calls only. It does not track aliases or imports, so code such as `my_eval = eval; my_eval(x)` or `builtins.eval(x)` will not be flagged. Full alias-tracking would require dataflow analysis, which is out of scope for v1.
:::

## Why it matters

Dynamic code execution via `eval()` or `exec()` is one of the most dangerous patterns in any language. An attacker who can influence the input to these functions can execute arbitrary code with the full privileges of the running process. See [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html).

## Configuration

No configuration knobs in v1.

## Examples — flagged

**Python:**

```python
def run_user_code(code_str):
    # DANGER: directly executes user-supplied code
    result = eval(code_str)
    return result

def execute_script(script):
    # DANGER: exec with untrusted input
    exec(script)

def dynamic_import(module_name):
    # DANGER: __import__ with untrusted input
    return __import__(module_name)
```

**JavaScript:**

```javascript
function runUserCode(codeStr) {
    // DANGER: directly executes user-supplied code
    return eval(codeStr);
}

function dynamicCall(funcStr) {
    // DANGER: Function constructor with untrusted input
    return new Function(funcStr)();
}
```

## Examples — not flagged

```python
# Safe: parsing, not execution
import ast
user_data = ast.literal_eval(user_input)

# Safe: restricted namespace (still risky but better than eval)
allowed_names = {"sin": math.sin, "cos": math.cos}
result = eval(expression, {"__builtins__": {}}, allowed_names)

# Safe: no dynamic execution
def process_data(value):
    return value * 2
```

## Fix guidance

- **Use safe alternatives:** Replace `eval()` with `ast.literal_eval()` for data, or with safer serialization formats (JSON, MessagePack).
- **Restrict namespaces:** If dynamic execution is truly unavoidable, use restricted `globals` and `locals` to whitelist available names.
- **Parse, don't evaluate:** If the input is structured (JSON, YAML), parse it with a dedicated library rather than executing code.
- **Avoid code generation:** If you need dynamic behavior, use polymorphism, lookup tables, or a DSL instead of generating code.
- **Validate input heavily:** If you cannot avoid `eval()`, validate and sanitize the input exhaustively (but do not rely on this as sole protection).

## Implementation

- Source (Python): [`crates/zuit-lang-python/src/analyzers/eval_sink.rs`](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-lang-python/src/analyzers/eval_sink.rs)

## References

- [CWE-95: Eval Injection](https://cwe.mitre.org/data/definitions/95.html)
- [OWASP: Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Python: ast.literal_eval()](https://docs.python.org/3/library/ast.html#ast.literal_eval)
