"""Unhealthy module — contains security issues and high complexity.

Phase 4 additions:
- Hardcoded AWS access key (SEC001-hardcoded-secret).
"""

import os


def run_user_code(code_str):
    # DANGER: directly executes user-supplied code — SEC002-eval-sink
    result = eval(code_str)
    return result


def execute_script(script):
    # DANGER: exec with untrusted input — SEC002-eval-sink
    exec(script)


def complex_logic(a, b, c, d, e):
    # Cyclomatic complexity >= 8: eight independent paths through this function.
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        return "all positive"
                    elif e < -10:
                        return "e very negative"
                    else:
                        return "e small negative"
                elif d < 0:
                    return "d negative c positive"
            elif c < 0:
                return "c negative b positive"
        elif b < 0:
            return "b negative a positive"
    elif a < 0:
        return "a negative"
    return "default"


def undocumented_public_function(x, y):
    return x + y


# Hardcoded AWS access key — triggers SEC001-hardcoded-secret (Phase 4 fixture).
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
