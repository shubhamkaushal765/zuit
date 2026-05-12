"""Cognitive-complexity fixture for Python.

Contains a function with cognitive complexity > 15 to exercise the
MAINT002-cognitive analyzer positive case.
"""


def high_cognitive(a, b, c, d, e):
    """A deeply-nested function designed to exceed cognitive complexity 15.

    Cognitive complexity (Sonar variant):
    - if a < 0 at depth 0: +1
      - if b < 0 at depth 1: +2
        - if c < 0 at depth 2: +3
          - if d < 0 at depth 3: +4
            - if e < 0 at depth 4: +5
            - elif e > 10 at depth 4: +5
          - elif d > 10 at depth 3: +4
        - elif c > 10 at depth 2: +3
      - elif b > 10 at depth 1: +2
    - elif a > 10 at depth 0: +1
    Total: 1+2+3+4+5+5+4+3+2+1 = 30
    """
    if a < 0:
        if b < 0:
            if c < 0:
                if d < 0:
                    if e < 0:
                        return "all-negative"
                    elif e > 10:
                        return "e-large"
                    else:
                        return "e-mid"
                elif d > 10:
                    return "d-large"
                else:
                    return "d-mid"
            elif c > 10:
                return "c-large"
            else:
                return "c-mid"
        elif b > 10:
            return "b-large"
        else:
            return "b-mid"
    elif a > 10:
        return "a-large"
    else:
        return "a-mid"
