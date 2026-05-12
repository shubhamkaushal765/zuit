"""Negative fixture for MAINT007-return-complexity.

Contains functions with few return statements (within threshold).
"""


def simple_function(x: int) -> str:
    """Function with few returns — should not be flagged."""
    if x < 0:
        return "negative"
    return "non-negative"


def another_simple(value: bool) -> int:
    """Another simple function."""
    return 1 if value else 0
