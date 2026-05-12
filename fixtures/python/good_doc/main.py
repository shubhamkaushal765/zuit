"""Negative fixture for DOC003-empty-doc.

Contains functions with proper doc comments.
"""


def add(a: int, b: int) -> int:
    """Adds two integers together and returns their sum."""
    return a + b


def is_even(n: int) -> bool:
    """Returns whether the given number is even."""
    return n % 2 == 0
