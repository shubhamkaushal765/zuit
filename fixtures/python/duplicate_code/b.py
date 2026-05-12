"""Positive fixture for CPLX003-duplicate-code: file B.

Contains a block of code duplicated from a.py.
"""


def transform_items(items):
    """Transform a list of items (duplicate of process_data)."""
    result = []
    for item in items:
        if item > 0:
            result.append(item * 2)
        else:
            result.append(0)
    return result


def check_value(value):
    """Check that a value meets criteria."""
    if not isinstance(value, int):
        return False
    if value <= 0:
        return False
    return True
