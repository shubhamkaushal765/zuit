"""Positive fixture for CPLX003-duplicate-code: file A."""


def process_data(items):
    """Process a list of data items."""
    result = []
    for item in items:
        if item > 0:
            result.append(item * 2)
        else:
            result.append(0)
    return result


def validate_input(value):
    """Validate that value is a positive integer."""
    if not isinstance(value, int):
        return False
    if value <= 0:
        return False
    return True
