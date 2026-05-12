"""Positive fixture for TEST002-no-asserts.

Contains a test function but no assertion of any kind.
"""


def test_thing() -> None:
    """Test function with no assertion — will be flagged."""
    x = 1
    _ = x + 1
