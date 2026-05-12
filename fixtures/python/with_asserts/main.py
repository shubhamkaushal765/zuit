"""Negative fixture for TEST002-no-asserts.

Contains a test function with an assertion — should NOT be flagged.
"""


def test_thing() -> None:
    """Test function with an assertion — should not be flagged."""
    x = 1
    assert x == 1
