"""Negative fixture for TEST004-flaky-time.

Contains test functions with no time/random tokens.
"""


def test_pure_logic() -> None:
    """Test with no flaky calls — should not be flagged."""
    result = 1 + 1
    assert result == 2


def test_another_pure() -> None:
    """Another clean test."""
    items = [1, 2, 3]
    assert len(items) == 3
