"""Positive fixture for TEST005-assert-count.

Contains a test function with more than 10 assertions (default threshold).
"""


def test_with_too_many_assertions() -> None:
    """Test that makes way too many assertions — should be flagged."""
    assert 1 == 1
    assert 2 == 2
    assert 3 == 3
    assert 4 == 4
    assert 5 == 5
    assert 6 == 6
    assert 7 == 7
    assert 8 == 8
    assert 9 == 9
    assert 10 == 10
    assert 11 == 11
