"""Negative fixture for TEST005-assert-count.

Contains a test function with a small number of assertions (under threshold).
"""


def test_with_few_assertions() -> None:
    """Test that makes just a few assertions — should not be flagged."""
    assert 1 == 1
    assert 2 == 2
    assert 3 == 3
