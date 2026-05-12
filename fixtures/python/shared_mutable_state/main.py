"""Positive fixture for TEST006-shared-mutable-state.

Module-level mutable state (COUNTER) is mutated inside a test function
without any setUp/tearDown or pytest fixture providing cleanup.
"""

COUNTER = 0
ITEMS = []


def test_increment_counter() -> None:
    """Mutates module-level COUNTER — flagged."""
    global COUNTER
    COUNTER += 1
    assert COUNTER > 0


def test_append_item() -> None:
    """Mutates module-level ITEMS — flagged."""
    global ITEMS
    ITEMS.append(42)
    assert len(ITEMS) > 0


def helper() -> int:
    """Non-test helper; should not be flagged."""
    return COUNTER
