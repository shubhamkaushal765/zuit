"""Negative fixture for TEST006-shared-mutable-state.

Module-level state exists, but the test class provides setUp/tearDown so
the analyzer suppresses all findings for this file.
"""

COUNTER = 0


class TestCounter:
    """Test class with proper setUp and tearDown teardown lifecycle."""

    def setUp(self) -> None:
        """Reset COUNTER before each test."""
        global COUNTER
        COUNTER = 0

    def tearDown(self) -> None:
        """Reset COUNTER after each test."""
        global COUNTER
        COUNTER = 0

    def test_increment(self) -> None:
        """Mutates COUNTER — but setUp/tearDown provides cleanup, suppressed."""
        global COUNTER
        COUNTER += 1
        assert COUNTER == 1
