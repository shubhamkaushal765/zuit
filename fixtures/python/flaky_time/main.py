"""Positive fixture for TEST004-flaky-time.

Contains test functions that reference time-dependent or random tokens,
which makes them potentially flaky.
"""

import time
import random


def test_with_sleep() -> None:
    """Test that uses time.sleep — flagged as flaky."""
    time.sleep(0.1)
    result = do_something()
    assert result is not None


def test_with_random() -> None:
    """Test that uses random.random — flagged as flaky."""
    val = random.random()
    assert 0.0 <= val <= 1.0


def test_with_time_time() -> None:
    """Test that uses time.time — flagged as flaky."""
    before = time.time()
    do_something()
    after = time.time()
    assert after >= before


def do_something():
    """Non-test helper."""
    return 42
