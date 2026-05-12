"""Positive fixture for TEST003-skipped.

Contains two different skip markers — both should produce findings.
"""

import unittest
import pytest


@pytest.mark.skip
def test_with_pytest_skip() -> None:
    """Skipped via pytest.mark.skip."""
    assert True


@unittest.skip
def test_with_unittest_skip() -> None:
    """Skipped via unittest.skip."""
    assert True
