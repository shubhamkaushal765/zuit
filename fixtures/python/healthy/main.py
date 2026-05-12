"""A small, well-structured Python module with no security issues."""

import os
import sys
from typing import List, Optional


def greet(name: str) -> str:
    """Return a friendly greeting for the given name."""
    return f"Hello, {name}!"


def compute_sum(numbers: List[int]) -> int:
    """Return the sum of a list of integers."""
    total = 0
    for n in numbers:
        total += n
    return total


async def fetch_data(url: str) -> Optional[str]:
    """Asynchronously fetch data from a URL (stub)."""
    if not url:
        return None
    return url


def _internal_helper(value: int) -> bool:
    """Private helper — not part of the public API."""
    return value > 0


class DataProcessor:
    """Process data items with basic validation."""

    def __init__(self, threshold: int) -> None:
        """Initialise with a numeric threshold."""
        self.threshold = threshold

    def process(self, items: List[int]) -> List[int]:
        """Return items that exceed the threshold."""
        return [x for x in items if x > self.threshold]
