"""Module with only legitimate, prose-style comments that should NOT trigger MAINT014."""

# This module provides utility functions for number manipulation.
# See the README for more details on usage and configuration.


def calculate(x: int) -> int:
    """Return the square of x."""
    # NOTE: This is a simple implementation.
    # TODO: add caching here
    return x * x


def greet(name: str) -> str:
    """Return a greeting string."""
    # Greets the user by name.
    return f"Hello, {name}!"
