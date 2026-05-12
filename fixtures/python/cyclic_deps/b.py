"""Module b — imports c, creating a three-way cycle: a → b → c → a."""

import c


def func_b():
    """Function in module b."""
    return "b"
