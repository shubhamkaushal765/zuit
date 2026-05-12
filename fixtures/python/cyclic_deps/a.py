"""Module a — imports b, creating a three-way cycle: a → b → c → a."""

import b


def func_a():
    """Function in module a."""
    return "a"
