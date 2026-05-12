"""Module c — imports a, creating a three-way cycle: a → b → c → a."""

import a


def func_c():
    """Function in module c."""
    return "c"
