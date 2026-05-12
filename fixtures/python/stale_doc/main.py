"""Positive fixture for DOC004-stale-doc.

Contains a function whose doc comment references parameter names that do not
match the actual parameter names in the signature.
"""


def add(x, y):
    """Add two numbers together.

    :param a: the first operand
    :param b: the second operand
    :return: the sum
    """
    return x + y
