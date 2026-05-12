"""Negative fixture for DOC004-stale-doc.

Contains a function whose doc comment references parameter names that match
the actual parameter names in the signature.
"""


def add(x, y):
    """Add two numbers together.

    :param x: the first operand
    :param y: the second operand
    :return: the sum
    """
    return x + y
