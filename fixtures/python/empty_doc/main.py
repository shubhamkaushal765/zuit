"""Positive fixture for DOC003-empty-doc.

Contains functions with empty or placeholder doc comments.
"""


def empty_doc_fn() -> int:
    """"""
    return 42


def punctuation_only_doc() -> bool:
    """."""
    return True


def name_as_doc() -> str:
    """name_as_doc"""
    return "hello"
