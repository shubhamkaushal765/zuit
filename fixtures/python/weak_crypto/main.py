"""Weak-crypto fixture for Python — positive case for SEC004-weak-crypto.

Demonstrates use of deprecated hash algorithms MD5 and SHA-1.
"""

import hashlib
from hashlib import md5


def hash_data_md5(data: bytes) -> str:
    """Hash data using MD5 (insecure — string literal 'md5' triggers SEC004)."""
    digest = hashlib.new("md5", data).hexdigest()
    return digest


def hash_data_sha1(data: bytes) -> str:
    """Hash data using SHA-1 (insecure — string literal 'sha1' triggers SEC004)."""
    return hashlib.new("sha1", data).hexdigest()


def direct_md5(data: bytes) -> bytes:
    """Direct hashlib.md5 usage — import from hashlib.md5 triggers SEC004."""
    return md5(data).digest()
