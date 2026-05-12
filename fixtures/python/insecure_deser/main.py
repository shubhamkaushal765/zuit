"""Positive fixture for SEC005-insecure-deser: uses pickle and yaml.load unsafely."""

import pickle
import yaml


def load_user_data(data: bytes):
    """Load user-supplied data using pickle (insecure)."""
    return pickle.loads(data)


def load_config(stream):
    """Load YAML config without specifying a safe loader."""
    return yaml.load(stream)
