"""Fan-out fixture for Python — positive case for CPLX001-fan-out.

This file imports more than 20 distinct modules to trigger the fan-out rule.
"""

import os
import sys
import re
import json
import csv
import math
import time
import datetime
import pathlib
import shutil
import tempfile
import hashlib
import logging
import typing
import collections
import itertools
import functools
import io
import struct
import threading
import subprocess


def placeholder() -> str:
    """Placeholder function — the many imports above trigger CPLX001."""
    return "fan-out-example"
