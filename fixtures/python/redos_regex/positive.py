"""Positive fixture for SEC014-redos-regex — patterns that cause catastrophic backtracking."""
import re

# Nested repetition: (a+)+ is the canonical ReDoS pattern.
pattern1 = re.compile(r"(a+)+")

# Nested repetition: (.*)*
pattern2 = re.compile(r"(.*)*")

# Nested repetition: (\w+)+ — common in user-input validators
pattern3 = re.compile(r"(\w+)+end")
