"""Negative fixture for SEC014-redos-regex — safe regex patterns."""
import re

# Simple character class repetition — no nested quantifiers.
pattern1 = re.compile(r"[a-z]+")

# Bounded repetition — not catastrophic.
pattern2 = re.compile(r"\d{1,5}")

# Anchored literal — trivially safe.
pattern3 = re.compile(r"^abc$")

# Alternation with distinct branches — no duplicates.
pattern4 = re.compile(r"(foo|bar)+")

# Simple star repetition over a literal.
pattern5 = re.compile(r"abc*")
