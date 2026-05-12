"""Positive fixture for SEC003-shell-injection.

Both signals are present:
  1. Import of ``subprocess`` (a shell-exec module).
  2. A string literal that matches the shell-prefix command pattern.
"""

import subprocess


def run_user_command(user_input: str) -> int:
    """Run an arbitrary shell command supplied by the user — injection risk."""
    # The string literal below matches the shell-prefix pattern: 'sh -c'.
    cmd = "sh -c " + user_input
    result = subprocess.call(cmd, shell=True)
    return result
