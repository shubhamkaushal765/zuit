"""Command-line entry point for the zuit pip package.

Locates the native zuit binary and exec's it, forwarding all arguments.
The lookup order is:

1. ZUIT_BIN environment variable (if set and executable).
2. A bundled zuit binary next to the Python package directory
   (forward-compatible: not present today, will be added when release wheels
   ship precompiled binaries).
3. zuit (or zuit.exe on Windows) on PATH via shutil.which, skipping
   any path that lives inside the active Python environment's bin/Scripts
   directory to prevent infinite recursion.
4. Exits with code 1 and a human-readable message if none of the above resolves.

On POSIX the resolved binary is exec'd via os.execv (replacing the current
process). On Windows subprocess.run is used and its return code is forwarded.
"""

from __future__ import annotations

import os
import shutil
import sys


def _is_inside_python_env(path: str) -> bool:
    """Return True when *path* lives inside the active Python prefix or venv.

    This guards against the launcher calling itself when the pip-installed
    ``zuit`` script on PATH resolves to us again.
    """
    # Normalise to absolute real paths for reliable prefix comparison.
    resolved = os.path.realpath(os.path.abspath(path))

    candidates: list[str] = []
    for attr in ("prefix", "exec_prefix", "base_prefix", "real_prefix"):
        val = getattr(sys, attr, None)
        if val:
            candidates.append(os.path.realpath(val))

    # Also check the virtual-env root via VIRTUAL_ENV if set.
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        candidates.append(os.path.realpath(venv))

    return any(resolved.startswith(c + os.sep) or resolved == c for c in candidates)


def _find_binary() -> str | None:
    """Return the path to the zuit native binary, or None."""
    binary_name = "zuit.exe" if sys.platform == "win32" else "zuit"

    # 1. ZUIT_BIN override.
    env_bin = os.environ.get("ZUIT_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin

    # 2. Bundled binary: one directory above the package directory.
    #    Layout: <site-packages>/zuit/_cli.py  →  sibling dir to package root.
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(pkg_dir, binary_name)
    if os.path.isfile(bundled) and os.access(bundled, os.X_OK):
        return bundled

    # 3. PATH lookup, skipping paths inside the active Python environment.
    on_path = shutil.which(binary_name)
    if on_path and not _is_inside_python_env(on_path):
        return on_path

    return None


def main() -> None:
    """Locate and exec the native zuit binary."""
    binary = _find_binary()

    if binary is None:
        sys.stderr.write(
            "zuit binary not found.\n"
            "Install the native binary via one of:\n"
            "  cargo install zuit\n"
            "  pip install zuit  (once binary wheels are published)\n"
        )
        sys.exit(1)

    args = [binary] + sys.argv[1:]

    if sys.platform == "win32":
        import subprocess

        result = subprocess.run(args)  # noqa: S603
        sys.exit(result.returncode)
    else:
        os.execv(binary, args)
