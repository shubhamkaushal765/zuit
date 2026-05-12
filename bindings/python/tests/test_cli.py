"""Unit tests for zuit._cli launcher.

Run from the repository root:
    python3 -m pytest bindings/python/tests/test_cli.py
or:
    python3 -m unittest bindings.python.tests.test_cli

The tests import _cli directly (not the top-level zuit package) so that
the native extension module is never loaded.
"""

from __future__ import annotations

import importlib
import io
import os
import sys
import unittest
from unittest.mock import MagicMock, patch


def _import_cli():
    """Import zuit._cli with python/zuit on sys.path."""
    pkg_root = os.path.join(
        os.path.dirname(__file__), "..", "python"
    )
    pkg_root = os.path.normpath(pkg_root)
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)
    # Ensure fresh import each time.
    for mod in list(sys.modules):
        if mod == "zuit._cli" or mod == "zuit" and "_cli" not in mod:
            pass  # leave package entry, reload _cli below
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "zuit._cli",
        os.path.join(pkg_root, "zuit", "_cli.py"),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class TestCliEnvOverride(unittest.TestCase):
    """test_uses_env_override_when_set"""

    def test_uses_env_override_when_set(self):
        cli = _import_cli()

        fake_bin = "/usr/local/bin/fake-zuit"
        captured: dict = {}

        def fake_execv(path, args):
            captured["path"] = path
            captured["args"] = args
            raise SystemExit(0)

        with patch.dict(os.environ, {"ZUIT_BIN": fake_bin}):
            with patch("os.path.isfile", return_value=True):
                with patch("os.access", return_value=True):
                    with patch.object(cli.os, "execv", side_effect=fake_execv):
                        with patch.object(cli.sys, "argv", ["zuit", "analyze", "."]):
                            try:
                                cli.main()
                            except SystemExit:
                                pass

        self.assertEqual(captured.get("path"), fake_bin)


class TestCliPathFallback(unittest.TestCase):
    """test_falls_back_to_path_when_no_env"""

    def test_falls_back_to_path_when_no_env(self):
        cli = _import_cli()

        fake_bin = "/usr/bin/zuit"
        captured: dict = {}

        def fake_execv(path, args):
            captured["path"] = path
            captured["args"] = args
            raise SystemExit(0)

        env = {k: v for k, v in os.environ.items() if k != "ZUIT_BIN"}

        with patch.dict(os.environ, env, clear=True):
            with patch.object(cli.shutil, "which", return_value=fake_bin):
                # Ensure bundled binary is not found.
                with patch("os.path.isfile", return_value=False):
                    # Not inside python env — safe to use.
                    with patch.object(cli, "_is_inside_python_env", return_value=False):
                        with patch.object(cli.os, "execv", side_effect=fake_execv):
                            with patch.object(cli.sys, "argv", ["zuit", "--version"]):
                                try:
                                    cli.main()
                                except SystemExit:
                                    pass

        self.assertEqual(captured.get("path"), fake_bin)


class TestCliNotFound(unittest.TestCase):
    """test_exits_with_clear_message_when_not_found"""

    def test_exits_with_clear_message_when_not_found(self):
        cli = _import_cli()

        env = {k: v for k, v in os.environ.items() if k != "ZUIT_BIN"}
        stderr_capture = io.StringIO()

        exit_code = None

        def fake_exit(code):
            nonlocal exit_code
            exit_code = code
            raise SystemExit(code)

        with patch.dict(os.environ, env, clear=True):
            with patch.object(cli.shutil, "which", return_value=None):
                with patch("os.path.isfile", return_value=False):
                    with patch.object(cli.sys, "stderr", stderr_capture):
                        with patch.object(cli.sys, "exit", side_effect=fake_exit):
                            try:
                                cli.main()
                            except SystemExit:
                                pass

        output = stderr_capture.getvalue()
        self.assertEqual(exit_code, 1)
        self.assertIn("zuit binary not found", output)


if __name__ == "__main__":
    unittest.main()
