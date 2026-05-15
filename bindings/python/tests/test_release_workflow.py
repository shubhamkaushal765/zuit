"""Tests for the GitHub Actions release workflow (OIDC trusted publishing).

Run from the repository root:
    python3 -m unittest bindings.python.tests.test_release_workflow -v
"""

from __future__ import annotations

import os
import unittest
import yaml


def _load_workflow():
    """Load and parse the release workflow YAML."""
    here = os.path.dirname(__file__)
    workflow_path = os.path.normpath(
        os.path.join(here, "..", "..", "..", ".github", "workflows", "release.yml")
    )
    with open(workflow_path, "r") as f:
        return yaml.safe_load(f)


class TestReleaseWorkflowTriggers(unittest.TestCase):
    """Tests for workflow-level trigger configuration."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load_workflow()
        # yaml parses `on:` as the boolean True key
        cls.on = cls.data.get("on") or cls.data.get(True)

    def test_workflow_triggers_on_version_tags(self):
        """on.push.tags contains 'v*'."""
        tags = self.on["push"]["tags"]
        self.assertIn("v*", tags)


class TestPublishToPyPIJob(unittest.TestCase):
    """Tests for the publish-to-pypi job."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load_workflow()
        cls.jobs = cls.data.get("jobs", {})
        cls.job = cls.jobs.get("publish-to-pypi", {})

    def test_publish_to_pypi_job_exists(self):
        """There is a job named 'publish-to-pypi'."""
        self.assertIn("publish-to-pypi", self.jobs)

    def test_publish_job_runs_only_on_tag_push(self):
        """publish-to-pypi has an 'if' condition restricting to tag pushes."""
        condition = self.job.get("if", "")
        valid_conditions = [
            "startsWith(github.ref, 'refs/tags/v')",
            "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
        ]
        self.assertIn(condition, valid_conditions)

    def test_publish_job_uses_oidc_permissions(self):
        """publish-to-pypi has permissions.id-token: write."""
        permissions = self.job.get("permissions", {})
        self.assertEqual(permissions.get("id-token"), "write")

    def test_publish_job_uses_environment(self):
        """publish-to-pypi has environment set to 'pypi'."""
        env = self.job.get("environment")
        if isinstance(env, dict):
            self.assertEqual(env.get("name"), "pypi")
        else:
            self.assertEqual(env, "pypi")

    def test_publish_job_needs_build_jobs(self):
        """publish-to-pypi needs both build-wheels and build-sdist."""
        needs = self.job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        self.assertIn("build-wheels", needs)
        self.assertIn("build-sdist", needs)

    def test_publish_job_uses_pypa_action(self):
        """At least one step uses pypa/gh-action-pypi-publish@."""
        steps = self.job.get("steps", [])
        uses_values = [s.get("uses", "") for s in steps if s]
        self.assertTrue(
            any(u.startswith("pypa/gh-action-pypi-publish@") for u in uses_values),
            f"No step uses pypa/gh-action-pypi-publish@. Found: {uses_values}",
        )

    def test_publish_job_downloads_all_artifacts(self):
        """At least one step uses actions/download-artifact@ with merge-multiple and dist- pattern."""
        steps = self.job.get("steps", [])
        found = False
        for step in steps:
            if not step:
                continue
            uses = step.get("uses", "")
            if uses.startswith("actions/download-artifact@"):
                with_block = step.get("with", {})
                pattern = str(with_block.get("pattern", ""))
                merge = with_block.get("merge-multiple", False)
                if pattern.startswith("dist-") and merge:
                    found = True
                    break
        self.assertTrue(
            found,
            "No download-artifact step found with merge-multiple:true and pattern starting with 'dist-'",
        )


class TestBuildSdistJob(unittest.TestCase):
    """Tests for the build-sdist job."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load_workflow()
        cls.jobs = cls.data.get("jobs", {})
        cls.job = cls.jobs.get("build-sdist", {})

    def test_build_sdist_job_exists(self):
        """There is a job named 'build-sdist'."""
        self.assertIn("build-sdist", self.jobs)

    def test_build_sdist_job_uses_maturin_sdist(self):
        """build-sdist uses PyO3/maturin-action@ with command: sdist."""
        steps = self.job.get("steps", [])
        found = False
        for step in steps:
            if not step:
                continue
            uses = step.get("uses", "")
            if uses.startswith("PyO3/maturin-action@"):
                with_block = step.get("with", {})
                if with_block.get("command") == "sdist":
                    found = True
                    break
        self.assertTrue(
            found,
            "No maturin-action step with command:sdist found in build-sdist",
        )


class TestBuildWheelsJob(unittest.TestCase):
    """Tests for the build-wheels job."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load_workflow()
        cls.jobs = cls.data.get("jobs", {})
        cls.job = cls.jobs.get("build-wheels", {})

    def test_build_wheels_pins_python_via_setup_python(self):
        """build-wheels uses actions/setup-python@v5 with a pinned python-version.

        GitHub runners track the latest Python release; pyo3 0.22 only
        supports up to Python 3.13. Without an explicit pin the macOS-latest
        runner picks Python 3.14 and pyo3-ffi's build script aborts with
        ``the configured Python interpreter version (3.14) is newer than
        PyO3's maximum supported version``. Pinning here keeps the maturin
        build deterministic across runner image rolls.
        """
        steps = self.job.get("steps", [])
        setup_step = None
        maturin_step = None
        for idx, step in enumerate(steps):
            if not step:
                continue
            uses = step.get("uses", "")
            if uses.startswith("actions/setup-python@") and setup_step is None:
                setup_step = (idx, step)
            if uses.startswith("PyO3/maturin-action@") and maturin_step is None:
                maturin_step = (idx, step)
        self.assertIsNotNone(
            setup_step,
            "build-wheels must include an actions/setup-python@ step",
        )
        self.assertIsNotNone(maturin_step, "build-wheels must include maturin-action")
        # setup-python must run BEFORE maturin so the pinned interpreter is on PATH.
        self.assertLess(
            setup_step[0],
            maturin_step[0],
            "setup-python must precede the maturin-action step",
        )
        version = str(setup_step[1].get("with", {}).get("python-version", ""))
        self.assertTrue(
            version.startswith("3.") and version != "3",
            f"python-version must be pinned to a specific 3.x release; got {version!r}",
        )
        # pyo3 0.22 max supported is 3.13 — reject anything higher.
        major, _, minor = version.partition(".")
        self.assertEqual(major, "3")
        self.assertLessEqual(
            int(minor),
            13,
            f"pyo3 0.22 max supports Python 3.13; pinned {version}",
        )

    def test_build_wheels_sets_manylinux_auto(self):
        """maturin-action step in build-wheels sets manylinux: auto.

        Without this, Linux wheels are tagged ``linux_x86_64`` which PyPI
        rejects on upload. ``auto`` lets maturin pick the lowest compatible
        manylinux tag and is a no-op on macOS/Windows runners.
        """
        steps = self.job.get("steps", [])
        for step in steps:
            if not step:
                continue
            uses = step.get("uses", "")
            if uses.startswith("PyO3/maturin-action@"):
                with_block = step.get("with", {})
                self.assertEqual(
                    with_block.get("manylinux"),
                    "auto",
                    "build-wheels must set manylinux: auto for PyPI compatibility",
                )
                return
        self.fail("No PyO3/maturin-action@ step found in build-wheels")


class TestWheelArtifactNames(unittest.TestCase):
    """Tests for artifact naming conventions."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load_workflow()
        cls.jobs = cls.data.get("jobs", {})

    def test_wheel_artifact_names_use_dist_prefix(self):
        """Every upload-artifact step in build-wheels and build-sdist uses a name starting with 'dist-'."""
        for job_name in ("build-wheels", "build-sdist"):
            job = self.jobs.get(job_name, {})
            steps = job.get("steps", [])
            for step in steps:
                if not step:
                    continue
                uses = step.get("uses", "")
                if uses.startswith("actions/upload-artifact@"):
                    artifact_name = str(step.get("with", {}).get("name", ""))
                    self.assertTrue(
                        artifact_name.startswith("dist-"),
                        f"Job '{job_name}' upload-artifact name '{artifact_name}' does not start with 'dist-'",
                    )


class TestBuildWheelsBundlesCliBinary(unittest.TestCase):
    """Tests asserting the build-wheels job stages the native CLI binary for maturin."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load_workflow()
        cls.jobs = cls.data.get("jobs", {})
        cls.job = cls.jobs.get("build-wheels", {})
        cls.steps = cls.job.get("steps", []) or []

    def _maturin_step_index(self):
        for idx, step in enumerate(self.steps):
            if step and step.get("uses", "").startswith("PyO3/maturin-action@"):
                return idx
        return None

    def test_build_wheels_builds_cli_binary_before_maturin(self):
        """build-wheels must run 'cargo build --release -p zuit' before the maturin step.

        The native CLI binary must be compiled in the same job so it can be
        staged into bindings/python/python/zuit/ before maturin bundles the
        wheel — no cross-job artifact wiring required.
        """
        cargo_build_idx = None
        for idx, step in enumerate(self.steps):
            if not step:
                continue
            run_cmd = step.get("run", "") or ""
            if "cargo build" in run_cmd and "--release" in run_cmd and "-p zuit" in run_cmd:
                cargo_build_idx = idx
                break

        self.assertIsNotNone(
            cargo_build_idx,
            "build-wheels must contain a step with 'cargo build --release -p zuit'",
        )

        maturin_idx = self._maturin_step_index()
        self.assertIsNotNone(maturin_idx, "build-wheels must contain a PyO3/maturin-action@ step")

        self.assertLess(
            cargo_build_idx,
            maturin_idx,
            "The 'cargo build --release -p zuit' step must appear before the maturin-action step",
        )

    def test_build_wheels_stages_cli_binary_for_maturin(self):
        """build-wheels must copy the compiled binary into bindings/python/python/zuit/.

        The staging step places the binary next to _cli.py so maturin
        picks it up as part of the python-source tree and bundles it in
        the wheel.
        """
        staging_idx = None
        for idx, step in enumerate(self.steps):
            if not step:
                continue
            run_cmd = step.get("run", "") or ""
            if "bindings/python/python/zuit" in run_cmd:
                staging_idx = idx
                break

        self.assertIsNotNone(
            staging_idx,
            "build-wheels must contain a step whose 'run' block references "
            "'bindings/python/python/zuit' (the staging destination for the CLI binary)",
        )

        maturin_idx = self._maturin_step_index()
        self.assertIsNotNone(maturin_idx, "build-wheels must contain a PyO3/maturin-action@ step")

        self.assertLess(
            staging_idx,
            maturin_idx,
            "The binary-staging step must appear before the maturin-action step",
        )

    def test_pyproject_toml_includes_cli_binary(self):
        """bindings/python/pyproject.toml must declare an [tool.maturin] include for the CLI binary.

        Maturin does not auto-bundle arbitrary files from python-source — only
        .py files are gathered automatically. An explicit 'include' entry is
        required so the precompiled zuit / zuit.exe binary is added to the wheel.
        """
        here = os.path.dirname(__file__)
        pyproject_path = os.path.normpath(
            os.path.join(here, "..", "pyproject.toml")
        )
        with open(pyproject_path, "r") as f:
            content = f.read()

        # Accept either TOML array-of-strings or array-of-tables form.
        # Both must at minimum reference the Unix binary name 'zuit/zuit'.
        self.assertIn(
            "zuit/zuit",
            content,
            "pyproject.toml [tool.maturin] include must reference 'zuit/zuit' "
            "so the native CLI binary is bundled in the wheel",
        )


if __name__ == "__main__":
    unittest.main()
