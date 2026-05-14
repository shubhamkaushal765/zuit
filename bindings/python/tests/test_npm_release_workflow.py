"""Tests for the npm publish job in the GitHub Actions release workflow.

Run from the repository root:
    python3 -m unittest bindings.python.tests.test_npm_release_workflow -v
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


class TestPublishToNpmJob(unittest.TestCase):
    """Tests for the publish-to-npm job."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load_workflow()
        cls.jobs = cls.data.get("jobs", {})
        cls.job = cls.jobs.get("publish-to-npm", {})

    def test_publish_to_npm_job_exists(self):
        """There is a job named 'publish-to-npm'."""
        self.assertIn("publish-to-npm", self.jobs)

    def test_publish_job_runs_only_on_tag_push(self):
        """publish-to-npm has an 'if' condition restricting to tag pushes."""
        condition = self.job.get("if", "")
        valid_conditions = [
            "startsWith(github.ref, 'refs/tags/v')",
            "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
        ]
        self.assertIn(condition, valid_conditions)

    def test_publish_job_uses_oidc_permissions(self):
        """publish-to-npm has permissions.id-token: write."""
        permissions = self.job.get("permissions", {})
        self.assertEqual(permissions.get("id-token"), "write")

    def test_publish_job_uses_environment_npm(self):
        """publish-to-npm has environment set to 'npm'."""
        env = self.job.get("environment")
        if isinstance(env, dict):
            self.assertEqual(env.get("name"), "npm")
        else:
            self.assertEqual(env, "npm")

    def test_publish_job_needs_build_npm(self):
        """publish-to-npm needs build-npm."""
        needs = self.job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        self.assertIn("build-npm", needs)

    def test_publish_job_runs_npm_publish_with_provenance(self):
        """At least one step runs 'npm publish' with '--provenance' and '--access public'."""
        steps = self.job.get("steps", [])
        found = False
        for step in steps:
            if not step:
                continue
            run_cmd = step.get("run", "")
            if "npm publish" in run_cmd and "--provenance" in run_cmd and "--access public" in run_cmd:
                found = True
                break
        self.assertTrue(
            found,
            "No step found running 'npm publish --provenance --access public'",
        )

    def test_publish_job_downloads_npm_dist_artifact(self):
        """At least one step uses actions/download-artifact@ with name: npm-dist."""
        steps = self.job.get("steps", [])
        found = False
        for step in steps:
            if not step:
                continue
            uses = step.get("uses", "")
            if uses.startswith("actions/download-artifact@"):
                with_block = step.get("with", {})
                if with_block.get("name") == "npm-dist":
                    found = True
                    break
        self.assertTrue(
            found,
            "No download-artifact step found with name: npm-dist",
        )


class TestBuildNpmJob(unittest.TestCase):
    """Tests for the build-npm job (launcher-only, single runner)."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load_workflow()
        cls.jobs = cls.data.get("jobs", {})
        cls.job = cls.jobs.get("build-npm", {})

    def test_build_npm_job_exists(self):
        """There is a job named 'build-npm'."""
        self.assertIn("build-npm", self.jobs)

    def test_build_npm_uploads_npm_dist_artifact(self):
        """build-npm uploads an artifact named 'npm-dist'."""
        steps = self.job.get("steps", [])
        found = False
        for step in steps:
            if not step:
                continue
            uses = step.get("uses", "")
            if uses.startswith("actions/upload-artifact@"):
                with_block = step.get("with", {})
                if with_block.get("name") == "npm-dist":
                    found = True
                    break
        self.assertTrue(
            found,
            "No upload-artifact step found with name: npm-dist in build-npm",
        )


if __name__ == "__main__":
    unittest.main()
