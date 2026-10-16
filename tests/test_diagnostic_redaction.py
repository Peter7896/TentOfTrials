#!/usr/bin/env python3
"""
Regression tests for diagnostic redaction, artifact pairing, and
repository-relative path reporting in the build system.

These tests validate that:
- Diagnostic metadata uses repository-relative `/` paths
- PII (home dir, usernames, machine names) is not leaked
- .logd references in JSON match actual diagnostic artifacts
- Errors are surfaced clearly when JSON or .logd is missing/mismatched
"""

import json
import os
import platform
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import build


class TestDiagnosticPathReporting(unittest.TestCase):
    """Verify diagnostic metadata uses repository-relative paths with forward slashes."""

    def test_logd_path_is_repo_relative(self):
        """The diagnostic_logd field must be a repository-relative path."""
        results = [("frailbox", True, 0.5, "", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        logd = report["diagnostic_logd"]
        self.assertIsNotNone(logd)
        self.assertIsInstance(logd, str)
        self.assertNotIn("\\", logd)
        self.assertTrue(logd.startswith("diagnostic/"))
        self.assertFalse(Path(logd).is_absolute())

    def test_no_absolute_paths_in_logd_field(self):
        """The diagnostic_logd field must never contain an absolute path."""
        results = [("frailbox", True, 0.5, "", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        logd = report["diagnostic_logd"]
        if platform.system() == "Windows":
            self.assertNotIn(":\\", logd)
        else:
            self.assertFalse(logd.startswith("/"))


class TestDiagnosticPIIRedaction(unittest.TestCase):
    """Verify diagnostic metadata does not leak PII."""

    def test_no_home_directory_in_report(self):
        """Home directory paths must not appear in diagnostic metadata."""
        home = str(Path.home())
        results = [("frailbox", True, 0.5, "output text", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        report_json = json.dumps(report)
        if home and home != "/":
            self.assertNotIn(home, report_json,
                             f"Home directory '{home}' leaked into diagnostic JSON")

    def test_no_username_in_report(self):
        """Username must not appear in diagnostic metadata."""
        import getpass
        username = getpass.getuser()
        results = [("frailbox", True, 0.5, "output text", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        report_json = json.dumps(report)
        if username and len(username) > 1:
            self.assertNotIn(username, report_json,
                             f"Username '{username}' leaked into diagnostic JSON")

    def test_no_machine_name_in_report(self):
        """Machine hostname must not appear in diagnostic metadata."""
        hostname = platform.node()
        results = [("frailbox", True, 0.5, "output text", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        report_json = json.dumps(report)
        if hostname and len(hostname) > 1:
            self.assertNotIn(hostname, report_json,
                             f"Hostname '{hostname}' leaked into diagnostic JSON")

    def test_no_temp_directory_in_report(self):
        """Temporary directory paths must not appear in diagnostic metadata."""
        tmpdir = tempfile.gettempdir()
        results = [("frailbox", True, 0.5, "output text", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        report_json = json.dumps(report)
        if tmpdir and tmpdir != "/tmp":
            self.assertNotIn(tmpdir, report_json,
                             "Temp directory leaked into diagnostic JSON")


class TestDiagnosticArtifactPairing(unittest.TestCase):
    """Verify JSON metadata correctly references .logd artifacts."""

    def test_json_references_logd(self):
        """When logd_relpaths are provided, diagnostic_logd must be set."""
        results = [("frailbox", True, 0.5, "", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        self.assertIsNotNone(report["diagnostic_logd"])
        self.assertIsNone(report["diagnostic_logd_error"])

    def test_missing_logd_sets_error(self):
        """When no logd_relpaths, diagnostic_logd_error should be set."""
        results = [("frailbox", True, 0.5, "", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_error="encryptly not found",
        )
        self.assertIsNone(report["diagnostic_logd"])
        self.assertEqual(report["diagnostic_logd_error"], "encryptly not found")

    def test_password_paired_with_logd(self):
        """A password must be present when logd_relpaths are provided."""
        results = [("frailbox", True, 0.5, "", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="hunter2",
        )
        self.assertEqual(report["password"], "hunter2")
        self.assertIsNotNone(report["decrypt_command"])
        self.assertIn("hunter2", report["decrypt_command"])

    def test_report_has_all_required_fields(self):
        """The report must contain all expected top-level keys."""
        results = [("frailbox", True, 0.5, "", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        required_keys = {
            "generated_at", "commit", "diagnostic_logd",
            "diagnostic_logd_error", "chunked", "chunk_size_bytes",
            "password", "decrypt_command", "total_modules",
            "passed", "failed", "modules", "pr_note",
        }
        for key in required_keys:
            self.assertIn(key, report, f"Missing required key: {key}")


class TestErrorHandling(unittest.TestCase):
    """Verify clear failure modes for diagnostic edge cases."""

    def test_empty_results_produces_valid_report(self):
        """An empty results list should still produce a valid report."""
        report = build.build_diagnostic_report(
            [], commit_id="abc12345",
        )
        self.assertEqual(report["total_modules"], 0)
        self.assertEqual(report["passed"], 0)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["modules"], [])

    def test_message_blocker_present_on_error(self):
        """message_blocker should be set when logd_error is present."""
        results = [("frailbox", False, 0.0, "build failed", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_error="encryptly failed",
            message_blocker=build.ENCRYPTLY_BLOCKER_MESSAGE,
        )
        self.assertEqual(report["message_blocker"], build.ENCRYPTLY_BLOCKER_MESSAGE)

    def test_json_serialization_is_deterministic(self):
        """The report must serialize to valid JSON deterministically."""
        results = [
            ("backend", True, 1.23, "ok", "/path/to/binary"),
            ("frontend", False, 0.45, "error output", None),
        ]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="hunter2",
        )
        json_str = json.dumps(report, indent=2)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["total_modules"], 2)
        self.assertEqual(parsed["passed"], 1)
        self.assertEqual(parsed["failed"], 1)


class TestCrossPlatformConsistency(unittest.TestCase):
    """Verify behavior is deterministic regardless of host OS."""

    def test_forward_slash_paths_on_all_platforms(self):
        """All paths in the report must use forward slashes on any OS."""
        results = [("frailbox", True, 0.5, "", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        logd = report["diagnostic_logd"]
        self.assertIsInstance(logd, str)
        self.assertNotIn("\\", logd)

    def test_relative_paths_not_absolute(self):
        """Repository-relative paths must not be absolute on any platform."""
        results = [("frailbox", True, 0.5, "", None)]
        report = build.build_diagnostic_report(
            results, commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="test",
        )
        logd = report["diagnostic_logd"]
        self.assertIsInstance(logd, str)
        self.assertFalse(logd.startswith("/"))
        self.assertNotIn(":/", logd[:3])


if __name__ == "__main__":
    unittest.main()
