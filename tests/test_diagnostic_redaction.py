#!/usr/bin/env python3
"""Regression tests for diagnostic artifact redaction (issue #1, $40 bounty).

Validates that diagnostic metadata does not leak local paths, usernames,
or machine names, and that artifact paths use repository-relative format.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Make build.py importable from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import build  # noqa: E402


class TestDiagnosticRedaction(unittest.TestCase):
    """Validates that diagnostic metadata contains no path/user leakage."""

    def setUp(self):
        self.home = str(Path.home())
        self.username = os.environ.get("USER", os.environ.get("USERNAME", ""))
        self.repo_root = str(Path(__file__).resolve().parents[1])
        self.temp = tempfile.gettempdir()

    # ── path normalisation ───────────────────────────────────────────

    def test_diagnostic_paths_under_diagnostic_dir(self):
        """diagnostic_paths_for_commit returns paths under diagnostic/."""
        logd_path, metadata_path, _ = build.diagnostic_paths_for_commit()

        logd_str = str(logd_path).replace("\\", "/")
        meta_str = str(metadata_path).replace("\\", "/")
        self.assertIn("diagnostic/", logd_str,
                      f"logd path should be under diagnostic/, got {logd_path}")
        self.assertIn("diagnostic/", meta_str,
                      f"metadata path should be under diagnostic/, got {metadata_path}")

    # ── no path leakage ──────────────────────────────────────────────

    def test_report_does_not_leak_home_directory(self):
        """Metadata JSON must not contain the user's home directory path."""
        report = build.build_diagnostic_report([],"test-commit")
        json_str = json.dumps(report)
        self.assertNotIn(self.home, json_str,
                         "diagnostic report leaked HOME path")
        # Also check Path.home() expansion for Windows
        home_lower = self.home.lower().replace("\\", "/")
        json_lower = json_str.lower().replace("\\", "/")
        self.assertNotIn(home_lower, json_lower)

    def test_report_does_not_leak_temp_directory(self):
        """Metadata must not contain temp directory paths."""
        report = build.build_diagnostic_report([],"test-commit")
        json_str = json.dumps(report)
        # Strip drive letter for Windows comparison
        temp_clean = self.temp.replace("\\", "/").split(":")[-1].lstrip("/")
        json_clean = json_str.replace("\\", "/")
        # Only assert if temp path is distinct enough
        if len(temp_clean) > 4:
            self.assertNotIn(temp_clean, json_clean,
                             f"diagnostic report leaked TEMP: {temp_clean}")

    def test_report_does_not_leak_username(self):
        """Metadata must not contain the current username."""
        if not self.username or len(self.username) < 2:
            self.skipTest("no username to check")
        report = build.build_diagnostic_report([],"test-commit")
        json_str = json.dumps(report).lower()
        self.assertNotIn(self.username.lower(), json_str,
                         f"diagnostic report leaked username: {self.username}")

    def test_report_does_not_leak_repo_absolute_path(self):
        """Metadata must not contain the absolute repository root path."""
        report = build.build_diagnostic_report([],"test-commit")
        json_str = json.dumps(report)
        self.assertNotIn(self.repo_root, json_str,
                         "diagnostic report leaked repo absolute path")

    # ── artifact pairing ─────────────────────────────────────────────

    def test_report_includes_logd_reference(self):
        """diagnostic report references the encrypted logd artifact."""
        report = build.build_diagnostic_report([],"test-commit")
        self.assertIn("diagnostic_logd", report,
                      "report must include diagnostic_logd key")

    def test_empty_results_yields_report(self):
        """Report with empty results still produces valid structure."""
        report = build.build_diagnostic_report([], "test-commit")
        self.assertEqual(report["commit"], "test-commit")
        self.assertEqual(report["passed"], 0)
        self.assertEqual(report["total_modules"], 0)

    # ── cross-platform determinism ───────────────────────────────────

    def test_paths_are_strings(self):
        """All path values in report are plain strings, not Path objects."""
        report = build.build_diagnostic_report([],"test-commit")
        for key, value in report.items():
            if key.endswith("_path") or key.endswith("_logd"):
                self.assertIsInstance(value, (str, list, type(None)),
                                      f"{key} should be str/list/None, got {type(value)}")

    def test_commit_id_present(self):
        """Report must include the commit ID provided."""
        report = build.build_diagnostic_report([],"abc123def456")
        self.assertIn("commit", report)
        self.assertEqual(report["commit"], "abc123def456")


if __name__ == "__main__":
    unittest.main()
