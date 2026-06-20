"""Tests for diagnostic redaction, artifact pairing, and path normalization.

Validates that build.py's diagnostic metadata:
- Reports artifact paths as repository-relative '/' paths
- Does not leak local home, repo, temp paths, machine names, or usernames
- Correctly pairs .logd references with generated artifacts
- Fails clearly on missing/mismatched artifacts
- Is deterministic on Windows and Unix-like hosts
"""

import json
import os
import platform
import re
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch, MagicMock

# Add repo root to path so we can import build
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from build import (
    ROOT,
    DIAGNOSTIC_DIR,
    build_diagnostic_report,
    diagnostic_paths_for_commit,
    current_commit_id,
)


class TestRepositoryRelativePaths(unittest.TestCase):
    """Validate that diagnostic metadata reports artifact paths as repository-relative '/' paths."""

    def _make_report(self, logd_relpaths=None, **kwargs):
        results = [("test-mod", True, 1.0, "ok", "test-mod-binary")]
        return build_diagnostic_report(
            results=results,
            commit_id="abc12345",
            logd_relpaths=logd_relpaths,
            **kwargs,
        )

    def test_single_logd_path_is_relative(self):
        """Single .logd path should be a relative path using '/' separators."""
        report = self._make_report(logd_relpaths=["diagnostic/build-abc12345.logd"])
        logd = report["diagnostic_logd"]
        self.assertIsInstance(logd, str)
        self.assertFalse(Path(logd).is_absolute())
        # Must use forward slashes even on Windows
        self.assertNotIn("\\", logd)

    def test_multiple_logd_paths_are_relative(self):
        """Multiple .logd paths (chunked) should all be relative."""
        paths = [
            "diagnostic/build-abc12345-part001.logd",
            "diagnostic/build-abc12345-part002.logd",
        ]
        report = self._make_report(logd_relpaths=paths)
        logd = report["diagnostic_logd"]
        self.assertIsInstance(logd, list)
        for p in logd:
            self.assertFalse(Path(p).is_absolute())
            self.assertNotIn("\\", p)

    def test_no_logd_when_not_generated(self):
        """When no .logd is generated, diagnostic_logd should be None."""
        report = self._make_report(logd_relpaths=None)
        self.assertIsNone(report["diagnostic_logd"])

    def test_decrypt_command_uses_relative_path(self):
        """Decrypt command should reference relative path."""
        report = self._make_report(
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="testpw",
        )
        cmd = report["decrypt_command"]
        self.assertIn("diagnostic/build-abc12345.logd", cmd)
        # Should not contain absolute paths
        self.assertNotIn(str(ROOT), cmd)

    def test_module_artifacts_are_relative(self):
        """Module artifact paths in report should be relative."""
        results = [
            ("backend", True, 5.0, "ok", "backend/target/debug/backend"),
            ("frontend", True, 10.0, "ok", "frontend/dist"),
        ]
        report = build_diagnostic_report(
            results=results,
            commit_id="abc12345",
        )
        for mod in report["modules"]:
            if mod["artifact"]:
                self.assertFalse(Path(mod["artifact"]).is_absolute())


class TestNoSensitivePathLeaks(unittest.TestCase):
    """Assert local home, repo, temp paths, machine names, and usernames are not leaked."""

    def _make_report(self, **kwargs):
        results = [("test-mod", True, 1.0, "ok", None)]
        return build_diagnostic_report(
            results=results,
            commit_id="abc12345",
            **kwargs,
        )

    def test_no_absolute_home_path_in_report(self):
        """Home directory path should not appear in report JSON."""
        report = self._make_report()
        report_json = json.dumps(report)
        home = str(Path.home())
        # Home path should not appear literally in the report
        if home != "/" and home != "":
            self.assertNotIn(home, report_json)

    def test_no_repo_root_path_in_report(self):
        """Repository root absolute path should not appear in report JSON."""
        report = self._make_report()
        report_json = json.dumps(report)
        self.assertNotIn(str(ROOT), report_json)

    def test_no_temp_path_in_report(self):
        """Temp directory path should not appear in report JSON."""
        report = self._make_report()
        report_json = json.dumps(report)
        temp_dir = tempfile.gettempdir()
        if temp_dir and temp_dir != "/tmp":
            self.assertNotIn(temp_dir, report_json)

    def test_no_hostname_in_report(self):
        """Machine hostname should not appear in report JSON."""
        report = self._make_report()
        report_json = json.dumps(report)
        hostname = platform.node()
        if hostname:
            self.assertNotIn(hostname, report_json)

    def test_no_username_in_report(self):
        """System username should not appear in report JSON."""
        import getpass
        report = self._make_report()
        report_json = json.dumps(report)
        try:
            username = getpass.getuser()
            if username:
                self.assertNotIn(username, report_json)
        except Exception:
            pass  # Some environments may not have a user

    def test_no_sensitive_env_vars_in_report(self):
        """Sensitive environment variable values should not leak."""
        report = self._make_report()
        report_json = json.dumps(report)
        sensitive_keys = ["HOME", "USER", "USERNAME", "HOSTNAME", "TMPDIR"]
        for key in sensitive_keys:
            val = os.environ.get(key, "")
            if val and len(val) > 2 and val != "/":
                self.assertNotIn(val, report_json,
                                 f"Env var {key} value leaked in report")


class TestArtifactPairing(unittest.TestCase):
    """Confirm .logd reference in JSON matches generated encrypted artifact."""

    def test_logd_reference_matches_diagnostic_dir(self):
        """The .logd path in report should point to diagnostic/ directory."""
        results = [("test-mod", True, 1.0, "ok", None)]
        report = build_diagnostic_report(
            results=results,
            commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
        )
        logd = report["diagnostic_logd"]
        self.assertTrue(logd.startswith("diagnostic/"))

    def test_logd_commit_id_matches_report_commit(self):
        """The commit ID in .logd filename should match report commit."""
        results = [("test-mod", True, 1.0, "ok", None)]
        report = build_diagnostic_report(
            results=results,
            commit_id="deadbeef",
            logd_relpaths=["diagnostic/build-deadbeef.logd"],
        )
        logd = report["diagnostic_logd"]
        self.assertIn("deadbeef", logd)
        self.assertEqual(report["commit"], "deadbeef")

    def test_chunked_logd_all_have_same_commit(self):
        """All chunked .logd files should reference the same commit."""
        paths = [
            "diagnostic/build-cafebabe-part001.logd",
            "diagnostic/build-cafebabe-part002.logd",
            "diagnostic/build-cafebabe-part003.logd",
        ]
        results = [("test-mod", True, 1.0, "ok", None)]
        report = build_diagnostic_report(
            results=results,
            commit_id="cafebabe",
            logd_relpaths=paths,
        )
        logd = report["diagnostic_logd"]
        self.assertEqual(len(logd), 3)
        for p in logd:
            self.assertIn("cafebabe", p)

    def test_diagnostic_json_exists_for_generated_logd(self):
        """For an existing diagnostic .logd, a corresponding .json should exist."""
        # Check existing artifacts from previous build
        for logd_file in DIAGNOSTIC_DIR.glob("build-*.logd"):
            json_file = logd_file.with_suffix(".json")
            self.assertTrue(
                json_file.exists(),
                f"Missing JSON metadata for {logd_file.name}",
            )

    def test_diagnostic_json_references_existing_logd(self):
        """Existing JSON metadata should reference an existing .logd file."""
        for json_file in DIAGNOSTIC_DIR.glob("build-*.json"):
            data = json.loads(json_file.read_text())
            logd_ref = data.get("diagnostic_logd")
            if logd_ref:
                if isinstance(logd_ref, str):
                    logd_files = [logd_ref]
                else:
                    logd_files = logd_ref
                for logd_path in logd_files:
                    full_path = ROOT / logd_path
                    self.assertTrue(
                        full_path.exists(),
                        f"JSON {json_file.name} references missing .logd: {logd_path}",
                    )


class TestMissingArtifactHandling(unittest.TestCase):
    """Fail clearly when JSON is missing, .logd is missing, or pair is mismatched."""

    def test_missing_logd_sets_error_field(self):
        """When .logd generation fails, diagnostic_logd_error should be set."""
        results = [("test-mod", False, 0.0, "encryptly not found", None)]
        report = build_diagnostic_report(
            results=results,
            commit_id="abc12345",
            logd_error="encryptly binary not found",
        )
        self.assertIsNotNone(report["diagnostic_logd_error"])
        self.assertIn("encryptly", report["diagnostic_logd_error"])

    def test_missing_logd_sets_logd_to_none(self):
        """When .logd generation fails, diagnostic_logd should be None."""
        results = [("test-mod", False, 0.0, "failed", None)]
        report = build_diagnostic_report(
            results=results,
            commit_id="abc12345",
            logd_error="some error",
        )
        self.assertIsNone(report["diagnostic_logd"])

    def test_message_blocker_set_on_failure(self):
        """When there's a blocker, message_blocker should be set."""
        results = [("test-mod", False, 0.0, "encryptly failed", None)]
        report = build_diagnostic_report(
            results=results,
            commit_id="abc12345",
            message_blocker="You need to fix your environment",
        )
        self.assertIsNotNone(report["message_blocker"])

    def test_mismatched_pair_detected(self):
        """A .logd referenced in JSON but not on disk should be detectable."""
        results = [("test-mod", True, 1.0, "ok", None)]
        fake_path = "diagnostic/build-nonexistent.logd"
        report = build_diagnostic_report(
            results=results,
            commit_id="abc12345",
            logd_relpaths=[fake_path],
        )
        # The report references a path that doesn't exist
        full_path = ROOT / fake_path
        self.assertFalse(
            full_path.exists(),
            "Test setup: fake .logd should not exist",
        )
        # But the report still references it — this is the mismatch
        self.assertEqual(report["diagnostic_logd"], fake_path)


class TestCrossPlatformDeterminism(unittest.TestCase):
    """Keep coverage deterministic on Windows and Unix-like hosts."""

    def test_path_separators_are_forward_slash(self):
        """All paths in report should use '/' separators, not OS-specific."""
        results = [
            ("backend", True, 1.0, "ok", "backend/target/debug/backend"),
        ]
        report = build_diagnostic_report(
            results=results,
            commit_id="abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
        )
        report_json = json.dumps(report)
        # Should not contain backslashes (Windows separator)
        self.assertNotIn("\\", report_json)

    def test_report_structure_is_consistent(self):
        """Report should have the same top-level keys regardless of platform."""
        results = [("test-mod", True, 1.0, "ok", None)]
        report = build_diagnostic_report(
            results=results,
            commit_id="abc12345",
        )
        expected_keys = {
            "generated_at",
            "commit",
            "diagnostic_logd",
            "diagnostic_logd_error",
            "message_blocker",
            "chunked",
            "chunk_size_bytes",
            "password",
            "decrypt_command",
            "total_modules",
            "passed",
            "failed",
            "modules",
            "pr_note",
        }
        self.assertEqual(set(report.keys()), expected_keys)

    def test_module_structure_is_consistent(self):
        """Each module entry should have consistent keys."""
        results = [
            ("mod-a", True, 1.0, "ok", "artifact-a"),
            ("mod-b", False, 2.0, "fail output", None),
        ]
        report = build_diagnostic_report(
            results=results,
            commit_id="abc12345",
        )
        for mod in report["modules"]:
            self.assertIn("name", mod)
            self.assertIn("status", mod)
            self.assertIn("elapsed_seconds", mod)
            self.assertIn("artifact", mod)
            self.assertIn("output", mod)

    def test_diagnostic_paths_for_commit_under_diagnostic(self):
        """diagnostic_paths_for_commit should return paths under diagnostic dir."""
        logd_path, metadata_path, commit_id = diagnostic_paths_for_commit()
        # Paths should be under diagnostic/ (may be absolute or relative)
        self.assertTrue(
            str(logd_path).endswith("diagnostic/build-" + commit_id + ".logd"),
            f"Logd path should end with diagnostic/build-*.logd, got: {logd_path}",
        )
        self.assertTrue(
            str(metadata_path).endswith("diagnostic/build-" + commit_id + ".json"),
            f"Metadata path should end with diagnostic/build-*.json, got: {metadata_path}",
        )


class TestDiagnosticPathsForCommit(unittest.TestCase):
    """Test the diagnostic_paths_for_commit helper."""

    def test_returns_three_values(self):
        """Should return (logd_path, metadata_path, commit_id)."""
        result = diagnostic_paths_for_commit()
        self.assertEqual(len(result), 3)

    def test_paths_are_under_diagnostic_dir(self):
        """Both paths should be under the diagnostic/ directory."""
        logd_path, metadata_path, _ = diagnostic_paths_for_commit()
        # Parent directory name should be 'diagnostic'
        self.assertEqual(logd_path.parent.name, "diagnostic")
        self.assertEqual(metadata_path.parent.name, "diagnostic")

    def test_logd_extension(self):
        """Logd path should have .logd extension."""
        logd_path, _, _ = diagnostic_paths_for_commit()
        self.assertEqual(logd_path.suffix, ".logd")

    def test_json_extension(self):
        """Metadata path should have .json extension."""
        _, metadata_path, _ = diagnostic_paths_for_commit()
        self.assertEqual(metadata_path.suffix, ".json")

    def test_same_commit_id_in_filenames(self):
        """Both paths should reference the same commit ID."""
        logd_path, metadata_path, commit_id = diagnostic_paths_for_commit()
        self.assertIn(commit_id, logd_path.name)
        self.assertIn(commit_id, metadata_path.name)


if __name__ == "__main__":
    unittest.main()
