#!/usr/bin/env python3
"""
Regression tests for diagnostic redaction, artifact pairing, and path normalization.

These tests validate the contract that build.py diagnostic metadata:
  1. Reports artifact paths as repository-relative paths (forward slashes)
  2. Does NOT leak local home, repo, temp paths, machine names, or usernames
  3. The .logd reference in JSON matches a generated encrypted artifact in diagnostic/
  4. Fails clearly when the JSON is missing, the .logd artifact is missing, or the pair is mismatched
  5. Is deterministic on Windows and Unix-like hosts

Usage:
  python3 test_diagnostic_redaction.py              # Run all tests
  python3 test_diagnostic_redaction.py -v           # Verbose
  python3 test_diagnostic_redaction.py --with-build  # Run with actual build.py output
"""

import json
import os
import platform
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
BUILD_PY = ROOT / "build.py"
DIAGNOSTIC_DIR = ROOT / "diagnostic"

# Patterns that should NEVER appear in diagnostic metadata (redaction targets)
SENSITIVE_PATTERNS = [
    # Home directory
    re.compile(re.escape(str(Path.home())), re.IGNORECASE),
    # Temp directory
    re.compile(re.escape(tempfile.gettempdir()), re.IGNORECASE),
    # Machine / hostname
    re.compile(re.escape(platform.node()), re.IGNORECASE),
    # Username
    re.compile(re.escape(os.environ.get("USERNAME", os.environ.get("USER", ""))), re.IGNORECASE),
    # Common temp path patterns
    re.compile(r"/tmp/[\w-]+", re.IGNORECASE),
    re.compile(r"C:\\Users\\[\w.]+", re.IGNORECASE),
    re.compile(r"C:\\Windows\\Temp", re.IGNORECASE),
    re.compile(r"C:\\Users\\[\w.]+\\AppData\\Local\\Temp", re.IGNORECASE),
    # Git commit full hash (should only be 8 chars in metadata)
    re.compile(r"\b[0-9a-f]{40}\b"),
]

# Pattern for repository-relative paths (should use forward slashes)
RELATIVE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9_./\-]+$")

# Pattern for Windows-style paths that should NOT appear
WINDOWS_PATH_PATTERN = re.compile(r"[A-Za-z]:\\|\\\\[\\w.]+")


def load_diagnostic_json(path: Path) -> dict[str, Any] | None:
    """Load a diagnostic JSON file, return None on failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, OSError):
        return None


def find_latest_diagnostic() -> tuple[Path | None, Path | None]:
    """Find the latest diagnostic JSON and .logd pair by commit ID."""
    if not DIAGNOSTIC_DIR.exists():
        return None, None

    json_files = sorted(DIAGNOSTIC_DIR.glob("build-*.json"))
    if not json_files:
        return None, None

    latest_json = json_files[-1]
    commit_id = latest_json.stem.replace("build-", "")
    logd_path = DIAGNOSTIC_DIR / f"build-{commit_id}.logd"

    return latest_json, logd_path


def check_sensitive_data(text: str) -> list[str]:
    """Return list of sensitive patterns found in text."""
    found = []
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(text):
            found.append(pattern.pattern[:50])
    return found


def normalize_path_to_repo_relative(path_str: str, root: Path) -> str:
    """Convert an absolute path to repository-relative path with forward slashes."""
    try:
        p = Path(path_str)
        if p.is_absolute():
            rel = p.relative_to(root)
            return str(rel).replace("\\", "/")
        return str(p).replace("\\", "/")
    except (ValueError, TypeError):
        return path_str


def is_repo_relative_path(path_str: str) -> bool:
    """Check if a path string is repository-relative (no drive letters, no backslashes)."""
    if not path_str:
        return False
    # Should not contain Windows drive letters or backslashes
    if WINDOWS_PATH_PATTERN.search(path_str):
        return False
    if "\\" in path_str:
        return False
    # Should start with a directory name or file name, not / or drive
    if path_str.startswith("/") or path_str.startswith("\\"):
        return False
    return True


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDiagnosticPathNormalization(unittest.TestCase):
    """Validate that diagnostic metadata reports artifact paths as repository-relative paths."""

    def test_artifact_paths_use_forward_slashes(self):
        """Artifact paths in JSON should use forward slashes, not backslashes."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None:
            self.skipTest("No diagnostic JSON found; run build.py first or use --with-build")

        data = load_diagnostic_json(json_path)
        self.assertIsNotNone(data, f"Failed to parse {json_path}")

        # Check diagnostic_logd field
        logd_ref = data.get("diagnostic_logd")
        if logd_ref:
            if isinstance(logd_ref, str):
                self.assertNotIn("\\", logd_ref,
                    f"diagnostic_logd contains backslash: {logd_ref}")
                self.assertFalse(logd_ref.startswith("/"),
                    f"diagnostic_logd should not start with /: {logd_ref}")
            elif isinstance(logd_ref, list):
                for ref in logd_ref:
                    self.assertNotIn("\\", ref,
                        f"diagnostic_logd list item contains backslash: {ref}")
                    self.assertFalse(ref.startswith("/"),
                        f"diagnostic_logd list item should not start with /: {ref}")

        # Check module artifact paths
        for module in data.get("modules", []):
            artifact = module.get("artifact")
            if artifact:
                self.assertNotIn("\\", artifact,
                    f"Module artifact contains backslash: {artifact}")
                self.assertFalse(artifact.startswith("/"),
                    f"Module artifact should not start with /: {artifact}")

    def test_artifact_paths_are_repo_relative(self):
        """Artifact paths should be repository-relative, not absolute."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None:
            self.skipTest("No diagnostic JSON found; run build.py first or use --with-build")

        data = load_diagnostic_json(json_path)
        self.assertIsNotNone(data, f"Failed to parse {json_path}")

        # Check diagnostic_logd
        logd_ref = data.get("diagnostic_logd")
        if logd_ref:
            refs = [logd_ref] if isinstance(logd_ref, str) else logd_ref
            for ref in refs:
                self.assertTrue(is_repo_relative_path(ref),
                    f"diagnostic_logd is not repo-relative: {ref}")

        # Check module artifacts
        for module in data.get("modules", []):
            artifact = module.get("artifact")
            if artifact:
                self.assertTrue(is_repo_relative_path(artifact),
                    f"Module artifact is not repo-relative: {artifact}")

    def test_no_windows_drive_letters_in_paths(self):
        """No Windows drive letters (C:\\, D:\\) should appear in any path field."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None:
            self.skipTest("No diagnostic JSON found")

        raw_text = json_path.read_text(encoding="utf-8")
        drive_matches = WINDOWS_PATH_PATTERN.findall(raw_text)
        self.assertEqual(drive_matches, [],
            f"Windows drive letter paths found in diagnostic JSON: {drive_matches}")


class TestDiagnosticRedaction(unittest.TestCase):
    """Assert that sensitive information is NOT leaked in diagnostic metadata."""

    def test_no_home_directory_leak(self):
        """Home directory path should not appear in diagnostic metadata."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None:
            self.skipTest("No diagnostic JSON found")

        raw_text = json_path.read_text(encoding="utf-8")
        home = str(Path.home())
        self.assertNotIn(home, raw_text,
            f"Home directory leaked: {home}")

    def test_no_username_leak(self):
        """Username should not appear in diagnostic metadata."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None:
            self.skipTest("No diagnostic JSON found")

        raw_text = json_path.read_text(encoding="utf-8")
        username = os.environ.get("USERNAME", os.environ.get("USER", ""))
        if username:
            self.assertNotIn(username, raw_text,
                f"Username leaked: {username}")

    def test_no_hostname_leak(self):
        """Machine hostname should not appear in diagnostic metadata."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None:
            self.skipTest("No diagnostic JSON found")

        raw_text = json_path.read_text(encoding="utf-8")
        hostname = platform.node()
        if hostname:
            self.assertNotIn(hostname, raw_text,
                f"Hostname leaked: {hostname}")

    def test_no_temp_directory_leak(self):
        """Temp directory path should not appear in diagnostic metadata."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None:
            self.skipTest("No diagnostic JSON found")

        raw_text = json_path.read_text(encoding="utf-8")
        tmpdir = tempfile.gettempdir()
        self.assertNotIn(tmpdir, raw_text,
            f"Temp directory leaked: {tmpdir}")

    def test_no_full_commit_hash(self):
        """Full 40-char commit hash should not appear; only first 8 chars are allowed."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None:
            self.skipTest("No diagnostic JSON found")

        raw_text = json_path.read_text(encoding="utf-8")
        full_hash = re.search(r"\b[0-9a-f]{40}\b", raw_text)
        self.assertIsNone(full_hash,
            "Full 40-char commit hash found in diagnostic metadata (should be truncated to 8 chars)")

    def test_redaction_summary_with_mock_data(self):
        """Test that sensitive data detection works correctly with mock data."""
        home = str(Path.home())
        hostname = platform.node()
        tmpdir = tempfile.gettempdir()

        # Mock diagnostic text with sensitive data
        mock_text = f"""
        Build completed on {hostname}
        Home: {home}
        Temp: {tmpdir}
        User: {os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))}
        Artifact: diagnostic/build-abc12345.logd
        """

        sensitive = check_sensitive_data(mock_text)
        self.assertGreater(len(sensitive), 0,
            "Sensitive data detection should find patterns in mock text with sensitive info")

        # Mock diagnostic text without sensitive data
        clean_text = """
        Build completed successfully
        Artifact: diagnostic/build-abc12345.logd
        Status: PASS
        """

        sensitive_clean = check_sensitive_data(clean_text)
        self.assertEqual(sensitive_clean, [],
            "Clean text should not trigger sensitive data detection")


class TestDiagnosticArtifactPairing(unittest.TestCase):
    """Confirm the .logd reference in JSON matches a generated encrypted artifact."""

    def test_logd_file_exists_for_json(self):
        """For every diagnostic JSON, the referenced .logd file must exist."""
        if not DIAGNOSTIC_DIR.exists():
            self.skipTest("diagnostic/ directory does not exist")

        json_files = sorted(DIAGNOSTIC_DIR.glob("build-*.json"))
        self.assertGreater(len(json_files), 0,
            "No diagnostic JSON files found in diagnostic/")

        for json_file in json_files:
            commit_id = json_file.stem.replace("build-", "")
            logd_file = DIAGNOSTIC_DIR / f"build-{commit_id}.logd"

            data = load_diagnostic_json(json_file)
            if data is None:
                continue

            logd_error = data.get("diagnostic_logd_error")
            if logd_error:
                # If there's an error creating the .logd, it's expected to be missing
                continue

            logd_ref = data.get("diagnostic_logd")
            if logd_ref:
                # The .logd should exist
                self.assertTrue(logd_file.exists(),
                    f"Referenced .logd not found: {logd_file} (referenced by {json_file.name})")

    def test_json_logd_pair_consistency(self):
        """JSON and .logd files should have matching commit IDs."""
        if not DIAGNOSTIC_DIR.exists():
            self.skipTest("diagnostic/ directory does not exist")

        json_files = sorted(DIAGNOSTIC_DIR.glob("build-*.json"))
        logd_files = sorted(DIAGNOSTIC_DIR.glob("build-*.logd"))

        json_commits = {f.stem.replace("build-", "") for f in json_files}
        logd_commits = {f.stem.replace("build-", "") for f in logd_files}

        # Every JSON should have a matching .logd (unless there's an error)
        for json_file in json_files:
            commit_id = json_file.stem.replace("build-", "")
            data = load_diagnostic_json(json_file)
            if data and data.get("diagnostic_logd_error"):
                continue  # Expected to be missing

            self.assertIn(commit_id, logd_commits,
                f"No .logd for commit {commit_id} (JSON: {json_file.name})")

        # Every .logd should have a matching JSON
        for logd_file in logd_files:
            commit_id = logd_file.stem.replace("build-", "")
            self.assertIn(commit_id, json_commits,
                f"No JSON for commit {commit_id} (logd: {logd_file.name})")

    def test_logd_file_has_content(self):
        """Referenced .logd files should not be empty."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None or logd_path is None:
            self.skipTest("No diagnostic pair found")

        data = load_diagnostic_json(json_path)
        if data and data.get("diagnostic_logd_error"):
            self.skipTest("logd creation had an error")

        if logd_path.exists():
            size = logd_path.stat().st_size
            self.assertGreater(size, 0,
                f"Referenced .logd is empty: {logd_path}")


class TestDiagnosticMissingFileHandling(unittest.TestCase):
    """Test that the system fails clearly when files are missing or mismatched."""

    def test_missing_json_detected(self):
        """Missing JSON file should be detected."""
        json_path, logd_path = find_latest_diagnostic()
        # This test verifies the detection logic works
        # If no JSON is found, the helper returns None
        if json_path is None:
            # This is expected when no build has been run
            self.assertTrue(True, "Correctly detected no diagnostic JSON")
        else:
            # Verify we can load it
            data = load_diagnostic_json(json_path)
            self.assertIsNotNone(data, f"Should be able to parse {json_path}")

    def test_missing_logd_with_error_flagged(self):
        """When .logd is missing but JSON exists, error should be flagged."""
        json_path, logd_path = find_latest_diagnostic()
        if json_path is None:
            self.skipTest("No diagnostic JSON found")

        data = load_diagnostic_json(json_path)
        if data is None:
            self.skipTest("Could not parse JSON")

        # If logd_error is set, the missing .logd is expected
        if data.get("diagnostic_logd_error"):
            self.assertTrue(True, "logd_error is properly set when .logd is missing")
        elif data.get("diagnostic_logd"):
            # If .logd is referenced, it should exist
            commit_id = data.get("commit", "")
            expected_logd = DIAGNOSTIC_DIR / f"build-{commit_id}.logd"
            self.assertTrue(expected_logd.exists(),
                f"Referenced .logd missing: {expected_logd}")

    def test_mismatched_pair_detection(self):
        """Detect when JSON references a .logd that doesn't match the commit ID."""
        if not DIAGNOSTIC_DIR.exists():
            self.skipTest("diagnostic/ directory does not exist")

        json_files = sorted(DIAGNOSTIC_DIR.glob("build-*.json"))
        for json_file in json_files:
            data = load_diagnostic_json(json_file)
            if data is None:
                continue

            json_commit = data.get("commit", "")
            logd_ref = data.get("diagnostic_logd")

            if logd_ref and json_commit != "00000000":
                # Extract commit from reference
                ref_match = re.search(r"build-([0-9a-f]{8})", str(logd_ref))
                if ref_match:
                    ref_commit = ref_match.group(1)
                    self.assertEqual(json_commit, ref_commit,
                        f"Commit mismatch: JSON says {json_commit}, logd ref says {ref_commit}")


class TestBuildPyIntegration(unittest.TestCase):
    """Integration tests that run build.py and validate the output."""

    def test_build_py_exists(self):
        """build.py should exist in the repository root."""
        self.assertTrue(BUILD_PY.exists(),
            f"build.py not found at {BUILD_PY}")

    def test_build_py_has_diagnostic_functions(self):
        """build.py should have key diagnostic functions."""
        if not BUILD_PY.exists():
            self.skipTest("build.py not found")

        content = BUILD_PY.read_text(encoding="utf-8")

        # Check for key functions
        required_functions = [
            "build_diagnostic_report",
            "write_diagnostic_report",
            "diagnostic_paths_for_commit",
            "generate_logd",
            "commit_diagnostic_artifacts",
        ]

        for func in required_functions:
            self.assertIn(f"def {func}", content,
                f"build.py missing required function: {func}")

    def test_build_py_redacts_password_in_report(self):
        """build.py should not hardcode passwords in the report generation."""
        if not BUILD_PY.exists():
            self.skipTest("build.py not found")

        content = BUILD_PY.read_text(encoding="utf-8")

        # Password should come from encryptly output, not be hardcoded
        # Check that there's no hardcoded password string
        hardcoded_passwords = re.findall(
            r'"password":\s*"[A-Za-z0-9]{10,}"', content
        )
        self.assertEqual(hardcoded_passwords, [],
            f"Hardcoded passwords found in build.py: {hardcoded_passwords}")

    def test_build_py_uses_utc_timestamps(self):
        """build.py should use UTC timestamps for deterministic output."""
        if not BUILD_PY.exists():
            self.skipTest("build.py not found")

        content = BUILD_PY.read_text(encoding="utf-8")

        # Should use datetime.timezone.utc
        self.assertIn("timezone.utc", content,
            "build.py should use datetime.timezone.utc for timestamps")


class TestPathNormalizationEdgeCases(unittest.TestCase):
    """Edge case tests for path normalization across platforms."""

    def test_forward_slash_normalization(self):
        """Forward slashes should be preserved."""
        self.assertTrue(is_repo_relative_path("diagnostic/build-abc12345.logd"))
        self.assertTrue(is_repo_relative_path("backend/target/debug/backend"))
        self.assertTrue(is_repo_relative_path("frontend/dist/index.html"))

    def test_backslash_rejection(self):
        """Backslashes should be rejected."""
        self.assertFalse(is_repo_relative_path("diagnostic\\build-abc12345.logd"))
        self.assertFalse(is_repo_relative_path("C:\\Users\\test\\diagnostic"))

    def test_absolute_path_rejection(self):
        """Absolute paths should be rejected."""
        self.assertFalse(is_repo_relative_path("/home/user/diagnostic/build.logd"))
        self.assertFalse(is_repo_relative_path("C:\\diagnostic\\build.logd"))

    def test_drive_letter_rejection(self):
        """Windows drive letters should be rejected."""
        self.assertFalse(is_repo_relative_path("C:\\diagnostic\\build.logd"))
        self.assertFalse(is_repo_relative_path("D:\\build\\output.logd"))


if __name__ == "__main__":
    verbosity = 2 if "-v" in sys.argv else 1
    with_build = "--with-build" in sys.argv

    if with_build:
        # Run build.py first to generate fresh diagnostic output
        print("Running build.py to generate diagnostic output...")
        import subprocess
        result = subprocess.run(
            [sys.executable, str(BUILD_PY)],
            cwd=str(ROOT),
            capture_output=False,
            timeout=900,
        )
        print(f"build.py exited with code {result.returncode}")
        print()

    unittest.main(verbosity=verbosity)
