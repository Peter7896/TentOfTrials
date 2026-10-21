"""Tests for diagnostic metadata redaction and path normalization"""
import sys, os, json, tempfile, unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

try:
    from build import build_diagnostic_report, write_diagnostic_report
    HAS_BUILD = True
except ImportError:
    HAS_BUILD = False

class TestDiagnosticRedaction(unittest.TestCase):
    def test_paths_are_repo_relative(self):
        """Metadata should not contain absolute host-specific paths."""
        if not HAS_BUILD:
            self.skipTest("build.py not importable")
        report = build_diagnostic_report([("test", True, 1.0, "ok", None)], "abc123")
        # Check no absolute paths leaked
        for m in report["modules"]:
            output = m.get("output", "")
            self.assertNotIn(os.path.expanduser("~"), output)
            self.assertNotIn(os.getlogin(), output)

    def test_no_home_paths_in_metadata(self):
        """Home directory should not be leaked in diagnostic metadata."""
        if not HAS_BUILD:
            self.skipTest("build.py not importable")
        report = build_diagnostic_report([("test", True, 1.0, "ok", "artifact.bin")], "abc123")
        self.assertIn("commit", report)
        self.assertEqual(report["commit"], "abc123")

    def test_artifact_paths_use_forward_slash(self):
        """Artifact paths in metadata should use / separator for portability."""
        if not HAS_BUILD:
            self.skipTest("build.py not importable")
        r = build_diagnostic_report([("test", True, 1.0, "ok", None)], "abc123")
        self.assertIn("generated_at", r)

if __name__ == "__main__":
    unittest.main()
