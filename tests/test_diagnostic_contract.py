"""Offline metadata contract tests; placeholder bytes do not validate encryption."""

import json
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import patch

import build


class DiagnosticContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.root = self.workspace / "repo"
        self.diagnostic = self.root / "diagnostic"
        self.diagnostic.mkdir(parents=True)
        self.metadata = self.diagnostic / "build-12345678.json"
        self.reference = "diagnostic/build-12345678.logd"
        self.home = self.workspace / "home"
        self.temp = self.workspace / "temp"
        for mock in (
            patch.object(build, "ROOT", self.root),
            patch.object(build.Path, "home", return_value=self.home),
            patch.object(build.tempfile, "gettempdir", return_value=str(self.temp)),
            patch.object(build.getpass, "getuser", return_value="fixture-user"),
            patch.object(build.platform, "node", return_value="fixture-host"),
            patch.dict(build.os.environ, {}, clear=True),
            patch.object(build.subprocess, "run", side_effect=AssertionError("No subprocesses allowed")),
        ):
            mock.start()
            self.addCleanup(mock.stop)

    def write_metadata(self, value):
        self.metadata.write_text(json.dumps(value), encoding="utf-8")

    def errors(self):
        return build.validate_diagnostic_metadata(self.metadata, root=self.root)

    def test_valid_pair_and_relative_artifact(self):
        (self.root / self.reference).write_bytes(b"placeholder, not encrypted")
        self.write_metadata({"commit": "12345678", "diagnostic_logd": self.reference})
        self.assertEqual(self.errors(), [])
        self.assertEqual(
            build.repo_relative_metadata_path(str(self.root / "backend/target/backend")),
            "backend/target/backend",
        )
        self.assertEqual(
            build.repo_relative_metadata_path(r"backend\target\backend"),
            "backend/target/backend",
        )

    def test_windows_artifact_normalization_is_host_independent(self):
        with patch.object(build, "ROOT", PureWindowsPath(r"C:\Users\fixture-user\repo")):
            for path in (
                r"C:\Users\fixture-user\repo\backend\target\backend.exe",
                "C:/Users/fixture-user/repo/backend/target/backend.exe",
            ):
                with self.subTest(path=path):
                    self.assertEqual(build.repo_relative_metadata_path(path), "backend/target/backend.exe")

    def test_report_redacts_output_and_failure_fields(self):
        private = " ".join(map(str, [self.root, self.home, self.temp, "fixture-user", "fixture-host"]))
        report = build.build_diagnostic_report(
            [("backend", False, 0.0, private, str(self.root / "backend/target/backend"))],
            "12345678",
            logd_error=private,
            message_blocker=private,
        )
        for field in (report["modules"][0]["output"], report["diagnostic_logd_error"], report["message_blocker"]):
            for token in private.split():
                self.assertNotIn(token, field)

    def test_windows_redaction_and_reference_separators(self):
        with (
            patch.object(build, "ROOT", PureWindowsPath(r"C:\Users\fixture-user\repo")),
            patch.object(build.Path, "home", return_value=PureWindowsPath(r"C:\Users\fixture-user")),
            patch.object(build.tempfile, "gettempdir", return_value=r"C:\Temp\private"),
        ):
            private = r"C:\Users\fixture-user\repo C:\Users\fixture-user C:\Temp\private"
            for text in (private, private.replace("\\", "/")):
                with self.subTest(text=text):
                    self.assertNotIn("C:", build.redact_diagnostic_text(text))
            report = build.build_diagnostic_report(
                [], "12345678", logd_relpaths=[r"diagnostic\build-12345678.logd"], password="fixture-key"
            )
            self.assertEqual(report["diagnostic_logd"], self.reference)
            self.assertNotIn("\\", report["decrypt_command"])

    def test_windows_redaction_and_validation_ignore_path_case(self):
        (self.root / self.reference).write_bytes(b"placeholder")
        with (
            patch.object(build, "ROOT", PureWindowsPath(r"C:\Users\ALICE\Project")),
            patch.object(build.Path, "home", return_value=PureWindowsPath(r"C:\Users\ALICE")),
            patch.object(build.getpass, "getuser", return_value="ALICE"),
            patch.object(build.platform, "node", return_value="DESKTOP-X"),
        ):
            private = r"c:\users\alice\project\src user=alice host=desktop-x"
            clean = build.redact_diagnostic_text(private)
            for token in ("c:", "alice", "desktop-x"):
                self.assertNotIn(token, clean.lower())
            self.write_metadata({"diagnostic_logd": self.reference, "modules": [{"output": private}]})
            self.assertTrue(any("leak" in error for error in self.errors()))

    def test_short_identity_does_not_match_inside_unrelated_words(self):
        (self.root / self.reference).write_bytes(b"placeholder")
        with patch.object(build, "_redaction_tokens", return_value=["me"]):
            self.assertEqual(
                build.redact_diagnostic_text("metadata memory user=me"),
                "metadata memory user=<redacted>",
            )
            report = build.build_diagnostic_report(
                [("backend", True, 0.0, "metadata memory user=me", None)],
                "12345678", logd_relpaths=[self.reference], password="fixture-key",
            )
            self.write_metadata(report)
            self.assertEqual(self.errors(), [])
            report["modules"][0]["output"] = "user=me"
            self.write_metadata(report)
            self.assertTrue(any("leak" in error for error in self.errors()))

    def test_existing_wrong_commit_artifact_is_mismatched(self):
        wrong = "diagnostic/build-deadbeef.logd"
        (self.root / wrong).write_bytes(b"placeholder")
        self.write_metadata({"diagnostic_logd": wrong})
        self.assertTrue(any("mismatch" in error for error in self.errors()))

    def test_missing_json_and_missing_artifact_are_errors(self):
        self.assertTrue(any("missing" in error for error in self.errors()))
        self.write_metadata({"diagnostic_logd": self.reference})
        self.assertTrue(any("missing" in error for error in self.errors()))

    def test_invalid_json_and_non_object_metadata_are_errors(self):
        self.metadata.write_text("{broken", encoding="utf-8")
        self.assertTrue(self.errors())
        for value in ([], None, "text", 123):
            with self.subTest(value=value):
                self.write_metadata(value)
                self.assertTrue(self.errors())

    def test_empty_or_invalid_reference_lists_are_errors(self):
        for value in ([], "", None, [None], [self.reference, self.reference]):
            with self.subTest(value=value):
                self.write_metadata({"diagnostic_logd": value})
                self.assertTrue(self.errors())

    def test_non_relative_and_outside_diagnostic_references_are_errors(self):
        outside_diagnostic = "build-12345678.logd"
        (self.root / outside_diagnostic).write_bytes(b"placeholder")
        for value in (outside_diagnostic, "../build-12345678.logd", "C:/diagnostic/build-12345678.logd", r"diagnostic\build-12345678.logd"):
            with self.subTest(value=value):
                self.write_metadata({"diagnostic_logd": value})
                self.assertTrue(self.errors())

    def test_empty_or_directory_artifacts_are_errors(self):
        artifact = self.root / self.reference
        self.write_metadata({"diagnostic_logd": self.reference})
        artifact.touch()
        self.assertTrue(self.errors())
        artifact.unlink()
        artifact.mkdir()
        self.assertTrue(self.errors())

    def test_symlink_outside_repository_is_rejected(self):
        outside = self.workspace / "outside.logd"
        outside.write_bytes(b"placeholder")
        try:
            (self.root / self.reference).symlink_to(outside)
        except OSError:
            self.skipTest("Creating symlinks is unavailable on this host")
        self.write_metadata({"diagnostic_logd": self.reference})
        self.assertTrue(any("outside" in error for error in self.errors()))

    def test_split_artifacts_require_matching_ordered_parts(self):
        parts = [f"diagnostic/build-12345678-part{index:03d}.logd" for index in (1, 2)]
        for part in parts:
            (self.root / part).write_bytes(b"placeholder")
        self.write_metadata({"diagnostic_logd": parts, "chunked": True})
        self.assertEqual(self.errors(), [])
        for invalid in (parts[::-1], parts[1:]):
            with self.subTest(parts=invalid):
                self.write_metadata({"diagnostic_logd": invalid, "chunked": True})
                self.assertTrue(any("mismatch" in error for error in self.errors()))

    def test_validator_rejects_leaks_and_invalid_module_paths(self):
        (self.root / self.reference).write_bytes(b"placeholder")
        for value in (str(self.root), str(self.home), str(self.temp), "fixture-host", "fixture-user"):
            with self.subTest(value=value):
                self.write_metadata({"diagnostic_logd": self.reference, "modules": [{"output": value}]})
                self.assertTrue(any("leak" in error for error in self.errors()))
        for path in ("../outside", "C:/Users/name/file", r"backend\file"):
            with self.subTest(path=path):
                self.write_metadata({"diagnostic_logd": self.reference, "modules": [{"artifact": path}]})
                self.assertTrue(self.errors())


if __name__ == "__main__":
    unittest.main()
