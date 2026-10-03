"""Synthetic checks for diagnostic privacy and report/artifact consistency.

These tests use marked temporary bytes only. They do not exercise or assert
encryptly's encryption format or claim that a generated artifact is encrypted.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build


class DiagnosticRedactionTests(unittest.TestCase):
    def test_redacts_repository_home_temp_host_and_user_in_both_path_styles(self):
        repo = Path(tempfile.gettempdir()) / "synthetic diagnostic repo"
        home = Path.home()
        temp_root = r"D:\synthetic-temp"
        host = "synthetic-host"
        user = "synthetic-user"
        raw = " ".join([
            str(repo / "build.log"),
            str(repo / "build.log").replace("/", "\\"),
            str(home / "private.txt"),
            temp_root + r"\private-temp.txt",
            host,
            user,
        ])
        with mock.patch.object(build.platform, "node", return_value=host), \
                mock.patch.object(build.getpass, "getuser", return_value=user), \
                mock.patch.object(build.tempfile, "gettempdir", return_value=temp_root):
            redacted = build.redact_diagnostic_text(raw, repo)

        for private in [str(repo), str(home), temp_root, host, user]:
            self.assertNotIn(private, redacted)
        self.assertIn("<REPO>", redacted)
        self.assertIn("<HOME>", redacted)
        self.assertIn("<TEMP>", redacted)
        self.assertIn("<HOST>", redacted)
        self.assertIn("<USER>", redacted)

    def test_redacts_other_absolute_windows_and_unix_paths(self):
        redacted = build.redact_diagnostic_text(
            r"C:\build\secret /opt/private/key.txt C:/Program Files/My App/file --retain-this http://example.com/path https://example.com/file file:///home/bob/file.txt \Device\HarddiskVolume1\Users\bob\file.txt"
        )
        self.assertNotIn(r"C:\build\secret", redacted)
        self.assertNotIn("/opt/private/key.txt", redacted)
        self.assertNotIn("C:/Program Files/My App/file", redacted)
        self.assertIn("--retain-this", redacted)
        self.assertIn("http://example.com/path", redacted)
        self.assertIn("https://example.com/file", redacted)
        self.assertNotIn("file:///home/bob/file.txt", redacted)
        self.assertNotIn(r"\Device\HarddiskVolume1\Users\bob\file.txt", redacted)

    def test_redacts_unc_paths_with_spaces(self):
        redacted = build.redact_diagnostic_text(r"\\server\share name\private file.txt")
        self.assertNotIn(r"\\server\share name\private file.txt", redacted)

    def test_artifact_metadata_path_is_portable_and_external_path_is_hidden(self):
        self.assertEqual("diagnostic/build-deadbeef.logd", build.diagnostic_relative_path(
            Path(build.ROOT) / "diagnostic" / "build-deadbeef.logd"
        ))
        self.assertEqual("<external-path>", build.diagnostic_display_path(r"C:\Users\synthetic\private.exe"))

    def test_report_redacts_paths_from_success_and_failure_fields(self):
        report = build.build_diagnostic_report(
            [("synthetic-module", False, 0.1, f"failed at {build.ROOT}\\private\\file", str(build.ROOT / "private.exe"))],
            "cafebabe",
            logd_error=f"packer failed at {build.ROOT}\\private\\packer.exe",
        )
        serialized = json.dumps(report)
        self.assertNotIn(str(build.ROOT), serialized)
        self.assertIn('"artifact": "private.exe"', serialized)
        self.assertIn("<REPO>", serialized)


class DiagnosticPairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-diagnostics-")
        self.root = Path(self.temp.name)
        self.diag = self.root / "diagnostic"
        self.diag.mkdir()
        self.metadata = self.diag / "build-cafebabe.json"
        self.logd = self.diag / "build-cafebabe.logd"

    def tearDown(self):
        self.temp.cleanup()

    def report(self, diagnostic_logd="diagnostic/build-cafebabe.logd"):
        self.metadata.write_text(json.dumps({"diagnostic_logd": diagnostic_logd}), encoding="utf-8")

    def test_accepts_matching_synthetic_artifact(self):
        self.report()
        self.logd.write_bytes(b"SYNTHETIC TEST FIXTURE, NOT ENCRYPTED")
        self.assertEqual([self.logd.resolve()], build.validate_diagnostic_artifact_pair(self.metadata, self.root))

    def test_fails_clearly_when_metadata_is_missing(self):
        with self.assertRaisesRegex(ValueError, "metadata is missing"):
            build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_fails_clearly_when_json_is_not_an_object(self):
        self.metadata.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must contain a JSON object"):
            build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_fails_clearly_when_referenced_logd_is_missing(self):
        self.report()
        with self.assertRaisesRegex(ValueError, r"\.logd artifact is missing"):
            build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_fails_clearly_when_referenced_logd_is_empty(self):
        self.report()
        self.logd.touch()
        with self.assertRaisesRegex(ValueError, r"\.logd artifact is empty"):
            build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_rejects_duplicate_artifact_references(self):
        name = "diagnostic/build-cafebabe.logd"
        self.report([name, name])
        self.logd.write_bytes(b"SYNTHETIC TEST FIXTURE, NOT ENCRYPTED")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_fails_clearly_when_artifact_set_does_not_match_report(self):
        self.report()
        self.logd.write_bytes(b"SYNTHETIC TEST FIXTURE, NOT ENCRYPTED")
        (self.diag / "build-cafebabe-part001.logd").write_bytes(b"SYNTHETIC EXTRA FIXTURE")
        with self.assertRaisesRegex(ValueError, "does not match"):
            build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_rejects_nonportable_or_escaping_metadata_paths(self):
        for unsafe in [r"diagnostic\build-cafebabe.logd", "../outside.logd", "C:/outside.logd"]:
            with self.subTest(unsafe=unsafe):
                self.report(unsafe)
                with self.assertRaisesRegex(ValueError, "safe repository-relative slash paths"):
                    build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_fails_when_artifact_exists_but_report_omits_it(self):
        self.report(None)
        self.logd.write_bytes(b"SYNTHETIC TEST FIXTURE, NOT ENCRYPTED")
        with self.assertRaisesRegex(ValueError, "exists but is not referenced"):
            build.validate_diagnostic_artifact_pair(self.metadata, self.root, require_logd=False)


if __name__ == "__main__":
    unittest.main()
