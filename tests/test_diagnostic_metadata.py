import json
import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import build


class DiagnosticMetadataTests(unittest.TestCase):
    def test_metadata_uses_repository_relative_forward_slash_paths(self):
        nested_artifact = build.ROOT / "backend" / "target" / "debug" / "backend"
        report = build.build_diagnostic_report(
            [
                (
                    "backend",
                    True,
                    1.23456,
                    "built artifact at " + str(nested_artifact),
                    str(nested_artifact),
                )
            ],
            "abc12345",
            logd_relpaths=["diagnostic/build-abc12345.logd"],
            password="pw",
        )

        module = report["modules"][0]
        self.assertEqual(module["artifact"], "backend/target/debug/backend")
        self.assertIn("backend/target/debug/backend", module["output"])
        self.assertNotIn(str(build.ROOT), json.dumps(report))
        self.assertEqual(report["diagnostic_logd"], "diagnostic/build-abc12345.logd")
        self.assertEqual(
            report["decrypt_command"],
            "encryptly unpack diagnostic/build-abc12345.logd <outdir> --password pw",
        )

    def test_metadata_redacts_local_identity_and_machine_paths(self):
        temp_dir = Path(tempfile.gettempdir()) / "tent-secret-temp"
        home_dir = Path.home()
        user = "diagnostic-user"
        host = "diagnostic-host"
        repo_secret = build.ROOT / "private" / "repo-file.txt"
        output = "\n".join(
            [
                f"home={home_dir}",
                f"tmp={temp_dir}",
                f"repo={repo_secret}",
                f"user={user}",
                f"host={host}",
            ]
        )

        with mock.patch("getpass.getuser", return_value=user), mock.patch(
            "platform.node", return_value=host
        ):
            report = build.build_diagnostic_report(
                [("backend", False, 0.5, output, str(repo_secret))],
                "abc12345",
                logd_relpaths=["diagnostic/build-abc12345.logd"],
            )

        encoded = json.dumps(report)
        for forbidden in [str(home_dir), str(temp_dir), str(build.ROOT), user, host]:
            self.assertNotIn(forbidden, encoded)
        self.assertIn("<HOME>", encoded)
        self.assertIn("<TEMP>", encoded)
        self.assertIn("private/repo-file.txt", encoded)

    def test_logd_pairing_validation_fails_clearly_for_missing_or_mismatched_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_path = root / "diagnostic" / "build-deadbeef.json"
            metadata_path.parent.mkdir()
            logd_path = root / "diagnostic" / "build-deadbeef.logd"
            metadata_path.write_text(
                json.dumps({"diagnostic_logd": "diagnostic/build-deadbeef.logd"}),
                encoding="utf-8",
            )

            ok, message = build.validate_diagnostic_artifact_pair(metadata_path, root=root)
            self.assertFalse(ok)
            self.assertIn("missing", message.lower())

            other = root / "diagnostic" / "build-other.logd"
            other.write_bytes(b"not the referenced artifact")
            ok, message = build.validate_diagnostic_artifact_pair(metadata_path, root=root)
            self.assertFalse(ok)
            self.assertIn("missing diagnostic/build-deadbeef.logd", message)

            logd_path.write_bytes(b"encrypted diagnostic")
            ok, message = build.validate_diagnostic_artifact_pair(metadata_path, root=root)
            self.assertTrue(ok, message)
            self.assertIn("matched", message)

    def test_logd_pairing_validation_reports_missing_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_json = Path(tmp) / "diagnostic" / "build-deadbeef.json"
            ok, message = build.validate_diagnostic_artifact_pair(missing_json, root=Path(tmp))
            self.assertFalse(ok)
            self.assertIn("metadata JSON missing", message)


if __name__ == "__main__":
    unittest.main()
