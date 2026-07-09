import getpass
import json
import platform
import tempfile
import unittest
from pathlib import Path

import build


class DiagnosticMetadataTests(unittest.TestCase):
    def test_report_redacts_local_identity_and_normalizes_artifact_paths(self):
        repo_artifact = build.ROOT / "backend" / "target" / "debug" / "backend"
        output = "\n".join(
            [
                f"repo={build.ROOT}",
                f"home={Path.home()}",
                f"temp={tempfile.gettempdir()}",
                f"user={getpass.getuser()}",
                f"host={platform.node()}",
            ]
        )

        report = build.build_diagnostic_report(
            [("backend", True, 1.234, output, str(repo_artifact))],
            "deadbeef",
            logd_relpaths=["diagnostic/build-deadbeef.logd"],
            password="pw",
        )

        module = report["modules"][0]
        self.assertEqual(module["artifact"], "backend/target/debug/backend")
        self.assertNotIn("\\", module["artifact"])

        encoded = json.dumps(report)
        self.assertNotIn(str(build.ROOT), encoded)
        self.assertNotIn(str(Path.home()), encoded)
        self.assertNotIn(tempfile.gettempdir(), encoded)
        self.assertNotIn(getpass.getuser(), encoded)
        if platform.node():
            self.assertNotIn(platform.node(), encoded)

    def test_validate_diagnostic_metadata_accepts_matching_logd_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_dir = root / "diagnostic"
            diagnostic_dir.mkdir()
            (diagnostic_dir / "build-deadbeef.logd").write_bytes(b"encrypted")
            metadata_path = diagnostic_dir / "build-deadbeef.json"
            metadata_path.write_text(
                json.dumps({"diagnostic_logd": "diagnostic/build-deadbeef.logd"}),
                encoding="utf-8",
            )

            self.assertEqual(build.validate_diagnostic_metadata(metadata_path, root), [])

    def test_validate_diagnostic_metadata_reports_missing_json(self):
        missing = Path(tempfile.gettempdir()) / "does-not-exist-diagnostic.json"

        errors = build.validate_diagnostic_metadata(missing, missing.parent)

        self.assertEqual(len(errors), 1)
        self.assertIn("metadata is missing", errors[0])

    def test_validate_diagnostic_metadata_reports_missing_logd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_dir = root / "diagnostic"
            diagnostic_dir.mkdir()
            metadata_path = diagnostic_dir / "build-deadbeef.json"
            metadata_path.write_text(
                json.dumps({"diagnostic_logd": "diagnostic/build-deadbeef.logd"}),
                encoding="utf-8",
            )

            errors = build.validate_diagnostic_metadata(metadata_path, root)

        self.assertEqual(len(errors), 1)
        self.assertIn(".logd artifact is missing", errors[0])

    def test_validate_diagnostic_metadata_rejects_absolute_or_backslash_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_dir = root / "diagnostic"
            diagnostic_dir.mkdir()
            metadata_path = diagnostic_dir / "build-deadbeef.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "diagnostic_logd": [
                            str(root / "diagnostic" / "build-deadbeef.logd"),
                            "diagnostic\\build-deadbeef.logd",
                        ]
                    }
                ),
                encoding="utf-8",
            )

            errors = build.validate_diagnostic_metadata(metadata_path, root)

        self.assertTrue(any("repository-relative" in error for error in errors))
        self.assertTrue(any("'/' separators" in error for error in errors))

    def test_validate_diagnostic_metadata_rejects_mismatched_artifact_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_dir = root / "diagnostic"
            diagnostic_dir.mkdir()
            (diagnostic_dir / "build-deadbeef.txt").write_text("not logd", encoding="utf-8")
            metadata_path = diagnostic_dir / "build-deadbeef.json"
            metadata_path.write_text(
                json.dumps({"diagnostic_logd": "diagnostic/build-deadbeef.txt"}),
                encoding="utf-8",
            )

            errors = build.validate_diagnostic_metadata(metadata_path, root)

        self.assertEqual(len(errors), 1)
        self.assertIn("not a .logd", errors[0])


if __name__ == "__main__":
    unittest.main()
