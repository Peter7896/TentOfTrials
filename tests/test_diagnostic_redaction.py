import getpass
import json
import platform
import tempfile
import unittest
from pathlib import Path

import build


class DiagnosticRedactionTests(unittest.TestCase):
    def test_report_uses_relative_artifact_paths_and_redacts_local_output(self):
        local_values = [
            str(build.ROOT),
            build.ROOT.as_posix(),
            str(Path.home()),
            Path.home().as_posix(),
            tempfile.gettempdir(),
            getpass.getuser(),
            platform.node(),
        ]
        output = "\n".join(value for value in local_values if value)
        artifact = build.ROOT / "backend" / "target" / "debug" / "backend"

        report = build.build_diagnostic_report(
            [("backend", True, 1.234, output, str(artifact))],
            "12345678",
            logd_relpaths=["diagnostic/build-12345678.logd"],
            password="test-password",
        )

        module = report["modules"][0]
        self.assertEqual(module["artifact"], "backend/target/debug/backend")
        for value in local_values:
            if value:
                self.assertNotIn(value, module["output"])

    def test_metadata_validator_accepts_relative_json_logd_pair(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            diagnostic_dir = root / "diagnostic"
            diagnostic_dir.mkdir()
            logd_path = diagnostic_dir / "build-12345678.logd"
            logd_path.write_bytes(b"encrypted diagnostic placeholder")
            metadata_path = diagnostic_dir / "build-12345678.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "diagnostic_logd": "diagnostic/build-12345678.logd",
                        "modules": [
                            {
                                "name": "backend",
                                "status": "PASS",
                                "artifact": "backend/target/debug/backend",
                                "output": "redacted output",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(build.validate_diagnostic_metadata(metadata_path, root=root), [])

    def test_metadata_validator_reports_missing_json_and_mismatched_logd(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            missing_json = root / "diagnostic" / "missing.json"
            self.assertIn("diagnostic metadata is missing", build.validate_diagnostic_metadata(missing_json, root=root)[0])

            diagnostic_dir = root / "diagnostic"
            diagnostic_dir.mkdir()
            metadata_path = diagnostic_dir / "build-12345678.json"
            metadata_path.write_text(
                json.dumps({"diagnostic_logd": "diagnostic/build-deadbeef.logd", "modules": []}),
                encoding="utf-8",
            )

            errors = build.validate_diagnostic_metadata(metadata_path, root=root)
            self.assertTrue(any("artifact is missing" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
