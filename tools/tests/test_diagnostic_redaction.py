"""Regression tests for diagnostic metadata redaction."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
import sys

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from diagnostic_redaction import (  # noqa: E402
    repo_relative_posix,
    sanitize_metadata,
    validate_diagnostic_bundle,
    validate_metadata_redaction,
)


class DiagnosticRedactionTests(unittest.TestCase):
    def test_repo_relative_posix_uses_forward_slashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "compliance" / "build"
            nested.mkdir(parents=True)
            value = repo_relative_posix(str(nested), root)
            self.assertEqual(value, "compliance/build")

    def test_sanitize_metadata_normalizes_logd_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = {
                "diagnostic_logd": ["diagnostic\\build-abcd1234-part001.logd"],
                "decrypt_command": "encryptly unpack diagnostic\\build-abcd1234.logd <outdir>",
                "modules": [{"name": "compliance", "artifact": str(root / "compliance" / "build")}],
            }
            cleaned = sanitize_metadata(metadata, root)
            self.assertEqual(cleaned["diagnostic_logd"], ["diagnostic/build-abcd1234-part001.logd"])
            self.assertEqual(cleaned["modules"][0]["artifact"], "compliance/build")
            validate_metadata_redaction(cleaned, root)

    def test_validate_bundle_requires_metadata_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "diagnostic" / "build-deadbeef-metadata.json"
            with self.assertRaises(FileNotFoundError):
                validate_diagnostic_bundle(missing, root)

    def test_validate_bundle_requires_matching_logd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diag = root / "diagnostic"
            diag.mkdir()
            metadata_path = diag / "build-deadbeef-metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "diagnostic_logd": ["diagnostic/build-deadbeef.logd"],
                        "modules": [{"artifact": "compliance/build"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(FileNotFoundError):
                validate_diagnostic_bundle(metadata_path, root)

    def test_validate_bundle_accepts_matching_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diag = root / "diagnostic"
            diag.mkdir()
            logd = diag / "build-deadbeef.logd"
            logd.write_text("encrypted-stub", encoding="utf-8")
            metadata_path = diag / "build-deadbeef-metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "diagnostic_logd": "diagnostic/build-deadbeef.logd",
                        "modules": [{"artifact": "compliance/build"}],
                    }
                ),
                encoding="utf-8",
            )
            validate_diagnostic_bundle(metadata_path, root)

    def test_validate_bundle_rejects_backslash_logd_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diag = root / "diagnostic"
            diag.mkdir()
            bad = diag / "build-deadbeef-part001.logd"
            bad.write_text("encrypted-stub", encoding="utf-8")
            metadata_path = diag / "build-deadbeef-metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "diagnostic_logd": ["diagnostic\\build-deadbeef-part001.logd"],
                        "modules": [{"artifact": "compliance/build"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                validate_diagnostic_bundle(metadata_path, root)


if __name__ == "__main__":
    unittest.main()
