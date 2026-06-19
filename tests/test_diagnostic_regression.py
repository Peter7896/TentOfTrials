import importlib.util
import json
import os
import tempfile
import unittest
import time
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_PY = REPO_ROOT / "build.py"

spec = importlib.util.spec_from_file_location("build", BUILD_PY)
build = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(build)


class DiagnosticRedactionTests(unittest.TestCase):
    def test_metadata_paths_are_repo_relative_and_sensitive_values_are_redacted(self):
        output = "\n".join(
            [
                f"repo={build.ROOT}",
                f"home={Path.home()}",
                f"temp={tempfile.gettempdir()}",
                f"machine={build.platform.node()}",
                f"user={build.getpass.getuser()}",
            ]
        )
        artifact = build.ROOT / "backend" / "target" / "debug" / "backend"

        report = build.build_diagnostic_report(
            [("backend", True, 1.25, output, str(artifact))],
            "deadbeef",
            logd_relpaths=["diagnostic/build-deadbeef.logd"],
            password="test-password",
        )

        self.assertEqual(report["diagnostic_logd"], "diagnostic/build-deadbeef.logd")
        self.assertEqual(
            build.repo_relative_path(r"diagnostic\build-deadbeef.logd"),
            "diagnostic/build-deadbeef.logd",
        )
        self.assertEqual(
            report["decrypt_command"],
            "encryptly unpack diagnostic/build-deadbeef.logd <outdir> --password test-password",
        )
        self.assertEqual(report["modules"][0]["artifact"], "backend/target/debug/backend")

        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn(str(build.ROOT), encoded)
        self.assertNotIn(str(build.ROOT).replace("\\", "/"), encoded)
        self.assertNotIn(str(Path.home()), encoded)
        self.assertNotIn(str(Path.home()).replace("\\", "/"), encoded)
        self.assertNotIn(tempfile.gettempdir(), encoded)
        self.assertNotIn(build.platform.node(), encoded)
        self.assertNotIn(build.getpass.getuser(), encoded)

    def test_chunked_decrypt_command_uses_forward_slash_paths(self):
        report = build.build_diagnostic_report(
            [("backend", True, 1.25, "", None)],
            "deadbeef",
            logd_relpaths=[
                r"diagnostic\build-deadbeef-part001.logd",
                r"diagnostic\build-deadbeef-part002.logd",
            ],
            password="test-password",
            chunked=True,
        )

        self.assertEqual(
            report["diagnostic_logd"],
            [
                "diagnostic/build-deadbeef-part001.logd",
                "diagnostic/build-deadbeef-part002.logd",
            ],
        )
        self.assertEqual(
            report["decrypt_command"],
            "encryptly unpack diagnostic/build-deadbeef.logd <outdir> --password test-password",
        )
        self.assertNotIn("\\", json.dumps(report, sort_keys=True))

    def test_logd_reference_must_match_generated_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_dir = root / "diagnostic"
            diagnostic_dir.mkdir()
            metadata_path = diagnostic_dir / "build-deadbeef.json"
            logd_path = diagnostic_dir / "build-deadbeef.logd"
            logd_path.write_bytes(b"logd")
            metadata_path.write_text(
                json.dumps({"diagnostic_logd": "diagnostic/build-deadbeef.logd"}),
                encoding="utf-8",
            )

            with patched_diagnostic_root(root, diagnostic_dir):
                build.validate_diagnostic_pair(metadata_path, expected_logd_paths=[logd_path])

    def test_missing_json_fails_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_dir = root / "diagnostic"
            metadata_path = diagnostic_dir / "missing.json"

            with patched_diagnostic_root(root, diagnostic_dir):
                with self.assertRaisesRegex(build.DiagnosticValidationError, "metadata JSON missing"):
                    build.validate_diagnostic_pair(metadata_path)

    def test_missing_logd_fails_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_dir = root / "diagnostic"
            diagnostic_dir.mkdir()
            metadata_path = diagnostic_dir / "build-deadbeef.json"
            metadata_path.write_text(
                json.dumps({"diagnostic_logd": "diagnostic/build-deadbeef.logd"}),
                encoding="utf-8",
            )

            with patched_diagnostic_root(root, diagnostic_dir):
                with self.assertRaisesRegex(build.DiagnosticValidationError, "diagnostic \\.logd missing"):
                    build.validate_diagnostic_pair(metadata_path)

    def test_mismatched_logd_reference_fails_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_dir = root / "diagnostic"
            diagnostic_dir.mkdir()
            metadata_path = diagnostic_dir / "build-deadbeef.json"
            actual_logd = diagnostic_dir / "build-deadbeef.logd"
            expected_logd = diagnostic_dir / "build-cafebabe.logd"
            actual_logd.write_bytes(b"logd")
            expected_logd.write_bytes(b"logd")
            metadata_path.write_text(
                json.dumps({"diagnostic_logd": "diagnostic/build-deadbeef.logd"}),
                encoding="utf-8",
            )

            with patched_diagnostic_root(root, diagnostic_dir):
                with self.assertRaisesRegex(build.DiagnosticValidationError, "diagnostic_logd mismatch"):
                    build.validate_diagnostic_pair(metadata_path, expected_logd_paths=[expected_logd])

    def test_non_utf8_output_uses_ascii_fallbacks(self):
        fake_stdout = FakeStdout("gbk")
        with mock.patch.object(build.sys, "stdout", fake_stdout):
            warning = build.safe_text(
                "\u26a0 Some tools missing  -  will try anyway:",
                "WARNING Some tools missing  -  will try anyway:",
            )
            status = build.mark("\u2713", "+")
            separator = build.rule(8)

        warning.encode("gbk")
        status.encode("gbk")
        separator.encode("gbk")
        self.assertEqual(warning, "WARNING Some tools missing  -  will try anyway:")
        self.assertEqual(status, "+")
        self.assertEqual(separator, "--------")

    def test_frontend_npm_install_missing_returns_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = build.Module(
                name="frontend",
                language="TypeScript",
                dir=Path(tmp),
                build_cmd=["npm", "run", "build"],
                clean_cmd=[],
            )

            def fake_run(*args, **kwargs):
                raise FileNotFoundError("npm")

            with mock.patch.object(build.subprocess, "run", side_effect=fake_run):
                with mock.patch.object(time, "time", side_effect=[100.0, 101.25]):
                    success, elapsed, output = build.build_module(module)

        self.assertFalse(success)
        self.assertEqual(elapsed, 1.25)
        self.assertIn("npm install command not found", output)

    def test_engine_cmake_missing_returns_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = build.Module(
                name="engine",
                language="C++",
                dir=Path(tmp),
                build_cmd=["cmake", "--build", "build"],
                clean_cmd=[],
            )

            def fake_run(*args, **kwargs):
                raise FileNotFoundError("cmake")

            with mock.patch.object(build.subprocess, "run", side_effect=fake_run):
                with mock.patch.object(time, "time", side_effect=[200.0, 202.5]):
                    success, elapsed, output = build.build_module(module)

        self.assertFalse(success)
        self.assertEqual(elapsed, 2.5)
        self.assertIn("CMake configure command not found", output)


def patched_diagnostic_root(root: Path, diagnostic_dir: Path):
    return mock.patch.multiple(build, ROOT=root, DIAGNOSTIC_DIR=diagnostic_dir)


class FakeStdout:
    def __init__(self, encoding: str):
        self.encoding = encoding

    def isatty(self):
        return False


if __name__ == "__main__":
    unittest.main()
