#!/usr/bin/env python3
"""Regression tests for diagnostic redaction, artifact pairing, and path reporting."""

import getpass
import json
import platform
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import build


class TestDiagnosticPathHelpers(unittest.TestCase):
  def test_encryptly_failure_message_hides_password_stdout(self):
    message = build.encryptly_failure_message("", "4d944e71565e39788edc", "encryptly pack failed")
    self.assertEqual(message, "encryptly pack failed")

  def test_repo_relative_path_uses_forward_slashes(self):
    artifact = build.diagnostic_repo_relpath(build.ROOT / "backend" / "target" / "backend")
    self.assertEqual(artifact, "backend/target/backend")
    self.assertNotIn("\\", artifact)

  def test_absolute_repo_path_becomes_relative(self):
    artifact = build.sanitize_diagnostic_artifact_path(str(build.ROOT / "market" / "market"))
    self.assertEqual(artifact, "market/market")

  def test_outside_repo_path_is_redacted(self):
    outside = str(Path.home() / "outside" / "binary")
    artifact = build.sanitize_diagnostic_artifact_path(outside)
    self.assertEqual(artifact, build.DIAGNOSTIC_REDACTED_PATH + "/outside/binary")


class TestDiagnosticRedaction(unittest.TestCase):
  def test_redacts_home_repo_temp_user_and_host(self):
    home = str(Path.home())
    repo = str(build.ROOT)
    tmp = tempfile.gettempdir()
    username = getpass.getuser()
    hostname = platform.node()
    raw = f"home={home} repo={repo} tmp={tmp} user={username} host={hostname}"
    redacted = build.redact_diagnostic_text(raw)

    self.assertNotIn(home, redacted)
    self.assertNotIn(repo, redacted)
    if tmp and tmp != "/tmp":
      self.assertNotIn(tmp, redacted)
    if username and len(username) > 1:
      self.assertNotIn(username, redacted)
    if hostname and len(hostname) > 1:
      self.assertNotIn(hostname, redacted)
    self.assertIn(build.DIAGNOSTIC_REDACTED_PATH, redacted)
    self.assertIn(build.DIAGNOSTIC_REDACTED_USER, redacted)
    self.assertIn(build.DIAGNOSTIC_REDACTED_HOST, redacted)

  def test_build_report_metadata_has_no_local_identifiers(self):
    home = str(Path.home())
    username = getpass.getuser()
    hostname = platform.node()
    binary = str(build.ROOT / "backend" / "target" / "debug" / "backend")
    output = (
      f"Compiling in {home}\n"
      f"Built for {username}@{hostname}\n"
      f"artifact at {binary}"
    )
    results = [("backend", True, 1.0, output, binary)]
    report = build.build_diagnostic_report(
      results,
      commit_id="abc12345",
      logd_relpaths=["diagnostic/build-abc12345.logd"],
      password="test-password",
    )
    report_json = json.dumps(report)

    if home and home != "/":
      self.assertNotIn(home, report_json)
    if username and len(username) > 1:
      self.assertNotIn(username, report_json)
    if hostname and len(hostname) > 1:
      self.assertNotIn(hostname, report_json)
    self.assertEqual(report["modules"][0]["artifact"], "backend/target/debug/backend")
    self.assertNotIn("\\", report["modules"][0]["artifact"] or "")


class TestDiagnosticArtifactPairing(unittest.TestCase):
  def setUp(self):
    self.temp_dir = tempfile.TemporaryDirectory()
    self.root = Path(self.temp_dir.name)
    self.diagnostic_dir = self.root / "diagnostic"
    self.diagnostic_dir.mkdir()

  def tearDown(self):
    self.temp_dir.cleanup()

  def _write_pair(self, commit_id: str, *, include_logd: bool = True) -> Path:
    metadata_path = self.diagnostic_dir / f"build-{commit_id}.json"
    logd_path = self.diagnostic_dir / f"build-{commit_id}.logd"
    if include_logd:
      logd_path.write_bytes(b"encrypted-diagnostic")
    report = build.build_diagnostic_report(
      [("backend", True, 1.0, "ok", None)],
      commit_id=commit_id,
      logd_relpaths=[f"diagnostic/build-{commit_id}.logd"] if include_logd else None,
      password="pw" if include_logd else None,
      logd_error=None if include_logd else "encryptly unavailable",
    )
    metadata_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return metadata_path

  def test_validate_pair_succeeds(self):
    metadata_path = self._write_pair("abc12345")
    report = build.validate_diagnostic_artifact_pair(self.root, metadata_path)
    self.assertEqual(report["commit"], "abc12345")

  def test_missing_json_fails_clearly(self):
    metadata_path = self.diagnostic_dir / "build-missing.json"
    with self.assertRaises(build.DiagnosticArtifactError) as ctx:
      build.validate_diagnostic_artifact_pair(self.root, metadata_path)
    self.assertIn("missing", str(ctx.exception).lower())

  def test_missing_logd_fails_clearly(self):
    metadata_path = self._write_pair("abc12345", include_logd=False)
    report = build.build_diagnostic_report(
      [("backend", True, 1.0, "ok", None)],
      commit_id="abc12345",
      logd_relpaths=["diagnostic/build-abc12345.logd"],
      password="pw",
    )
    metadata_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with self.assertRaises(build.DiagnosticArtifactError) as ctx:
      build.validate_diagnostic_artifact_pair(self.root, metadata_path)
    self.assertIn("missing", str(ctx.exception).lower())

  def test_mismatched_commit_pair_fails_clearly(self):
    metadata_path = self._write_pair("abc12345")
    other_logd = self.diagnostic_dir / "build-other000.logd"
    other_logd.write_bytes(b"encrypted-diagnostic")
    report = json.loads(metadata_path.read_text(encoding="utf-8"))
    report["diagnostic_logd"] = "diagnostic/build-other000.logd"
    metadata_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with self.assertRaises(build.DiagnosticArtifactError) as ctx:
      build.validate_diagnostic_artifact_pair(self.root, metadata_path)
    self.assertIn("does not pair", str(ctx.exception).lower())

  def test_backslash_logd_reference_fails_clearly(self):
    metadata_path = self._write_pair("abc12345")
    report = json.loads(metadata_path.read_text(encoding="utf-8"))
    report["diagnostic_logd"] = "diagnostic\\build-abc12345.logd"
    metadata_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with self.assertRaises(build.DiagnosticArtifactError) as ctx:
      build.validate_diagnostic_artifact_pair(self.root, metadata_path)
    self.assertIn("forward-slash", str(ctx.exception).lower())


class TestDiagnosticReportShape(unittest.TestCase):
  def test_chunked_logd_paths_are_repo_relative(self):
    report = build.build_diagnostic_report(
      [("backend", True, 1.0, "", None)],
      commit_id="abc12345",
      logd_relpaths=[
        "diagnostic/build-abc12345-part001.logd",
        "diagnostic/build-abc12345-part002.logd",
      ],
      password="pw",
      chunked=True,
    )
    self.assertIsInstance(report["diagnostic_logd"], list)
    for ref in report["diagnostic_logd"]:
      self.assertTrue(ref.startswith("diagnostic/"))
      self.assertNotIn("\\", ref)

  def test_error_only_report_allows_missing_logd(self):
    metadata_dir = build.DIAGNOSTIC_DIR
    metadata_dir.mkdir(parents=True, exist_ok=True)
    commit_id = "erroronly"
    metadata_path = metadata_dir / f"build-{commit_id}.json"
    report = build.build_diagnostic_report(
      [("encryptly-preflight", False, 0.1, "blocked", None)],
      commit_id=commit_id,
      logd_error="encryptly unavailable",
      message_blocker=build.ENCRYPTLY_BLOCKER_MESSAGE,
    )
    metadata_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    validated = build.validate_diagnostic_artifact_pair(
      build.ROOT,
      metadata_path,
      require_logd=False,
    )
    self.assertIsNone(validated["diagnostic_logd"])
    metadata_path.unlink(missing_ok=True)


class TestStubDiagnosticArtifacts(unittest.TestCase):
  def test_stub_pair_is_valid(self):
    metadata_path = build.DIAGNOSTIC_DIR / "build-00000000.json"
    if not metadata_path.exists():
      self.skipTest("stub diagnostic metadata is not present")
    report = build.validate_diagnostic_artifact_pair(build.ROOT, metadata_path)
    self.assertEqual(report["diagnostic_logd"], "diagnostic/build-00000000.logd")


if __name__ == "__main__":
  unittest.main()
