"""Offline regression fixtures; these bytes never assert real encryption."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build


class PairContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repo"
        self.diag = self.root / "diagnostic"
        self.diag.mkdir(parents=True)
        self.metadata = self.diag / "build-cafebabe.json"
        guard = patch.object(build.subprocess, "run", side_effect=AssertionError("offline tests only"))
        guard.start()
        self.addCleanup(guard.stop)

    def bundle(self, names, commit="cafebabe", chunked=False, metadata=None):
        metadata = metadata or self.metadata
        for name in names:
            (self.root / name).write_bytes(b"SYNTHETIC CONTRACT FIXTURE, NOT ENCRYPTED")
        metadata.write_text(json.dumps({"commit": commit, "diagnostic_logd": names,
                                        "chunked": chunked}), encoding="utf-8")
        return metadata

    def test_rejects_explicit_commit_mismatch(self):
        self.bundle(["diagnostic/build-cafebabe.logd"], commit="deadbeef")
        with self.assertRaisesRegex(ValueError, "commit"):
            build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_rejects_gaps_and_reversed_chunks(self):
        for indexes in ((1, 3), (2, 1)):
            with self.subTest(indexes=indexes):
                for artifact in self.diag.glob("*.logd"):
                    artifact.unlink()
                names = [f"diagnostic/build-cafebabe-part{i:03d}.logd" for i in indexes]
                self.bundle(names, chunked=True)
                with self.assertRaisesRegex(ValueError, "sequence"):
                    build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_accepts_ordered_chunks_including_single_chunk(self):
        for count in (1, 2):
            with self.subTest(count=count):
                for artifact in self.diag.glob("*.logd"):
                    artifact.unlink()
                names = [f"diagnostic/build-cafebabe-part{i:03d}.logd" for i in range(1, count + 1)]
                self.bundle(names, chunked=True)
                self.assertEqual([str((self.root / n).resolve()) for n in names],
                                 [str(p) for p in build.validate_diagnostic_artifact_pair(self.metadata, self.root)])

    def test_rejects_pair_outside_diagnostic_directory(self):
        metadata = self.root / "build-cafebabe.json"
        self.bundle(["build-cafebabe.logd"], metadata=metadata)
        with self.assertRaisesRegex(ValueError, "diagnostic"):
            build.validate_diagnostic_artifact_pair(metadata, self.root)

    def test_rejects_non_commit_metadata_filename(self):
        metadata = self.diag / "build-not-a-commit.json"
        self.bundle(["diagnostic/build-not-a-commit.logd"], metadata=metadata)
        with self.assertRaisesRegex(ValueError, "filename"):
            build.validate_diagnostic_artifact_pair(metadata, self.root)

    def test_rejects_symbolic_link_artifact_outside_diagnostic(self):
        outside = self.root / "outside.logd"
        outside.write_bytes(b"SYNTHETIC")
        artifact = self.diag / "build-cafebabe.logd"
        try:
            artifact.symlink_to(outside)
        except OSError:
            self.skipTest("symlinks unavailable")
        self.metadata.write_text(json.dumps({"commit": "cafebabe",
            "diagnostic_logd": "diagnostic/build-cafebabe.logd"}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "diagnostic"):
            build.validate_diagnostic_artifact_pair(self.metadata, self.root)

    def test_rejects_same_directory_symlinks_that_alias_another_commit(self):
        for link_metadata in (False, True):
            with self.subTest(link_metadata=link_metadata):
                for path in self.diag.iterdir():
                    path.unlink()
                report = json.dumps({"commit": "cafebabe", "diagnostic_logd":
                                     "diagnostic/build-cafebabe.logd"})
                artifact = self.diag / "build-cafebabe.logd"
                target = self.diag / ("build-deadbeef.json" if link_metadata else "build-deadbeef.logd")
                target.write_text(report if link_metadata else "SYNTHETIC OTHER COMMIT", encoding="utf-8")
                try:
                    if link_metadata:
                        self.metadata.symlink_to(target)
                        artifact.write_bytes(b"SYNTHETIC")
                    else:
                        self.metadata.write_text(report, encoding="utf-8")
                        artifact.symlink_to(target)
                except OSError:
                    self.skipTest("symlinks unavailable")
                with self.assertRaisesRegex(ValueError, "symbolic link"):
                    build.validate_diagnostic_artifact_pair(self.metadata, self.root)


class RedactionAliasTests(unittest.TestCase):
    def test_redacts_lexical_and_resolved_root_in_both_slash_styles(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real repo"
            alias = Path(directory) / "alias repo"
            real.mkdir()
            try:
                alias.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symlinks unavailable")
            with patch.object(build.Path, "home", return_value=Path(directory) / "home"), \
                    patch.object(build.tempfile, "gettempdir", return_value=str(Path(directory) / "temp")), \
                    patch.object(build.getpass, "getuser", return_value="fixture-user"), \
                    patch.object(build.platform, "node", return_value="fixture-host"):
                for base in (alias, alias.resolve()):
                    for raw in (str(base / "build.log"), str(base / "build.log").replace("/", "\\")):
                        with self.subTest(raw=raw):
                            redacted = build.redact_diagnostic_text(raw, alias)
                            self.assertIn("<REPO>", redacted)
                            self.assertNotIn("alias repo", redacted)
                            self.assertNotIn("real repo", redacted)


if __name__ == "__main__":
    unittest.main()
