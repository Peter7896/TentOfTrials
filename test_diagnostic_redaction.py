"""Offline contract checks; synthetic fixture bytes do not prove encryption.

Pairing cases extend Krusheek's PR #36 and the contract covered in PR #35.
Declared commit provenance is checked; a real build remains a separate gate.
"""

import json
import re
import unittest
import tempfile
import getpass
import platform
from pathlib import Path
from build import build_diagnostic_report, ROOT, Module, verify_binary

class TestDiagnosticRedaction(unittest.TestCase):
    def test_artifact_path_normalization(self):
        # Create a mock module that has an absolute path for build_dir
        # We need to test verify_binary actually converts this to a repo-relative path
        test_dir = ROOT / "test_module_dir"
        test_dir.mkdir(exist_ok=True)
        
        m = Module(
            name="test_module",
            language="Python",
            dir=ROOT,
            build_cmd=[],
            clean_cmd=[],
            build_dir=test_dir
        )
        
        # Verify it uses posix slashes even on Windows
        artifact_path = verify_binary(m)
        self.assertEqual(artifact_path, "test_module_dir")
            
        # Clean up
        test_dir.rmdir()

    def test_report_redaction(self):
        # Mock results
        # tuple: (name, success, elapsed, output, binary)
        mock_results = [
            ("backend", True, 1.5, "Some output with my username " + getpass.getuser(), "backend/target/debug/backend"),
            ("frontend", False, 0.5, "Failed in " + str(ROOT), None)
        ]
        
        report = build_diagnostic_report(
            results=mock_results,
            commit_id="abcdef12",
            logd_relpaths=["diagnostic/build-abcdef12.logd"],
            password="test_password",
            chunked=False
        )
        
        raw_json = json.dumps(report)
        
        # Paths that shouldn't appear
        leaks = [
            str(ROOT.parent), # The parent directory, revealing home structure
            Path.home().as_posix(),
            str(Path.home()),
            tempfile.gettempdir(),
            tempfile.gettempdir().replace("\\", "/"),
            getpass.getuser(),
        ]
        
        # It's okay if "backend" or "frontend" or "diagnostic" appears, 
        # but the absolute local path to ROOT shouldn't.
        # Actually, ROOT itself might not be a leak if it's just the folder name,
        # but the parent path definitely is.
        root_parent = str(ROOT.parent)
        if root_parent and root_parent != "/" and root_parent != "\\":
            self.assertNotIn(root_parent, raw_json)
            self.assertNotIn(root_parent.replace("\\", "/"), raw_json)
            
        for leak in leaks:
            if not leak or leak in ["/", "\\", "C:\\", "C:/"]:
                continue
            self.assertNotIn(leak, raw_json, f"Sensitive info leaked: {leak}")

    def test_mismatched_pair(self):
        # The wrong-commit artifact exists: checking only existence is not enough.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            diagnostic = root / "diagnostic"
            diagnostic.mkdir()
            metadata = diagnostic / "build-12345678.json"
            wrong = "diagnostic/build-deadbeef.logd"
            (root / wrong).write_bytes(b"SYNTHETIC FIXTURE, NOT ENCRYPTED")
            metadata.write_text(json.dumps({"commit": "12345678", "diagnostic_logd": wrong}))
            with self.assertRaisesRegex(AssertionError, "mismatch"):
                check_pair(metadata, diagnostic)

def check_pair(json_path: Path, logd_dir: Path, *, expected_commit=None):
    """Check a declared commit's metadata and files, without asserting encryption.

    Callers validating a particular source revision can supply its short or full
    commit ID. Without it, this checks the metadata/file contract only.
    """
    diagnostic = logd_dir.parent.resolve() / "diagnostic"
    if logd_dir.name != "diagnostic" or logd_dir.resolve() != diagnostic:
        raise AssertionError("Diagnostic directory is outside the repository's diagnostic/")
    if json_path.resolve().parent != diagnostic:
        raise AssertionError("JSON is outside diagnostic/")
    if not json_path.is_file():
        raise AssertionError("JSON missing or not a file")
    match = re.fullmatch(r"build-([0-9a-f]{8})\.json", json_path.name)
    if not match:
        raise AssertionError("JSON filename must contain an 8-character commit")
    commit = match.group(1)
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AssertionError("JSON is unreadable or invalid") from error
    if not isinstance(data, dict):
        raise AssertionError("JSON must contain an object")
    if data.get("commit") != commit:
        raise AssertionError("Metadata commit mismatch with JSON filename")
    if expected_commit is not None:
        if (not isinstance(expected_commit, str)
                or not re.fullmatch(r"[0-9a-f]{8}(?:[0-9a-f]{32})?", expected_commit)
                or expected_commit[:8] != commit):
            raise AssertionError("Metadata does not match the required source commit")

    references = data.get("diagnostic_logd")
    if isinstance(references, str):
        references = [references]
    if (not isinstance(references, list) or not references
            or any(not isinstance(name, str) or not name for name in references)):
        raise AssertionError("Missing or invalid diagnostic_logd references")
    if len(references) != len(set(references)):
        raise AssertionError("Duplicate diagnostic_logd references")

    stem = f"build-{commit}"
    single = [f"diagnostic/{stem}.logd"]
    parts = [f"diagnostic/{stem}-part{index:03d}.logd"
             for index in range(1, len(references) + 1)]
    if references != single and references != parts:
        raise AssertionError("Artifact mismatch: expected matching ordered files inside diagnostic/")
    split = references != single
    if data.get("chunked", False) is not split:
        raise AssertionError("Artifact chunked flag mismatch")
    for name in references:
        artifact = diagnostic / Path(name).name
        if artifact.resolve().parent != diagnostic:
            raise AssertionError("Artifact is outside diagnostic/")
        if not artifact.is_file():
            raise AssertionError("Diagnostic artifact missing or not a file")
        if artifact.stat().st_size == 0:
            raise AssertionError("Diagnostic artifact is empty")
    actual = {f"diagnostic/{path.name}" for path in diagnostic.glob(f"{stem}*.logd")}
    if actual != set(references):
        raise AssertionError("Artifact set mismatch: unreferenced or missing files")

class TestPairing(unittest.TestCase):
    def test_valid_pair(self):
        # We can just verify the logic of our check_pair function
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            diag_dir = td / "diagnostic"
            diag_dir.mkdir()
            
            json_file = diag_dir / "build-12345678.json"
            logd_file = diag_dir / "build-12345678.logd"
            
            logd_file.write_bytes(b"SYNTHETIC FIXTURE, NOT ENCRYPTED")
            json_file.write_text(json.dumps({
                "commit": "12345678",
                "diagnostic_logd": "diagnostic/build-12345678.logd"
            }))
            
            # Should pass
            check_pair(json_file, diag_dir)
            
            # Now test missing logd
            logd_file.unlink()
            with self.assertRaises(AssertionError):
                check_pair(json_file, diag_dir)

class TestPairingBoundaries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.root = self.workspace / "repo"
        self.diagnostic = self.root / "diagnostic"
        self.diagnostic.mkdir(parents=True)
        self.metadata = self.diagnostic / "build-12345678.json"
        self.reference = "diagnostic/build-12345678.logd"

    def report(self, reference=None, **fields):
        data = {"commit": "12345678", "diagnostic_logd": reference or self.reference}
        data.update(fields)
        self.metadata.write_text(json.dumps(data), encoding="utf-8")

    def artifact(self, reference=None):
        artifact = self.root / (reference or self.reference)
        artifact.write_bytes(b"SYNTHETIC TEST FIXTURE, NOT ENCRYPTED")
        return artifact

    def check(self, **kwargs):
        return check_pair(self.metadata, self.diagnostic, **kwargs)

    def test_missing_json(self):
        with self.assertRaisesRegex(AssertionError, "JSON missing"):
            self.check()

    def test_invalid_json_and_nonobject_report(self):
        for text in ("{broken", "[]", "null", '"text"'):
            with self.subTest(text=text):
                self.metadata.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(AssertionError, "JSON"):
                    self.check()

    def test_metadata_commit_must_match_filename(self):
        self.artifact()
        for commit in (None, "deadbeef", "123", 12345678):
            with self.subTest(commit=commit):
                self.report(commit=commit)
                with self.assertRaisesRegex(AssertionError, "commit"):
                    self.check()

    def test_source_commit_can_be_required_by_caller(self):
        self.artifact()
        self.report()
        self.check(expected_commit="12345678" + "a" * 32)
        with self.assertRaisesRegex(AssertionError, "source commit"):
            self.check(expected_commit="deadbeef")

    def test_invalid_or_duplicate_references(self):
        self.artifact()
        for value in (None, [], "", 123, [None], [self.reference, self.reference]):
            with self.subTest(value=value):
                self.report(diagnostic_logd=value)
                with self.assertRaises(AssertionError):
                    self.check()

    def test_paths_must_be_directly_inside_diagnostic(self):
        self.artifact()
        outside = self.root / "build-12345678.logd"
        outside.write_bytes(b"SYNTHETIC OUTSIDE FIXTURE")
        for value in (outside.name, str(outside), "../build-12345678.logd",
                      "diagnostic/../build-12345678.logd", "C:/diagnostic/build-12345678.logd",
                      r"diagnostic\build-12345678.logd", "diagnostic//build-12345678.logd"):
            with self.subTest(value=value):
                self.report(diagnostic_logd=value)
                with self.assertRaises(AssertionError):
                    self.check()

    def test_empty_or_directory_artifact(self):
        self.report()
        artifact = self.root / self.reference
        artifact.touch()
        with self.assertRaises(AssertionError):
            self.check()
        artifact.unlink()
        artifact.mkdir()
        with self.assertRaises(AssertionError):
            self.check()

    def test_artifact_symlink_cannot_escape_diagnostic(self):
        self.report()
        outside = self.root / "outside.logd"
        outside.write_bytes(b"SYNTHETIC OUTSIDE FIXTURE")
        try:
            (self.root / self.reference).symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable")
        with self.assertRaisesRegex(AssertionError, "outside"):
            self.check()

    def test_metadata_must_be_inside_diagnostic(self):
        self.artifact()
        self.report()
        outside = self.root / self.metadata.name
        self.metadata.rename(outside)
        with self.assertRaisesRegex(AssertionError, "outside"):
            check_pair(outside, self.diagnostic)

    def test_metadata_symlink_cannot_escape_diagnostic(self):
        self.artifact()
        self.report()
        outside = self.workspace / self.metadata.name
        self.metadata.rename(outside)
        try:
            self.metadata.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable")
        with self.assertRaisesRegex(AssertionError, "outside"):
            self.check()

    def test_diagnostic_directory_cannot_be_symlink(self):
        elsewhere = self.workspace / "elsewhere"
        self.diagnostic.rename(elsewhere)
        try:
            self.diagnostic.symlink_to(elsewhere, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable")
        self.artifact()
        self.report()
        with self.assertRaisesRegex(AssertionError, "outside"):
            self.check()

    def test_split_pair_is_complete_ordered_and_matches_chunked_flag(self):
        parts = [f"diagnostic/build-12345678-part{i:03d}.logd" for i in (1, 2)]
        for part in parts:
            self.artifact(part)
        self.report(parts, chunked=True)
        self.check()
        for value in (parts[::-1], parts[1:]):
            with self.subTest(parts=value):
                self.report(value, chunked=True)
                with self.assertRaisesRegex(AssertionError, "mismatch"):
                    self.check()
        self.report(parts, chunked=False)
        with self.assertRaisesRegex(AssertionError, "chunked"):
            self.check()

    def test_split_pair_rejects_gaps(self):
        parts = [f"diagnostic/build-12345678-part{i:03d}.logd" for i in (1, 3)]
        for part in parts:
            self.artifact(part)
        self.report(parts, chunked=True)
        with self.assertRaisesRegex(AssertionError, "mismatch"):
            self.check()

    def test_unreferenced_same_commit_artifact_is_rejected(self):
        self.artifact()
        self.artifact("diagnostic/build-12345678-part001.logd")
        self.report()
        with self.assertRaisesRegex(AssertionError, "mismatch"):
            self.check()


if __name__ == "__main__":
    unittest.main()
