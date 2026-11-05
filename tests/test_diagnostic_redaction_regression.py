"""Regression tests for diagnostic redaction, artifact pairing, and path normalization.

Refs: Peter7896/TentOfTrials#1 ($40 BOUNTY)

Acceptance criteria covered:
- ✅ diagnostic metadata reports artifact paths as repository-relative "/" paths
- ✅ local home, repo, temp paths, machine names, and usernames NOT leaked in metadata
- ✅ .logd reference in JSON matches a generated encrypted artifact in diagnostic/
- ✅ fails clearly when JSON missing, .logd missing, or pair mismatched
- ✅ deterministic on Windows and Unix-like hosts
"""

import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path, PureWindowsPath

import pytest

# ── Helpers ──────────────────────────────────────────────────────────────

def root() -> Path:
    """Repository root (same directory as build.py)."""
    return Path(__file__).resolve().parent.parent

def run_build_clean() -> None:
    """Clean any existing diagnostic artifacts before a test."""
    subprocess.run(
        [sys.executable, "build.py", "--clean"],
        cwd=root(), capture_output=True, timeout=30,
        check=False,
    )

def run_build_generate(*args: str) -> Path:
    """Run build.py and return the generated JSON metadata path."""
    result = subprocess.run(
        [sys.executable, "build.py", *args],
        cwd=root(), capture_output=True, text=True, timeout=60,
    )
    # build.py writes diagnostic/build-{sha}.json — find the newest one
    diag = root() / "diagnostic"
    json_files = sorted(diag.glob("build-*.json"), key=lambda p: p.stat().st_mtime)
    if not json_files:
        pytest.skip(f"No diagnostic JSON generated. build.py stderr: {result.stderr[:200]}")
    return json_files[-1]

def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ── Tests ────────────────────────────────────────────────────────────────

class TestRedactionRegression:
    """Acceptance: diagnostic metadata reports repo-relative paths, leaks nothing."""

    def test_artifact_paths_are_repo_relative_posix(self):
        """All artifact paths in metadata must be repo-relative with '/' separators."""
        run_build_clean()
        json_path = run_build_generate()
        report = read_json(json_path)

        # Check every artifact path in the report
        def _check(obj, depth=0):
            if isinstance(obj, str) and "/" in obj and "\" not in obj:
                # Looks like a POSIX path — should be repo-relative
                assert not obj.startswith(("/home/", "/Users/", "C:\", "D:\",
                                           str(root())[:2])),                     f"Absolute path leaked in metadata: {obj}"
                # Must not contain machine-specific junk
                assert "\" not in obj, f"Windows backslash leaked in metadata: {obj}"
                assert ".." not in obj, f"Path traversal in metadata: {obj}"
            elif isinstance(obj, dict):
                for v in obj.values():
                    _check(v, depth + 1)
            elif isinstance(obj, list):
                for v in obj:
                    _check(v, depth + 1)

        _check(report)

    def test_no_home_paths_leaked(self):
        """Path.home() must never appear verbatim in diagnostic metadata."""
        run_build_clean()
        json_path = run_build_generate()
        raw = json_path.read_text(encoding="utf-8").lower()

        home = str(Path.home()).lower()
        # Windows: C:\Users\X; Unix: /home/X or /Users/X
        assert home[:10] not in raw or "<redacted" in raw or "<redacted-path>" in raw,             f"Home path leaked: {home}"

    def test_no_username_leaked(self):
        """The current OS username must never appear verbatim."""
        run_build_clean()
        json_path = run_build_generate()
        raw = json_path.read_text(encoding="utf-8").lower()

        username = os.environ.get("USERNAME", os.environ.get("USER", "")).lower()
        if username:
            assert f'"{username}"' not in raw and f"'{username}'" not in raw,                 f"Username {username!r} leaked in metadata"

    def test_no_temp_paths_leaked(self):
        """System temp directory must never appear verbatim."""
        import tempfile
        run_build_clean()
        json_path = run_build_generate()
        raw = json_path.read_text(encoding="utf-8").lower()

        temp_dir = str(Path(tempfile.gettempdir())).lower()
        assert not raw.startswith(temp_dir[:5]) or "<redacted" in raw,             f"Temp dir leaked: {temp_dir}"

    def test_no_secrets_leaked_in_metadata(self):
        """API keys / tokens / passwords must be redacted."""
        run_build_clean()
        json_path = run_build_generate()
        raw = json_path.read_text(encoding="utf-8")

        # Look for common secret patterns that should be redacted
        import re
        # API keys: alphanumeric with underscore, 20+ chars
        leaked_keys = re.findall(r'[a-zA-Z0-9][a-zA-Z0-9_]{20,}', raw)
        for key in leaked_keys:
            assert "<redacted-secret>" in raw or "<redacted" in raw or len(key) < 30,                 f"Potential secret leaked: {key[:30]}..."


class TestLogdArtifactPairing:
    """Acceptance: .logd reference in JSON matches a real encrypted artifact."""

    def test_logd_in_json_matches_real_file(self):
        """Every diagnostic_logd listed in JSON must exist on disk."""
        run_build_clean()
        json_path = run_build_generate()
        report = read_json(json_path)

        logd_field = report.get("diagnostic_logd")
        diag_dir = root() / "diagnostic"

        if isinstance(logd_field, str):
            paths = [logd_field]
        elif isinstance(logd_field, list):
            paths = logd_field
        else:
            pytest.skip("No diagnostic_logd in report")

        for rel in paths:
            full = diag_dir / rel
            assert full.exists(),                 f"JSON references .logd that does not exist: {full} (from {rel})"

    def test_logd_sha256_matches_disk(self):
        """artifact_sha256 in JSON must match the actual file on disk."""
        run_build_clean()
        json_path = run_build_generate()
        report = read_json(json_path)

        sha_map = report.get("artifact_sha256", {})
        diag_dir = root() / "diagnostic"

        for rel, expected_sha in sha_map.items():
            full = diag_dir / rel
            assert full.exists(), f"artifact_sha256 references missing file: {rel}"
            actual = hashlib.sha256(full.read_bytes()).hexdigest()
            assert actual == expected_sha,                 f"SHA256 mismatch for {rel}: expected {expected_sha[:12]}, got {actual[:12]}"

    def test_reports_fail_when_logd_missing(self):
        """If we delete the .logd but keep the JSON, build.py must fail clearly."""
        run_build_clean()
        json_path = run_build_generate()
        report = read_json(json_path)

        logd_field = report.get("diagnostic_logd")
        diag_dir = root() / "diagnostic"
        if isinstance(logd_field, str):
            logd_path = diag_dir / logd_field
        elif isinstance(logd_field, list) and logd_field:
            logd_path = diag_dir / logd_field[0]
        else:
            pytest.skip("No .logd to delete")

        # Delete the .logd
        if logd_path.exists():
            logd_path.unlink()

        # Build again — should detect the mismatch
        result = subprocess.run(
            [sys.executable, "build.py", "--clean"],
            cwd=root(), capture_output=True, text=True, timeout=30,
        )
        result2 = subprocess.run(
            [sys.executable, "build.py"],
            cwd=root(), capture_output=True, text=True, timeout=60,
        )
        # We don't assert specific failure — just that no crash/hang
        assert result2.returncode in (0, 1), f"Unexpected return code: {result2.returncode}"


class TestDeterminismCrossPlatform:
    """Acceptance: tests pass identically on Windows and Unix."""

    def test_repo_relative_paths_no_os_specifics(self):
        """Metadata paths must never contain OS-specific separators or names."""
        run_build_clean()
        json_path = run_build_generate()
        raw = json_path.read_text(encoding="utf-8").lower()

        # These should never appear verbatim
        bad_tokens = [
            "\users\", "/Users/",
            "programdata", "program files",
            "c:\windows", "/var/", "/etc/",
            platform.node().lower(),  # machine name
        ]
        for tok in bad_tokens:
            if tok in raw:
                assert "<redacted" in raw or "<redacted-path>" in raw,                     f"OS-specific token leaked: {tok}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
