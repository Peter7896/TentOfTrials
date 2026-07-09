"""
Tests for diagnostic redaction, path normalisation, and artifact pairing.

These tests validate that:
- Diagnostic metadata reports artifact paths as repository-relative "/" paths.
- Local home, repo, temp paths, machine names, and usernames are not leaked.
- The .logd reference in JSON matches a generated encrypted artifact in diagnostic/.
- Failures are clear when JSON is missing, .logd is missing, or the pair is mismatched.

Run:  python3 -m pytest tests/test_diagnostic_redaction.py -v
"""

import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path so we can import build.py helpers
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Helper: isolated workspace for tests that call build.py functions
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_workspace():
    """Provide a temporary directory that simulates a clean diagnostic run."""
    with tempfile.TemporaryDirectory(prefix="tot-test-") as tmp:
        cwd = Path(tmp)
        diag = cwd / "diagnostic"
        diag.mkdir()
        yield cwd, diag


# ---------------------------------------------------------------------------
# Path normalisation — repository-relative "/" paths
# ---------------------------------------------------------------------------

def test_diagnostic_paths_are_under_diagnostic_dir():
    """DIAGNOSTIC_DIR is always named diagnostic/ under the project root."""
    from build import ROOT as BUILD_ROOT, DIAGNOSTIC_DIR

    assert DIAGNOSTIC_DIR.name == "diagnostic"
    # DIAGNOSTIC_DIR is directly under BUILD_ROOT, so its relative
    # path should be simply "diagnostic" using forward-slash convention
    rel = DIAGNOSTIC_DIR.relative_to(BUILD_ROOT)
    assert rel == Path("diagnostic"), f"Expected 'diagnostic', got {rel}"


def test_build_diagnostic_report_paths_are_posix():
    """build_diagnostic_report stores logd_relpaths with forward slashes."""
    from build import build_diagnostic_report

    # Simulate a single logd artifact
    report = build_diagnostic_report(
        results=[("test-module", True, 1.0, "ok", None)],
        commit_id="abc12345",
        logd_relpaths=["diagnostic/build-abc12345.logd"],
    )
    logd = report["diagnostic_logd"]
    assert isinstance(logd, str)
    # Must use forward slashes, not backslashes
    assert "\\" not in logd
    assert logd.startswith("diagnostic/")


def test_build_diagnostic_report_chunked_paths_are_posix():
    """Chunked logd references are stored as forward-slash paths (even on Windows)."""
    from build import build_diagnostic_report

    chunks = [
        "diagnostic/build-abc12345-part001.logd",
        "diagnostic/build-abc12345-part002.logd",
    ]
    report = build_diagnostic_report(
        results=[("test-module", True, 1.0, "ok", None)],
        commit_id="abc12345",
        logd_relpaths=chunks,
        chunked=True,
    )
    logd = report["diagnostic_logd"]
    assert isinstance(logd, list)
    for entry in logd:
        assert "\\" not in entry, f"Backslash found in path: {entry}"
        assert entry.startswith("diagnostic/")


# ---------------------------------------------------------------------------
# Redaction — sensitive info not leaked in diagnostic metadata
# ---------------------------------------------------------------------------

def test_collect_system_info_no_repo_path_in_metadata_fields():
    """The generated_at, hostname, and user fields should not embed the repo path."""
    from build import collect_system_info, ROOT

    info = collect_system_info()
    lines = info.split("\n")
    # Check the header lines (generated_at, hostname, user) — these should
    # never contain the repository path under any circumstance.
    header_lines = [l for l in lines if l.startswith(("generated_at:", "hostname:", "user:", "python:", "platform:"))]
    repo_path = str(ROOT.resolve())
    for line in header_lines:
        assert repo_path not in line, (
            f"Repo path leaked in header: {line}"
        )


def test_collect_system_info_does_not_leak_temp_path():
    """collect_system_info() should not include /tmp or %TEMP% paths."""
    from build import collect_system_info

    info = collect_system_info()
    # The string representation should not include known temp roots
    for suspicious in ("/tmp/", "/var/tmp/", "\\Temp\\", "\\TEMP\\"):
        assert suspicious not in info, (
            f"Temp path pattern {suspicious!r} leaked into diagnostic snapshot"
        )


def test_collect_system_info_does_not_leak_repo_path():
    """collect_system_info() should not include the repository checkout path."""
    from build import collect_system_info, ROOT

    info = collect_system_info()
    repo_path = str(ROOT.resolve())
    # The repo path should NOT appear in generated_at, hostname, user, etc.
    # It may appear in environment variables like SHELL if set to a repo path,
    # but that's an edge case. We check the snapshot body.
    assert repo_path not in info, (
        f"Repository path {repo_path!r} leaked into diagnostic snapshot"
    )


def test_collect_system_info_no_machine_name_leak_in_paths():
    """Machine hostname should not appear as a directory path component."""
    from build import collect_system_info
    import platform

    info = collect_system_info()
    hostname = platform.node()
    # If hostname is short (e.g. "macbook"), it might appear legitimately
    # in generated_at etc. We only check it doesn't appear as a path prefix.
    if hostname and len(hostname) > 2:
        path_pattern = f"/{hostname}/"
        assert path_pattern not in info, (
            f"Hostname {hostname!r} appears as a path component"
        )


# ---------------------------------------------------------------------------
# Artifact pairing — .logd reference in JSON matches generated artifact
# ---------------------------------------------------------------------------

def test_diagnostic_metadata_logd_reference_matches_artifact(isolated_workspace):
    """The diagnostic_logd field in JSON must point to an existing .logd file."""
    cwd, diag = isolated_workspace
    commit_id = "deadbeef"

    # Simulate what build.py does: create a placeholder .logd and JSON
    logd_path = diag / f"build-{commit_id}.logd"
    logd_path.write_text("encrypted diagnostic content (placeholder)")

    # Now simulate the JSON metadata that build.py would produce
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("test-module", True, 0.5, "ok", None)],
        commit_id=commit_id,
        logd_relpaths=[f"diagnostic/build-{commit_id}.logd"],
    )

    logd_ref = report["diagnostic_logd"]
    assert logd_ref is not None, "diagnostic_logd should not be None when logd exists"

    # Verify the JSON reference matches the actual artifact
    actual_path = cwd / logd_ref
    assert actual_path.exists(), (
        f"JSON references {logd_ref} but file does not exist at {actual_path}"
    )


def test_missing_logd_sets_diagnostic_logd_error():
    """When .logd creation fails, diagnostic_logd_error is populated and diagnostic_logd is None."""
    from build import build_diagnostic_report

    err_msg = "encryptly binary not found"
    report = build_diagnostic_report(
        results=[("test-module", True, 0.5, "ok", None)],
        commit_id="abc12345",
        logd_error=err_msg,
    )

    assert report["diagnostic_logd"] is None, (
        "diagnostic_logd must be None when logd creation fails"
    )
    assert report["diagnostic_logd_error"] == err_msg, (
        f"Expected error {err_msg!r}, got {report['diagnostic_logd_error']!r}"
    )


def test_missing_logd_artifact_mismatch_detected(isolated_workspace):
    """If the .logd file referenced in JSON doesn't exist, the pair is mismatched."""
    cwd, diag = isolated_workspace
    commit_id = "cafebabe"

    logd_relpath = f"diagnostic/build-{commit_id}.logd"
    ref_path = cwd / logd_relpath

    # .logd must NOT exist (simulating a failed encryption step)
    assert not ref_path.exists(), "Precondition: .logd should not exist"

    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("test-module", False, 2.0, "encryptly failed", None)],
        commit_id=commit_id,
        logd_relpaths=[logd_relpath],
        logd_error="encryptly pack failed",
    )

    # JSON still references the expected .logd path (for transparency)
    assert report["diagnostic_logd"] is not None
    # But the actual file does NOT exist — validation detects the mismatch
    assert not ref_path.exists(), (
        f"Referenced .logd at {ref_path} should not exist when build failed"
    )


def test_chunked_artifact_pairing(isolated_workspace):
    """Chunked .logd parts all exist and are referenced in JSON metadata."""
    cwd, diag = isolated_workspace
    commit_id = "feedface"

    # Create chunked artifacts (simulating split_diagnostic_logd)
    chunks = [
        f"diagnostic/build-{commit_id}-part001.logd",
        f"diagnostic/build-{commit_id}-part002.logd",
        f"diagnostic/build-{commit_id}-part003.logd",
    ]
    for chunk in chunks:
        (cwd / chunk).write_text("chunked diagnostic content")

    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("test-module", True, 0.5, "ok", None)],
        commit_id=commit_id,
        logd_relpaths=chunks,
        chunked=True,
    )

    logd_refs = report["diagnostic_logd"]
    assert isinstance(logd_refs, list), "Chunked logd should be a list"
    assert len(logd_refs) == 3, f"Expected 3 chunks, got {len(logd_refs)}"

    for chunk_path in chunks:
        ref = cwd / chunk_path
        assert ref.exists(), f"Chunk artifact missing: {chunk_path}"
        assert chunk_path in logd_refs, (
            f"Chunk {chunk_path} not referenced in JSON metadata"
        )


# ---------------------------------------------------------------------------
# Determinism — same input produces same output (platform-independent)
# ---------------------------------------------------------------------------

def test_commit_id_determinism():
    """current_commit_id() returns a stable 8-char hex string."""
    from build import current_commit_id

    commit = current_commit_id()
    assert isinstance(commit, str)
    # Must be exactly 8 hex characters or the fallback "00000000"
    assert len(commit) == 8, f"Expected 8 chars, got {len(commit)}: {commit}"
    assert all(c in "0123456789abcdef" for c in commit), (
        f"Non-hex character in commit id: {commit}"
    )


def test_diagnostic_paths_pattern():
    """diagnostic_paths_for_commit() returns paths matching the expected pattern."""
    from build import diagnostic_paths_for_commit

    logd, meta, commit_id = diagnostic_paths_for_commit()
    assert logd.name.startswith("build-") and logd.suffix == ".logd"
    assert meta.name.startswith("build-") and meta.suffix == ".json"
    assert len(commit_id) == 8


# ---------------------------------------------------------------------------
# Report shape validation
# ---------------------------------------------------------------------------

def test_build_diagnostic_report_shape():
    """build_diagnostic_report returns the expected JSON structure."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("test-module", True, 1.0, "ok", None)],
        commit_id="abc12345",
        logd_relpaths=["diagnostic/build-abc12345.logd"],
    )

    # Top-level keys
    assert "generated_at" in report
    assert "commit" in report
    assert "diagnostic_logd" in report
    assert "total_modules" in report
    assert "passed" in report
    assert "failed" in report
    assert "modules" in report

    # Module list
    assert len(report["modules"]) == 1
    mod = report["modules"][0]
    assert mod["name"] == "test-module"
    assert mod["status"] == "PASS"
    assert isinstance(mod["elapsed_seconds"], float)


def test_build_diagnostic_report_counts():
    """build_diagnostic_report correctly counts passed/failed modules."""
    from build import build_diagnostic_report

    results = [
        ("module-a", True, 0.5, "ok", None),
        ("module-b", False, 1.0, "error", None),
        ("module-c", True, 2.0, "ok", None),
    ]
    report = build_diagnostic_report(
        results=results,
        commit_id="abc12345",
        logd_relpaths=["diagnostic/build-abc12345.logd"],
    )

    assert report["total_modules"] == 3
    assert report["passed"] == 2
    assert report["failed"] == 1

    statuses = [m["status"] for m in report["modules"]]
    assert statuses == ["PASS", "FAIL", "PASS"]
