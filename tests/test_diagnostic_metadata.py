"""
Tests for diagnostic report generation and metadata shape.

These tests validate that:
- Successful report metadata includes commit id, module summaries, and diagnostic_logd path.
- logd generation failure populates diagnostic_logd_error without claiming a valid archive.
- Chunked or multi-file logd references work correctly.
- Tests are deterministic and avoid requiring external toolchains or network access.

Run:  python3 -m pytest tests/test_diagnostic_metadata.py -v
"""

import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path so we can import build.py helpers
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Successful report metadata
# ---------------------------------------------------------------------------

def test_report_contains_commit_id():
    """build_diagnostic_report includes the commit id."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
    )
    assert report["commit"] == "abcd1234"


def test_report_contains_module_summaries():
    """build_diagnostic_report returns module summaries with name, status, elapsed."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", True, 1.5, "build output", "target/debug/module-a")],
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
    )

    modules = report["modules"]
    assert len(modules) == 1
    mod = modules[0]
    assert mod["name"] == "module-a"
    assert mod["status"] == "PASS"
    assert mod["elapsed_seconds"] == 1.5
    assert mod["artifact"] == "target/debug/module-a"


def test_report_contains_diagnostic_logd_path():
    """build_diagnostic_report includes the diagnostic_logd path in JSON."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
    )

    assert report["diagnostic_logd"] is not None
    assert report["diagnostic_logd"] == "diagnostic/build-abcd1234.logd"


def test_report_tracks_pass_fail_counts():
    """build_diagnostic_report correctly counts passed and failed modules."""
    from build import build_diagnostic_report

    results = [
        ("module-a", True, 0.5, "ok", None),
        ("module-b", False, 1.0, "error", None),
        ("module-c", True, 2.0, "ok", None),
    ]
    report = build_diagnostic_report(
        results=results,
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
    )

    assert report["total_modules"] == 3
    assert report["passed"] == 2
    assert report["failed"] == 1


def test_report_modules_preserve_order():
    """Module list preserves the original insertion order."""
    from build import build_diagnostic_report

    results = [
        ("backend", True, 10.0, "ok", "debug/backend"),
        ("frontend", False, 5.0, "npm error", None),
    ]
    report = build_diagnostic_report(
        results=results,
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
    )

    names = [m["name"] for m in report["modules"]]
    assert names == ["backend", "frontend"]


def test_report_generated_at_is_iso_format():
    """generated_at field is ISO 8601 formatted timestamp."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
    )

    ts = report["generated_at"]
    assert "T" in ts, f"Expected ISO 8601 timestamp (with T), got {ts}"
    assert ts.endswith("+00:00") or ts.endswith("Z") or "+" in ts[19:], (
        f"Expected timezone info in timestamp: {ts}"
    )


# ---------------------------------------------------------------------------
# logd generation failure — populated error without valid archive
# ---------------------------------------------------------------------------

def test_logd_error_populated_when_encryption_fails():
    """When logd creation fails, diagnostic_logd is None and diagnostic_logd_error has the reason."""
    from build import build_diagnostic_report

    error_msg = "encryptly binary not found (detected macos-arm64)"
    report = build_diagnostic_report(
        results=[("module-a", False, 0.5, "error", None)],
        commit_id="abcd1234",
        logd_error=error_msg,
    )

    assert report["diagnostic_logd"] is None, (
        "diagnostic_logd must be None when logd creation fails"
    )
    assert report["diagnostic_logd_error"] == error_msg


def test_logd_error_without_logd_ref_does_not_claim_valid_archive():
    """When logd_error is set and logd_relpaths is None, no valid archive is claimed."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", False, 0.5, "error", None)],
        commit_id="abcd1234",
        logd_error="encryptly pack failed",
    )

    # Must not claim a valid .logd reference
    assert report["diagnostic_logd"] is None
    # Must not claim a password (no archive was created)
    assert report.get("password") is None
    # Must not claim a decrypt command (no archive to decrypt)
    assert report.get("decrypt_command") is None


def test_logd_error_sets_blocker_message():
    """When logd_error is set, message_blocker should be populated."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", False, 0.5, "error", None)],
        commit_id="abcd1234",
        logd_error="encryptly binary not found",
        message_blocker="You need to fix your environment so encryptly runs before building.",
    )

    assert report["message_blocker"] is not None
    assert "encryptly" in report["message_blocker"]


# ---------------------------------------------------------------------------
# Chunked / multi-file logd references
# ---------------------------------------------------------------------------

def test_single_logd_ref_is_string():
    """A single logd artifact is stored as a string, not a list."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
    )

    assert isinstance(report["diagnostic_logd"], str)
    assert not isinstance(report["diagnostic_logd"], list)


def test_chunked_logd_ref_is_list():
    """Multiple chunked logd artifacts are stored as a list of strings."""
    from build import build_diagnostic_report

    chunks = [
        "diagnostic/build-abcd1234-part001.logd",
        "diagnostic/build-abcd1234-part002.logd",
    ]
    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=chunks,
        chunked=True,
    )

    assert isinstance(report["diagnostic_logd"], list)
    assert len(report["diagnostic_logd"]) == 2
    assert report["chunked"] is True


def test_chunked_report_has_chunk_size():
    """Chunked report includes the chunk_size_bytes field."""
    from build import build_diagnostic_report, DIAGNOSTIC_CHUNK_SIZE

    chunks = [
        "diagnostic/build-abcd1234-part001.logd",
        "diagnostic/build-abcd1234-part002.logd",
    ]
    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=chunks,
        chunked=True,
    )

    assert report["chunk_size_bytes"] == DIAGNOSTIC_CHUNK_SIZE


def test_chunked_report_no_chunk_size_when_not_chunked():
    """When not chunked, chunk_size_bytes should be None."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
        chunked=False,
    )

    assert report["chunk_size_bytes"] is None


def test_chunked_refs_are_forward_slash_paths():
    """Chunked logd paths use forward slashes (even on Windows)."""
    from build import build_diagnostic_report

    chunks = [
        "diagnostic/build-abcd1234-part001.logd",
        "diagnostic/build-abcd1234-part002.logd",
    ]
    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=chunks,
        chunked=True,
    )

    for ref in report["diagnostic_logd"]:
        assert "\\" not in ref, f"Backslash found in logd ref: {ref}"
        assert ref.startswith("diagnostic/"), f"Path doesn't start with diagnostic/: {ref}"


# ---------------------------------------------------------------------------
# Decrypt command generation
# ---------------------------------------------------------------------------

def test_decrypt_command_generated_with_password():
    """When password is provided, decrypt_command is populated."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
        password="test-password-123",
    )

    cmd = report["decrypt_command"]
    assert cmd is not None
    assert "encryptly unpack" in cmd
    assert "test-password-123" in cmd


def test_decrypt_command_none_without_password():
    """When password is None, decrypt_command is None."""
    from build import build_diagnostic_report

    report = build_diagnostic_report(
        results=[("module-a", True, 1.0, "ok", None)],
        commit_id="abcd1234",
        logd_relpaths=["diagnostic/build-abcd1234.logd"],
    )

    assert report.get("decrypt_command") is None


# ---------------------------------------------------------------------------
# Determinism and stability
# ---------------------------------------------------------------------------

def test_commit_id_format():
    """current_commit_id() returns an 8-char hex string (or fallback 00000000)."""
    from build import current_commit_id

    commit = current_commit_id()
    assert isinstance(commit, str)
    assert len(commit) == 8
    assert all(c in "0123456789abcdef" for c in commit)


def test_diagnostic_path_pattern():
    """diagnostic_paths_for_commit() returns paths matching build-PATTERN.logd/json."""
    from build import diagnostic_paths_for_commit

    logd, meta, commit_id = diagnostic_paths_for_commit()
    assert logd.name == f"build-{commit_id}.logd"
    assert meta.name == f"build-{commit_id}.json"
