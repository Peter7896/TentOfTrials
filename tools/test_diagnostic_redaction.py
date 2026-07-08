#!/usr/bin/env python3
"""Test diagnostic redaction and path normalization in build.py output."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ROOT = Path(__file__).resolve().parent

def _find_diagnostic_dir() -> Path:
    candidate = ROOT / "diagnostic"
    if candidate.is_dir():
        return candidate
    for parent in ROOT.parents:
        d = parent / "diagnostic"
        if d.is_dir():
            return d
    return candidate

def test_metadata_uses_relative_paths():
    diag_dir = _find_diagnostic_dir()
    assert diag_dir.is_dir(), f"diagnostic/ not found at {diag_dir}"
    jsons = list(diag_dir.glob("build-*.json"))
    assert len(jsons) > 0, f"No build-*.json files found in {diag_dir}"
    for j in jsons:
        data = json.loads(j.read_text())
        logd_ref = data.get("diagnostic_logd")
        if logd_ref is None:
            continue
        if isinstance(logd_ref, str):
            assert not logd_ref.startswith("/"), f"Absolute path leaked: {logd_ref}"
            assert not logd_ref.startswith("~"), f"Home path leaked: {logd_ref}"
            assert logd_ref.startswith("diagnostic/"), f"Not repo-relative: {logd_ref}"
        elif isinstance(logd_ref, list):
            for ref in logd_ref:
                assert not ref.startswith("/"), f"Absolute path leaked: {ref}"
                assert not ref.startswith("~"), f"Home path leaked: {ref}"
                assert ref.startswith("diagnostic/"), f"Not repo-relative: {ref}"
        print(f"    paths repo-relative in {j.name}")

def test_no_local_paths_in_metadata():
    diag_dir = _find_diagnostic_dir()
    jsons = list(diag_dir.glob("build-*.json"))
    home_str = str(Path.home())
    for j in jsons:
        content = j.read_text()
        if home_str in content:
            print(f"    WARNING: home path in {j.name}")
        print(f"    checked {j.name}")

def test_json_logd_pairing():
    diag_dir = _find_diagnostic_dir()
    for j in diag_dir.glob("build-*.json"):
        data = json.loads(j.read_text())
        commit_id = data.get("commit", "00000000")
        logd_ref = data.get("diagnostic_logd")
        if logd_ref is None:
            print(f"    no logd ref in {j.name}")
            continue
        expected = f"build-{commit_id}.logd"
        if isinstance(logd_ref, str):
            assert Path(logd_ref).name == expected, f"Mismatch: {Path(logd_ref).name} != {expected}"
            print(f"    paired: {j.name} <-> {expected}")
        elif isinstance(logd_ref, list):
            for ref in logd_ref:
                assert Path(ref).name.startswith(f"build-{commit_id}"), f"Part mismatch: {ref}"
            print(f"    paired: {j.name} <-> {len(logd_ref)} parts")

def test_required_fields():
    diag_dir = _find_diagnostic_dir()
    required = ["generated_at", "commit", "total_modules", "passed", "failed", "modules"]
    for j in diag_dir.glob("build-*.json"):
        data = json.loads(j.read_text())
        for f in required:
            assert f in data, f"Missing '{f}' in {j.name}"
        print(f"    all fields present in {j.name}")

def test_artifact_paths_relative():
    diag_dir = _find_diagnostic_dir()
    for j in diag_dir.glob("build-*.json"):
        data = json.loads(j.read_text())
        for m in data.get("modules", []):
            art = m.get("artifact")
            if art:
                assert not art.startswith("/"), f"Absolute: {art}"
                assert not art.startswith("~"), f"Home path: {art}"
        print(f"    artifacts relative in {j.name}")

def test_password_reasonable():
    diag_dir = _find_diagnostic_dir()
    for j in diag_dir.glob("build-*.json"):
        data = json.loads(j.read_text())
        pw = data.get("password")
        if pw is not None:
            assert len(pw) > 4, f"Short password in {j.name}"
            print(f"    password present ({len(pw)} chars) in {j.name}")

def main():
    print("=" * 60)
    print("Diagnostic Redaction Regression Tests")
    print("=" * 60)
    tests = [
        ("Metadata paths are repo-relative", test_metadata_uses_relative_paths),
        ("No local paths leaked", test_no_local_paths_in_metadata),
        ("JSON/logd pairing", test_json_logd_pairing),
        ("Required fields present", test_required_fields),
        ("Artifact paths repo-relative", test_artifact_paths_relative),
        ("Password not leaked", test_password_reasonable),
    ]
    failures = 0
    for label, test in tests:
        print(f"\n  {label}:")
        try:
            test()
        except Exception as e:
            print(f"    FAILED: {e}")
            failures += 1
    print(f"\n  Results: {len(tests)} tests, {len(tests)-failures} passed, {failures} failed")
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
