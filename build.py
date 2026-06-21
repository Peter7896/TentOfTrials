import json
import subprocess
from pathlib import Path

# ... (truncated) ...


def write_diagnostic_report(metadata_path: Path, report: dict) -> None:
    metadata_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"    {color('✓', Colors.GREEN)} {metadata_path.relative_to(ROOT)} created")


def commit_diagnostic_artifacts(paths: list[Path], commit_id: str) -> bool:
    """Commit diagnostic files as soon as they are produced."""
    existing = [path for path in paths if path.exists()]
    if not existing:
        print(f"    {color('✗', Colors.RED)} No diagnostic artifacts found to commit")
        return False

    relpaths = [str(path.relative_to(ROOT)) for path in existing]
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", *relpaths],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if status.returncode != 0:
        print(f"    {color('✗', Colors.RED)} Could not inspect diagnostic git status: {status.stderr.strip()}")
        return False

    # Add regression tests for diagnostic redaction
    def test_diagnostic_redaction():
        # Assuming we have a function to generate the report
        report = generate_diagnostic_report()
        assert "home" not in report
        assert "repo" not in report
        assert "temp" not in report
        assert "machine_name" not in report
        assert "username" not in report

        # Check artifact paths
        for artifact in report.get("artifacts", []):
            assert artifact["path"].startswith("/")

    # Add test for JSON and .logd artifact matching
    def test_logd_artifact_matching():
        report = generate_diagnostic_report()
        logd_artifacts = report.get("logd_artifacts", [])
        json_artifacts = report.get("artifacts", [])

        for logd in logd_artifacts:
            assert any(logd["name"] == json_artifact["name"] for json_artifact in json_artifacts)

    # Run tests
    test_diagnostic_redaction()
    test_logd_artifact_matching()

# ... (truncated) ...