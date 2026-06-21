from pathlib import Path
from typing import Optional
import subprocess

ROOT = Path(__file__).resolve().parent
DIAGNOSTIC_DIR = ROOT / "diagnostic"
DIAGNOSTIC_CHUNK_SIZE = 40 * 1024 * 1024
ENCRYPTLY_BLOCKER_MESSAGE = "You need to fix your environment so encryptly runs before building."

def current_commit_id() -> str:
    """Return the first 4 bytes (8 hex chars) of HEAD for stable per-commit diagnostics."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=5,
        )
        commit = result.stdout.strip()
        if result.returncode == 0 and len(commit) >= 8:
            return commit[:8]
    except Exception:
        pass
    return "00000000"

def diagnostic_paths_for_commit() -> tuple[Path, Path, str]:
    """Return stable diagnostic artifact paths under diagnostic/ for the current commit."""
    DIAGNOSTIC_DIR.mkdir(parents=True, exist_ok=True)
    commit_id = current_commit_id()
    logd_path = DIAGNOSTIC_DIR / f"build-{commit_id}.logd"
    metadata_path = DIAGNOSTIC_DIR / f"build-{commit_id}.json"
    return logd_path, metadata_path, commit_id

def split_diagnostic_logd(logd_path: Path, chunk_size: int = DIAGNOSTIC_CHUNK_SIZE) -> list[Path]:
    """Split an oversized .logd into numbered .logd chunks and remove the original."""
    if logd_path.stat().st_size <= chunk_size:
        return [logd_path]
    # Additional logic for splitting the logd file would go here.