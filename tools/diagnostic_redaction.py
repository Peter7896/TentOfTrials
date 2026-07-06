"""Helpers to keep diagnostic metadata free of host-specific path leaks."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

_SENSITIVE_PARTS = (
    os.path.expanduser("~"),
    tempfile.gettempdir(),
)


def repo_relative_posix(path: Optional[str], root: Path) -> Optional[str]:
    """Return a repository-relative path using forward slashes."""
    if not path:
        return path
    candidate = Path(path)
    try:
        if candidate.is_absolute():
            rel = candidate.resolve().relative_to(root.resolve())
        else:
            rel = candidate
        return rel.as_posix()
    except ValueError:
        return candidate.name


def redact_path_string(value: str, root: Path) -> str:
    """Replace absolute home/temp/repo paths inside free-form text."""
    text = value
    root_resolved = str(root.resolve())
    for prefix in (root_resolved, *_SENSITIVE_PARTS):
        if prefix:
            text = text.replace(prefix.replace("\\", "/"), "<redacted>")
            text = text.replace(prefix, "<redacted>")
    return text


def sanitize_metadata(metadata: dict[str, Any], root: Path) -> dict[str, Any]:
    """Return metadata with repo-relative artifact paths and normalized logd refs."""
    cleaned = dict(metadata)
    logd_field = cleaned.get("diagnostic_logd")
    if isinstance(logd_field, list):
        cleaned["diagnostic_logd"] = [repo_relative_posix(item, root) for item in logd_field]
    elif isinstance(logd_field, str):
        cleaned["diagnostic_logd"] = repo_relative_posix(logd_field, root)

    if isinstance(cleaned.get("decrypt_command"), str):
        cleaned["decrypt_command"] = redact_path_string(cleaned["decrypt_command"], root)

    modules = cleaned.get("modules")
    if isinstance(modules, list):
        sanitized_modules = []
        for entry in modules:
            if not isinstance(entry, dict):
                sanitized_modules.append(entry)
                continue
            item = dict(entry)
            if "artifact" in item:
                item["artifact"] = repo_relative_posix(item.get("artifact"), root)
            sanitized_modules.append(item)
        cleaned["modules"] = sanitized_modules

    timings = cleaned.get("module_timings")
    if isinstance(timings, list):
        sanitized_timings = []
        for entry in timings:
            if not isinstance(entry, dict):
                sanitized_timings.append(entry)
                continue
            item = dict(entry)
            if isinstance(item.get("command"), list):
                item["command"] = [
                    repo_relative_posix(part, root) if isinstance(part, str) and ("/" in part or "\\" in part) else part
                    for part in item["command"]
                ]
            sanitized_timings.append(item)
        cleaned["module_timings"] = sanitized_timings

    return cleaned


def _logd_paths_from_metadata(metadata: dict[str, Any]) -> list[str]:
    logd_field = metadata.get("diagnostic_logd")
    if isinstance(logd_field, list):
        return [str(item) for item in logd_field]
    if isinstance(logd_field, str):
        return [logd_field]
    return []


def _contains_sensitive_leak(text: str, root: Path) -> bool:
    lowered = text.lower()
    if re.search(r"[a-z]:\\", text, re.I):
        return True
    if os.path.expanduser("~") and os.path.expanduser("~") in text:
        return True
    if str(root.resolve()) in text:
        return True
    if tempfile.gettempdir() and tempfile.gettempdir() in text:
        return True
    if re.search(r"\b(?:hostname|username|machine)\s*[:=]", lowered):
        return True
    return False


def validate_metadata_redaction(metadata: dict[str, Any], root: Path) -> None:
    """Raise ValueError when metadata still exposes host-specific paths."""
    serialized = json.dumps(metadata)
    if _contains_sensitive_leak(serialized, root):
        raise ValueError("diagnostic metadata leaks host-specific paths")


def validate_diagnostic_bundle(metadata_path: Path, root: Path) -> None:
    """Validate metadata/logd pairing and redaction contract."""
    if not metadata_path.exists():
        raise FileNotFoundError(f"diagnostic metadata missing: {metadata_path}")

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    validate_metadata_redaction(metadata, root)

    logd_refs = _logd_paths_from_metadata(metadata)
    if not logd_refs:
        raise ValueError("diagnostic metadata missing diagnostic_logd reference")

    missing = [ref for ref in logd_refs if not (root / ref).exists()]
    if missing:
        raise FileNotFoundError(
            f"diagnostic .logd artifact(s) missing for metadata pair: {', '.join(missing)}"
        )

    for ref in logd_refs:
        if "\\" in ref:
            raise ValueError(f"diagnostic_logd must use repository-relative '/' paths: {ref}")

    for module in metadata.get("modules", []):
        artifact = module.get("artifact")
        if artifact and (Path(artifact).is_absolute() or "\\" in str(artifact)):
            raise ValueError(f"module artifact must be repository-relative: {artifact}")
