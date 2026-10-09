#!/usr/bin/env python3
"""Explicit-input authenticated diagnostic bundles; never discover local files.

The safe-logd-v1 format is documented in docs/safe-logd-format.md. It is NOT
compatible with Encryptly. The only pack inputs are three caller-supplied texts.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import stat
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "safe-logd-v1"
MAGIC = b"SAFELOGD\x01"
REQUIRED_FILES = ("build.log", "build-summary.txt", "system-info.txt")
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_ARCHIVE_BYTES = len(MAGIC) + NONCE_BYTES + MAX_PAYLOAD_BYTES + TAG_BYTES
MAX_METADATA_BYTES = 1024 * 1024


def _validate_texts(texts: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(texts, Mapping) or set(texts) != set(REQUIRED_FILES):
        raise ValueError("diagnostics must contain exactly the three required files")
    result = {}
    total = 0
    for name in REQUIRED_FILES:
        text = texts[name]
        if not isinstance(text, str):
            raise ValueError("diagnostic values must be text")
        size = len(text.encode("utf-8"))
        if size > MAX_FILE_BYTES:
            raise ValueError("diagnostic file exceeds the size limit")
        total += size
        result[name] = text
    if total > MAX_TOTAL_BYTES:
        raise ValueError("diagnostic texts exceed the total size limit")
    return result


def _decode_key(key: str) -> bytes:
    if not isinstance(key, str) or len(key) != 44:
        raise ValueError("password must be a canonical base64url-encoded 256-bit key")
    try:
        raw = base64.b64decode(key.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError, binascii.Error) as error:
        raise ValueError("invalid diagnostic key") from error
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode("ascii") != key:
        raise ValueError("invalid diagnostic key")
    return raw


def _read_regular_file(path: Path, limit: int) -> bytes:
    # O_NOFOLLOW prevents a final-component symlink swap on platforms supporting
    # it; the explicit check also rejects symlinks on Windows.
    path = Path(path)
    if path.is_symlink():
        raise ValueError("diagnostic input must not be a symbolic link")
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("diagnostic input must be a regular file")
        if info.st_size > limit:
            raise ValueError("diagnostic input exceeds the size limit")
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("diagnostic input exceeds the size limit")
    return data


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _parse_json(data: bytes):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("invalid diagnostic JSON") from error


def pack_diagnostic_texts(output_path: Path, texts: Mapping[str, str]) -> str:
    """Encrypt exactly three in-memory texts and return their random key.

    Never scans a directory or reads any input file. Refuses to replace an
    existing destination. The caller must redact the text before calling.
    """
    payload = json.dumps({"format": FORMAT, "files": _validate_texts(texts)},
                         ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("serialized diagnostics exceed the payload size limit")
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_BYTES)
    archive = MAGIC + nonce + AESGCM(key).encrypt(nonce, payload, MAGIC)
    # Exclusive creation also rejects existing symlinks without following them.
    with Path(output_path).open("xb") as output:
        output.write(archive)
    return base64.urlsafe_b64encode(key).decode("ascii")


def unpack_diagnostic_texts(input_path: Path, key: str) -> dict[str, str]:
    """Authenticate/decrypt a bounded archive, returning only the allowed texts."""
    raw_key = _decode_key(key)
    archive = _read_regular_file(Path(input_path), MAX_ARCHIVE_BYTES)
    prefix_length = len(MAGIC) + NONCE_BYTES
    if len(archive) < prefix_length + TAG_BYTES or not archive.startswith(MAGIC):
        raise ValueError("unsupported or truncated diagnostic format")
    nonce = archive[len(MAGIC):prefix_length]
    try:
        payload = AESGCM(raw_key).decrypt(nonce, archive[prefix_length:], MAGIC)
    except InvalidTag as error:
        raise ValueError("diagnostic authentication failed (wrong key or altered data)") from error
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("diagnostic payload exceeds the size limit")
    document = _parse_json(payload)
    if (not isinstance(document, dict) or set(document) != {"format", "files"}
            or document["format"] != FORMAT):
        raise ValueError("unsupported diagnostic payload schema")
    return _validate_texts(document["files"])


def extract_diagnostic_texts(texts: Mapping[str, str], output_dir: Path) -> None:
    """Write only fixed filenames into a newly-created output directory."""
    checked = _validate_texts(texts)
    output_dir = Path(output_dir)
    output_dir.mkdir()  # Refuse an existing directory, file, or symlink.
    for name in REQUIRED_FILES:
        with (output_dir / name).open("xb") as output:
            output.write(checked[name].encode("utf-8"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    unpack = commands.add_parser("unpack", help="decrypt safe-logd-v1; not Encryptly")
    unpack.add_argument("archive", type=Path)
    unpack.add_argument("output_dir", type=Path, help="new output directory; must not exist")
    unpack.add_argument("--metadata", type=Path, required=True,
                        help="matching JSON containing format and password/key")
    args = parser.parse_args(argv)
    try:
        report = _parse_json(_read_regular_file(args.metadata, MAX_METADATA_BYTES))
        if not isinstance(report, dict) or report.get("format") != FORMAT:
            raise ValueError("metadata must declare safe-logd-v1")
        texts = unpack_diagnostic_texts(args.archive, report.get("password"))
        extract_diagnostic_texts(texts, args.output_dir)
    except (OSError, ValueError) as error:
        parser.exit(1, f"safe-logd: {error}\n")
    print(f"Verified and extracted {len(REQUIRED_FILES)} diagnostic files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
