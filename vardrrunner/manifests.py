"""Atomic, sanitized run manifests and artifact hashing.

The SQLite journal is the recovery source of truth.  A manifest travels with a
run directory so an operator can inspect or archive that run without opening the
database.  It contains provenance and hashes, never credentials or raw output.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from vardrrunner import redaction

MANIFEST_NAME = "manifest.json"
MANIFEST_SCHEMA_VERSION = 1


def encode_export_json(payload: dict[str, Any], *, maximum_bytes: int) -> bytes:
    """Bound the exact serialized redacted derivative before reserving disk space."""
    data = (
        json.dumps(redaction.redact(payload), indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    if len(data) > maximum_bytes:
        raise ValueError("export document exceeds limit")
    return data


def write_exclusive(path: Path, data: bytes, *, directory_fd: int | None = None) -> Path:
    """Write new owner-only export bytes; never replace or delete partial output."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def artifact_digest(
    path: Path, chunk_size: int = 1024 * 1024, *, directory_fd: int | None = None
) -> tuple[str, int]:
    """Return ``(sha256, size)`` while reading the artifact once."""
    digest = hashlib.sha256()
    size = 0
    handle = (
        path.open("rb")
        if directory_fd is None
        else os.fdopen(
            os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd), "rb"
        )
    )
    with handle as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def write_atomic_json(path: Path, payload: dict[str, Any]) -> Path:
    """Write JSON durably and atomically beside its final destination."""
    safe = redaction.redact(payload)
    text = json.dumps(safe, indent=2, sort_keys=True) + "\n"
    return write_atomic_text(path, text)


def write_atomic_text(path: Path, content: str) -> Path:
    """Write text durably and atomically with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            temp_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)
    return path


def write_run_manifest(run_dir: Path, payload: dict[str, Any]) -> Path:
    """Write the versioned manifest for a run directory."""
    document = {"manifest_schema_version": MANIFEST_SCHEMA_VERSION, **payload}
    return write_atomic_json(run_dir / MANIFEST_NAME, document)
