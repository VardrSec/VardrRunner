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


def artifact_digest(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
    """Return ``(sha256, size)`` while reading the artifact once."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def write_atomic_json(path: Path, payload: dict[str, Any]) -> Path:
    """Write JSON durably and atomically beside its final destination."""
    path.parent.mkdir(parents=True, exist_ok=True)
    safe = redaction.redact(payload)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(safe, fh, indent=2, sort_keys=True)
            fh.write("\n")
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
