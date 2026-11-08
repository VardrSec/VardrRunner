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

from vardrrunner import __version__, redaction

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


def case_snapshot(case: dict) -> dict:
    """Informational derivative, never credentials, an exact original or replay authority."""
    from urllib.parse import urlsplit, urlunsplit

    removed: list[str] = []
    anonymous: list[tuple[str, ...]] = []

    def walk(value, path=()):
        if len(path) > 10:
            removed.append(".".join(path))
            return redaction.MASK
        if isinstance(value, list):
            return [walk(item, (*path, str(i))) for i, item in enumerate(value)]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            location = (*path, str(key))
            credential_keys = {"type", "header", "value", "value_env", "value_keychain"}
            if (
                str(key).lower() == "credential"
                and isinstance(item, dict)
                and item.get("type") == "static_header"
                and set(item) <= credential_keys
                and all(item.get(field) in (None, "") for field in credential_keys - {"type"})
            ):
                anonymous.append(location)
                result[key] = {"type": "static_header"}
                continue
            if "credential" in str(key).lower() and item in (None, "", {}, []):
                continue  # Known empty credentials do not need replacement inputs.
            sensitive = any(
                part in str(key).lower()
                for part in ("credential", "header", "body", "query", "params")
            )
            if sensitive and item not in (None, "", {}, []):
                removed.append(".".join(location))
                result[key] = redaction.MASK
            elif str(key).lower().endswith("url") and isinstance(item, str):
                try:
                    original = urlsplit(item)
                    clean = urlunsplit(
                        (original.scheme, original.netloc.rsplit("@", 1)[-1], original.path, "", "")
                    )
                    sanitized = redaction.redact_url(clean)
                    if (
                        "@" in original.netloc
                        or original.query
                        or original.fragment
                        or sanitized != clean
                    ):
                        removed.append(".".join(location))
                    result[key] = sanitized
                except ValueError:
                    removed.append(".".join(location))
                    result[key] = redaction.MASK
            else:
                result[key] = walk(item, location)
        return result

    safe = redaction.redact(walk(case))
    for location in anonymous:
        parent = safe
        for key in location[:-1]:
            if isinstance(parent, dict):
                parent = parent.get(key)
            elif isinstance(parent, list) and key.isdigit() and int(key) < len(parent):
                parent = parent[int(key)]
            else:
                parent = None
                break
        if isinstance(parent, dict):
            parent[location[-1]] = {"type": "static_header"}  # Closed canonical payload only.
    target = (
        (safe.get("request") or {}).get("url") if isinstance(safe.get("request"), dict) else None
    )
    return {
        "case_snapshot": safe,
        "logical_target": target,
        "snapshot_kind": "redacted_unresolved_reviewed",
        "snapshot_redactions": removed,
        "requires_operator_inputs": bool(removed),
        "requires_new_review": True,
        "independent_reproduction": "not_performed",
    }


def evidence_provenance(case: dict, original_hash: str, tools: dict) -> dict:
    return {
        "runner_version": __version__,
        "tools": tools,
        "case_hash": original_hash,
        **case_snapshot(case),
        "execution_authority": False,
    }
