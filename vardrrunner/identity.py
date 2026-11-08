"""Stable, non-secret identity for one VardrRunner installation."""

from __future__ import annotations

import json
import os
import socket
import stat
import time
import uuid
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path

from vardrrunner import config, manifests
from vardrrunner.windows_journal import WindowsJournalError, WindowsJournalPin

ENV_RUNNER_NAME = "VARDRRUNNER_NAME"
IDENTITY_SCHEMA_VERSION = 1


class IdentityError(RuntimeError):
    """The local identity is unreadable or invalid."""


@dataclass(frozen=True)
class RunnerIdentity:
    runner_id: str
    name: str
    hostname: str

    def payload(self) -> dict[str, str | int]:
        return {
            "identity_schema_version": IDENTITY_SCHEMA_VERSION,
            "runner_id": self.runner_id,
            "name": self.name,
            "hostname": self.hostname,
        }


def identity_file() -> Path:
    return config.config_dir() / "runner-identity.json"


def _validated(data: object) -> RunnerIdentity:
    if not isinstance(data, dict):
        raise IdentityError("runner identity must be a JSON object")
    raw_id = data.get("runner_id")
    raw_name = data.get("name")
    raw_hostname = data.get("hostname")
    try:
        runner_id = str(uuid.UUID(str(raw_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise IdentityError("runner identity contains an invalid UUID") from exc
    name = str(raw_name or "").strip()
    hostname = str(raw_hostname or "").strip()
    if not name or len(name) > 128 or any(ord(char) < 32 for char in name):
        raise IdentityError("runner identity name must be 1-128 printable characters")
    if not hostname:
        raise IdentityError("runner identity hostname is missing")
    return RunnerIdentity(runner_id=runner_id, name=name, hostname=hostname)


def _read(path: Path) -> RunnerIdentity:
    """Read an identity, briefly tolerating another process's first write."""
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            return _validated(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            last_error = exc
            if attempt < 4:
                time.sleep(0.01)
    raise IdentityError(f"cannot read runner identity: {last_error}") from last_error


def read_existing(path: Path) -> RunnerIdentity:
    """Read one bounded existing identity without defaults, creation or overrides.

    Reject linked/reparse components and detect replacement or content changes.
    Windows uses the existing noncreating name pin; this is not an OS sandbox.
    """
    try:
        path = Path(path).absolute()
        if ".." in path.parts:
            raise IdentityError("identity_path_unsupported")
        for component in (path, *path.parents):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise IdentityError("identity_path_unsupported")
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise IdentityError("identity_file_unsupported")
        if os.name == "posix":
            effective_uid = getattr(os, "geteuid", None)
            if (
                not callable(effective_uid)
                or before.st_uid not in {0, effective_uid()}
                or stat.S_IMODE(before.st_mode) & 0o077
            ):
                raise IdentityError("identity_permissions_unsupported")
        guard = (
            WindowsJournalPin(path, create=False, observed=before)
            if os.name == "nt"
            else nullcontext()
        )
        with guard:
            descriptor = os.open(
                path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())

                def identity(item):
                    return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_nlink)

                if identity(opened) != identity(before) or not stat.S_ISREG(opened.st_mode):
                    raise IdentityError("identity_changed")
                data = stream.read(8193)
                if identity(os.fstat(stream.fileno())) != identity(opened) or identity(
                    path.lstat()
                ) != identity(opened):
                    raise IdentityError("identity_changed")
        if not 0 < len(data) <= 8192:
            raise IdentityError("identity_size_unsupported")
        # Use the shared duplicate-key/depth checks, then the existing pure loader.
        from vardrrunner.authorization.codec import decoded

        value = decoded(data, 8192)
        if (
            type(value) is not dict
            or set(value) != {"identity_schema_version", "runner_id", "name", "hostname"}
            or type(value["identity_schema_version"]) is not int
            or value["identity_schema_version"] != IDENTITY_SCHEMA_VERSION
        ):
            raise IdentityError("identity_schema_unsupported")
        result = _validated(value)
        if value["runner_id"] != result.runner_id:
            raise IdentityError("identity_uuid_unsupported")
        return result
    except (OSError, ValueError, WindowsJournalError):
        raise IdentityError("identity_unavailable") from None


def _create_exclusive(path: Path, created: RunnerIdentity) -> bool:
    """Create without overwrite; return False when another process won."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    except FileExistsError:
        return False
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(created.payload(), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return True


def load_or_create() -> RunnerIdentity:
    """Load the stable identity, creating it atomically on first use."""
    path = identity_file()
    if path.exists():
        saved = _read(path)
        override = os.environ.get(ENV_RUNNER_NAME)
        if override and override.strip():
            return _validated(
                {
                    "runner_id": saved.runner_id,
                    "name": override.strip(),
                    "hostname": saved.hostname,
                }
            )
        return saved

    hostname = socket.gethostname()
    name = os.environ.get(ENV_RUNNER_NAME, "").strip() or hostname
    created = _validated({"runner_id": str(uuid.uuid4()), "name": name, "hostname": hostname})
    try:
        if not _create_exclusive(path, created):
            return load_or_create()
    except OSError as exc:
        raise IdentityError(f"cannot create runner identity: {exc}") from exc
    return created


def rename(name: str) -> RunnerIdentity:
    """Persist a human label without changing the stable runner UUID."""
    current = load_or_create()
    updated = _validated(
        {"runner_id": current.runner_id, "name": name.strip(), "hostname": current.hostname}
    )
    try:
        manifests.write_atomic_json(identity_file(), updated.payload())
    except OSError as exc:
        raise IdentityError(f"cannot update runner identity: {exc}") from exc
    return updated
