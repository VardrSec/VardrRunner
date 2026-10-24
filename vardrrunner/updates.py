"""Release checks against public package metadata, and the operator-run upgrade."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vardrrunner import __version__, api, compatibility, config, manifests

CACHE_TTL = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)


class UpdateCheckError(RuntimeError):
    """Release metadata or its cache is unavailable or malformed."""


@dataclass(frozen=True)
class UpdateStatus:
    current: str
    latest: str
    update_available: bool
    checked_at: str
    from_cache: bool

    def payload(self) -> dict[str, str | bool]:
        return {
            "current": self.current,
            "latest": self.latest,
            "update_available": self.update_available,
            "checked_at": self.checked_at,
            "from_cache": self.from_cache,
        }


def cache_file() -> Path:
    return config.config_dir() / "update-check.json"


def _status(latest: str, checked_at: str, from_cache: bool) -> UpdateStatus:
    try:
        current_tuple = compatibility.version_tuple(__version__)
        latest_tuple = compatibility.version_tuple(latest)
        datetime.fromisoformat(checked_at)
    except ValueError as exc:
        raise UpdateCheckError(f"invalid release metadata: {exc}") from exc
    return UpdateStatus(
        current=__version__,
        latest=latest,
        update_available=latest_tuple > current_tuple,
        checked_at=checked_at,
        from_cache=from_cache,
    )


def _cached(now: datetime) -> UpdateStatus | None:
    path = cache_file()
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        checked = datetime.fromisoformat(str(payload["checked_at"]))
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        if checked - now > MAX_CLOCK_SKEW or now - checked > CACHE_TTL:
            return None
        return _status(str(payload["latest"]), checked.isoformat(), True)
    except (OSError, ValueError, KeyError, TypeError):
        return None


def cached(
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> UpdateStatus | None:
    """Return a fresh cached result, or None. Never makes a network request, so a command
    that is not itself a release check can still mention a release one already found."""
    checked_now = now()
    if checked_now.tzinfo is None:
        checked_now = checked_now.replace(tzinfo=timezone.utc)
    return _cached(checked_now)


def installer(prefix: str | None = None, base_prefix: str | None = None) -> str | None:
    """How this copy was installed — "pipx", "uv" or "venv" — judged from where its
    interpreter lives, or None when the layout does not say."""
    prefix = sys.prefix if prefix is None else prefix
    base_prefix = sys.base_prefix if base_prefix is None else base_prefix
    parts = [part.lower() for part in Path(prefix).parts]
    if "pipx" in parts and "venvs" in parts:
        return "pipx"
    if "uv" in parts and "tools" in parts:
        return "uv"
    if prefix != base_prefix:
        return "venv"
    return None


def upgrade_command(prefix: str | None = None, base_prefix: str | None = None) -> str:
    """The installer's own upgrade command for this copy. A layout that does not identify
    the installer gets both supported commands, not a confident wrong one."""
    return {
        "pipx": "`pipx upgrade vardrrunner`",
        "uv": "`uv tool upgrade vardrrunner`",
        "venv": "`python -m pip install --upgrade vardrrunner`",
    }.get(
        installer(prefix, base_prefix) or "",
        "`pipx upgrade vardrrunner` or `uv tool upgrade vardrrunner`",
    )


def upgrade_argv() -> list[str] | None:
    """The argv `vardrrunner update` runs, or None when it should only name the command.

    Only pipx is run: upgrading from inside the running pipx executable is verified on
    Windows, where the open file is the usual obstacle. pip in a plain virtualenv must
    replace the very `vardrrunner.exe` that is running, and uv is unverified, so for those
    the command is printed for the operator instead (ADR 0012 amendment, 2026-10-24).
    """
    if installer() != "pipx":
        return None
    pipx = shutil.which("pipx")
    return [pipx, "upgrade", "vardrrunner"] if pipx else None


def run_upgrade(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the installer in the foreground. Output is captured so a harmless pipx note
    about the shim it cannot overwrite does not read as a failure."""
    return subprocess.run(
        argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False
    )


def installed_version() -> str | None:
    """The version now on disk, read by a fresh interpreter: this process still holds
    the modules that were loaded before the upgrade replaced them.

    `-I` keeps the working directory and PYTHON* variables off the import path, so a
    `vardrrunner` folder or stale egg-info where the operator happens to stand can neither
    answer for, nor run code as, the installed package.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", "from vardrrunner import __version__; print(__version__)"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    version = result.stdout.strip()
    return version if result.returncode == 0 and version else None


def notice(status: UpdateStatus) -> str:
    """One line naming the newer release and the command that installs it."""
    return (
        f"[yellow]Update available:[/yellow] {status.current} → {status.latest}. "
        "Run `vardrrunner update`."
    )


def check(
    *,
    force: bool = False,
    timeout: int = 10,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> UpdateStatus:
    """Latest release vs. this copy. `force` skips the 24-hour cache; the explicit commands
    (`update`, `update check`, `doctor`) always pass it, and every fetch refreshes the cache."""
    checked_now = now()
    if checked_now.tzinfo is None:
        checked_now = checked_now.replace(tzinfo=timezone.utc)
    if not force and (cached := _cached(checked_now)) is not None:
        return cached
    try:
        payload = api.fetch_release_metadata(timeout=timeout)
        latest = str(payload["info"]["version"])
        result = _status(latest, checked_now.isoformat(), False)
        manifests.write_atomic_json(
            cache_file(), {"checked_at": result.checked_at, "latest": result.latest}
        )
    except (api.ReleaseMetadataError, OSError, ValueError, KeyError, TypeError) as exc:
        raise UpdateCheckError(f"release check failed: {exc}") from exc
    return result
