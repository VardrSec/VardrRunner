"""Cached, opt-in release checks against public package metadata."""

from __future__ import annotations

import json
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


def check(
    *,
    force: bool = False,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> UpdateStatus:
    checked_now = now()
    if checked_now.tzinfo is None:
        checked_now = checked_now.replace(tzinfo=timezone.utc)
    if not force and (cached := _cached(checked_now)) is not None:
        return cached
    try:
        payload = api.fetch_release_metadata()
        latest = str(payload["info"]["version"])
        result = _status(latest, checked_now.isoformat(), False)
        manifests.write_atomic_json(
            cache_file(), {"checked_at": result.checked_at, "latest": result.latest}
        )
    except (api.ReleaseMetadataError, OSError, ValueError, KeyError, TypeError) as exc:
        raise UpdateCheckError(f"release check failed: {exc}") from exc
    return result
