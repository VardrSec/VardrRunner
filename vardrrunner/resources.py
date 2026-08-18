"""Locally enforced queue resource ceilings."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

ENV_MAX_TARGETS = "VARDRRUNNER_MAX_TARGETS"
ENV_MAX_ARTIFACT_MB = "VARDRRUNNER_MAX_ARTIFACT_MB"
ENV_MAX_CONCURRENT_JOBS = "VARDRRUNNER_MAX_CONCURRENT_JOBS"
ENV_MIN_FREE_DISK_MB = "VARDRRUNNER_MIN_FREE_DISK_MB"


class ResourceLimitError(RuntimeError):
    """A local resource policy is invalid or would be exceeded."""


@dataclass(frozen=True)
class RunnerLimits:
    max_targets: int = 500
    max_artifact_bytes: int = 100 * 1024**2
    max_concurrent_jobs: int = 1
    min_free_disk_bytes: int = 512 * 1024**2


DEFAULT_LIMITS = RunnerLimits()


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ResourceLimitError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ResourceLimitError(f"{name} must be between {minimum} and {maximum}")
    return value


def load_limits() -> RunnerLimits:
    return RunnerLimits(
        max_targets=_env_int(ENV_MAX_TARGETS, 500, 1, 100_000),
        max_artifact_bytes=_env_int(ENV_MAX_ARTIFACT_MB, 100, 1, 10_240) * 1024**2,
        max_concurrent_jobs=_env_int(ENV_MAX_CONCURRENT_JOBS, 1, 1, 8),
        min_free_disk_bytes=_env_int(ENV_MIN_FREE_DISK_MB, 512, 0, 1_048_576) * 1024**2,
    )


def ensure_free_space(path: Path, minimum_bytes: int) -> int:
    """Return free bytes or raise before claim when the local reserve is breached."""
    target = path
    while not target.exists() and target != target.parent:
        target = target.parent
    try:
        free = shutil.disk_usage(target).free
    except OSError as exc:
        raise ResourceLimitError("could not determine free disk space") from exc
    if free < minimum_bytes:
        raise ResourceLimitError(
            f"free disk reserve breached ({free // 1024**2} MiB available; "
            f"{minimum_bytes // 1024**2} MiB required)"
        )
    return free


def enforce_artifact(path: Path, maximum_bytes: int) -> int:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ResourceLimitError("could not inspect output artifact") from exc
    if size > maximum_bytes:
        raise ResourceLimitError(
            f"artifact exceeds local limit ({size // 1024**2} MiB; "
            f"maximum {maximum_bytes // 1024**2} MiB)"
        )
    return size
