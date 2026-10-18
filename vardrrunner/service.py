"""Inspect and remove legacy startup services; never create or start them."""

from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path

from vardrrunner import redaction

SERVICE_NAME = "VardrRunner"


class ServiceError(RuntimeError):
    """Service installation or control failed safely."""


@dataclass(frozen=True)
class ServicePlan:
    kind: str
    definition_path: Path | None
    uninstall_commands: tuple[tuple[str, ...], ...]
    status_command: tuple[str, ...]


def _clean_path(path: Path) -> Path:
    text = str(path.expanduser().resolve())
    if any(ord(char) < 32 for char in text):
        raise ServiceError("service paths may not contain control characters")
    return Path(text)


def build_plan(*, system: str | None = None, home: Path | None = None) -> ServicePlan:
    """Build only status/removal commands for services installed by older versions."""
    system = system or platform.system()
    home = _clean_path(home or Path.home())
    if system == "Linux":
        return ServicePlan(
            "systemd-user",
            home / ".config" / "systemd" / "user" / "vardrrunner.service",
            (
                ("systemctl", "--user", "disable", "--now", "vardrrunner.service"),
                ("systemctl", "--user", "daemon-reload"),
            ),
            ("systemctl", "--user", "status", "vardrrunner.service", "--no-pager"),
        )
    if system == "Darwin":
        path = home / "Library" / "LaunchAgents" / "com.vardrsec.vardrrunner.plist"
        getuid = getattr(os, "getuid", None)
        if getuid is None:  # pragma: no cover - Darwin always provides getuid
            raise ServiceError("launchd user identity is unavailable")
        domain = f"gui/{getuid()}"
        return ServicePlan(
            "launchd-user",
            path,
            (("launchctl", "bootout", domain, str(path)),),
            ("launchctl", "print", f"{domain}/com.vardrsec.vardrrunner"),
        )
    if system == "Windows":
        return ServicePlan(
            "scheduled-task",
            None,
            (
                ("schtasks.exe", "/End", "/TN", SERVICE_NAME),
                ("schtasks.exe", "/Delete", "/TN", SERVICE_NAME, "/F"),
            ),
            ("schtasks.exe", "/Query", "/TN", SERVICE_NAME, "/V", "/FO", "LIST"),
        )
    raise ServiceError(f"legacy service cleanup is unsupported on {system}")


def _run(
    command: tuple[str, ...], *, tolerate_missing: bool = False
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ServiceError(redaction.redact_exception(exc)) from exc
    if result.returncode != 0 and not tolerate_missing:
        detail = redaction.redact_text((result.stderr or result.stdout or "").strip())
        raise ServiceError(f"service command failed ({result.returncode}): {detail}")
    return result


def uninstall(plan: ServicePlan) -> None:
    commands = list(plan.uninstall_commands)
    if plan.definition_path and commands:
        _run(commands.pop(0), tolerate_missing=True)
        plan.definition_path.unlink(missing_ok=True)
    for command in commands:
        _run(command, tolerate_missing=True)


def status(plan: ServicePlan) -> tuple[bool, str]:
    result = _run(plan.status_command, tolerate_missing=True)
    text = redaction.redact_text((result.stdout or result.stderr or "").strip())
    return result.returncode == 0, text
