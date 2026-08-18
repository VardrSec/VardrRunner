"""Cross-platform user-service plans for unattended daemon operation."""

from __future__ import annotations

import os
import platform
import plistlib
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from vardrrunner import config, manifests, redaction

SERVICE_NAME = "VardrRunner"


class ServiceError(RuntimeError):
    """Service installation or control failed safely."""


@dataclass(frozen=True)
class ServicePlan:
    kind: str
    definition_path: Path | None
    definition: str | None
    install_commands: tuple[tuple[str, ...], ...]
    start_command: tuple[str, ...] | None
    stop_command: tuple[str, ...]
    uninstall_commands: tuple[tuple[str, ...], ...]
    status_command: tuple[str, ...]
    environment_file: Path | None = None


def _clean_path(path: Path) -> Path:
    text = str(path.expanduser().resolve())
    if any(ord(char) < 32 for char in text):
        raise ServiceError("service paths may not contain control characters")
    return Path(text)


def _systemd_quote(value: str) -> str:
    return '"' + value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_plan(
    *,
    executable: Path | None = None,
    system: str | None = None,
    home: Path | None = None,
    log_file: Path | None = None,
    env_file: Path | None = None,
) -> ServicePlan:
    """Build a deterministic service plan without changing the host."""
    system = system or platform.system()
    home = _clean_path(home or Path.home())
    found = str(executable) if executable else shutil.which("vardrrunner")
    if not found:
        raise ServiceError("vardrrunner executable is not on PATH")
    exe = _clean_path(Path(found))
    log = _clean_path(log_file or (config.config_dir() / "daemon.jsonl"))
    daemon_args = (
        str(exe),
        "daemon",
        "start",
        "--log-file",
        str(log),
        "--log-format",
        "json",
    )
    environment = _clean_path(env_file) if env_file else None
    if environment and system != "Linux":
        raise ServiceError("--env-file is currently supported only by systemd on Linux")
    if environment and not environment.is_file():
        raise ServiceError(f"environment file does not exist: {environment}")
    if environment and system == "Linux" and os.name != "nt":
        mode = stat.S_IMODE(environment.stat().st_mode)
        if mode & 0o077:
            raise ServiceError(
                f"environment file permissions {oct(mode)} expose credentials; use chmod 600"
            )

    if system == "Linux":
        path = home / ".config" / "systemd" / "user" / "vardrrunner.service"
        env_line = f"EnvironmentFile={_systemd_quote(str(environment))}\n" if environment else ""
        definition = (
            "[Unit]\nDescription=VardrRunner local security worker\nAfter=network-online.target\n"
            "Wants=network-online.target\n\n[Service]\nType=simple\n"
            f"{env_line}ExecStart={' '.join(_systemd_quote(arg) for arg in daemon_args)}\n"
            "Restart=on-failure\nRestartSec=10\nTimeoutStopSec=1800\n\n"
            "[Install]\nWantedBy=default.target\n"
        )
        return ServicePlan(
            "systemd-user",
            path,
            definition,
            (("systemctl", "--user", "daemon-reload"),),
            ("systemctl", "--user", "enable", "--now", "vardrrunner.service"),
            ("systemctl", "--user", "stop", "vardrrunner.service"),
            (
                ("systemctl", "--user", "disable", "--now", "vardrrunner.service"),
                ("systemctl", "--user", "daemon-reload"),
            ),
            ("systemctl", "--user", "status", "vardrrunner.service", "--no-pager"),
            environment_file=environment,
        )

    if system == "Darwin":
        path = home / "Library" / "LaunchAgents" / "com.vardrsec.vardrrunner.plist"
        document = {
            "Label": "com.vardrsec.vardrrunner",
            "ProgramArguments": list(daemon_args),
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ProcessType": "Background",
        }
        definition = plistlib.dumps(document, fmt=plistlib.FMT_XML).decode("utf-8")
        getuid = getattr(os, "getuid", None)
        if getuid is None:  # pragma: no cover - Darwin always provides getuid
            raise ServiceError("launchd user identity is unavailable")
        domain = f"gui/{getuid()}"
        return ServicePlan(
            "launchd-user",
            path,
            definition,
            (),
            ("launchctl", "bootstrap", domain, str(path)),
            ("launchctl", "bootout", domain, str(path)),
            (("launchctl", "bootout", domain, str(path)),),
            ("launchctl", "print", f"{domain}/com.vardrsec.vardrrunner"),
            environment_file=None,
        )

    if system == "Windows":
        task_command = subprocess.list2cmdline(list(daemon_args))
        create = (
            "schtasks.exe",
            "/Create",
            "/TN",
            SERVICE_NAME,
            "/SC",
            "ONLOGON",
            "/TR",
            task_command,
            "/F",
        )
        return ServicePlan(
            "scheduled-task",
            None,
            None,
            (create,),
            ("schtasks.exe", "/Run", "/TN", SERVICE_NAME),
            ("schtasks.exe", "/End", "/TN", SERVICE_NAME),
            (("schtasks.exe", "/Delete", "/TN", SERVICE_NAME, "/F"),),
            ("schtasks.exe", "/Query", "/TN", SERVICE_NAME, "/V", "/FO", "LIST"),
            environment_file=None,
        )

    raise ServiceError(f"service installation is unsupported on {system}")


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


def install(plan: ServicePlan, *, start: bool = True) -> None:
    if plan.kind == "launchd-user" and start:
        _run(plan.stop_command, tolerate_missing=True)
    if plan.definition_path and plan.definition is not None:
        manifests.write_atomic_text(plan.definition_path, plan.definition)
    for command in plan.install_commands:
        _run(command)
    if start and plan.start_command:
        _run(plan.start_command)


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
