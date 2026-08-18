"""
vardrrunner doctor — deep preflight for unattended use.

Where `status` is a quick human glance ("show me where I stand"), `doctor`
validates the machine ("is this box safe to run unattended?") and is built for
scripts: it exits 0 only when the runner is healthy enough to work, exits
non-zero on any actionable failure, and prints a remediation hint per problem.

    vardrrunner doctor && vardrrunner daemon start --detach

Checks: credential source, backend URL validity, config-file permissions, API
auth, daemon PID health, run-dir writability, free disk, tool versions, and
per-pipeline readiness. `--json` emits a machine-readable report.
"""

import platform
import shutil
import stat
from dataclasses import dataclass
from enum import Enum

import requests
import typer
from rich.console import Console

from vardrrunner import (
    api,
    config,
    credentials,
    identity,
    pipelines,
    redaction,
    resources,
    runner,
    service,
)
from vardrrunner.commands import daemon
from vardrrunner.journal import Journal, JournalError

console = Console()

# Free-disk thresholds for the runs directory.
_DISK_WARN_BYTES = 1 * 1024**3  # 1 GiB → warn
_DISK_FAIL_BYTES = 100 * 1024**2  # 100 MiB → fail
_PRODUCTION_DISK_WARN_BYTES = 5 * 1024**3
_PRODUCTION_DISK_FAIL_BYTES = 1 * 1024**3


class Health(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class Check:
    name: str
    status: Health
    detail: str
    remediation: str = ""


# ── individual checks ────────────────────────────────────────────────────────


def _check_credentials(production: bool = False) -> list[Check]:
    url = config.get_api_url()
    source = config.credential_source()  # never the secret itself
    if not url or source is None:
        return [
            Check(
                "credentials",
                Health.FAIL,
                "no API key configured",
                "Run `vardrrunner login vardrmap`, or set VARDRMAP_URL and VARDRMAP_API_KEY.",
            )
        ]

    posture = credentials.inspect()
    checks = [Check("credentials", Health.OK, f"API key source: {source}")]

    # Storage posture: a working runner with a cleartext key is healthy but not
    # safe, and an operator provisioning a VPS needs to know which they have.
    if posture.at_rest_encrypted:
        checks.append(Check("credential storage", Health.OK, "OS keychain (encrypted at rest)"))
    elif posture.source == "environment":
        checks.append(
            Check("credential storage", Health.OK, "environment variable (not written to disk)")
        )
    elif posture.plaintext_in_config:
        checks.append(
            Check(
                "credential storage",
                Health.FAIL if production else Health.WARN,
                f"cleartext in {posture.config_file}",
                "Install a keyring backend and re-run login, or use VARDRMAP_API_KEY.",
            )
        )

    if not posture.keychain_available:
        checks.append(
            Check(
                "os keychain",
                Health.WARN,
                "no keyring backend on this machine",
                "Install gnome-keyring/kwallet (Linux), or use VARDRMAP_API_KEY on servers.",
            )
        )

    try:
        config.validate_api_url(url)
        checks.append(Check("backend url", Health.OK, url))
    except config.InvalidApiUrl as e:
        checks.append(
            Check(
                "backend url",
                Health.FAIL,
                str(e),
                "Use an https:// URL (or VARDRRUNNER_ALLOW_INSECURE=1 for non-local http).",
            )
        )
    return checks


def _check_permissions() -> Check:
    path = config.CONFIG_FILE
    if not path.exists():
        return Check("config permissions", Health.OK, "no config file")
    # Only a config file holding a plaintext key is sensitive; URL-only is fine.
    has_secret = "api_key" in config.load()
    if platform.system() == "Windows" or not has_secret:
        return Check(
            "config permissions",
            Health.OK,
            "no plaintext key in file" if not has_secret else "not enforced on Windows",
        )
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        return Check(
            "config permissions",
            Health.WARN,
            f"{oct(mode)} — group/other can read your plaintext API key",
            f"`chmod 600 {path}`, or `vardrrunner login` to move the key into the keychain",
        )
    return Check("config permissions", Health.OK, oct(mode))


def _check_auth() -> Check:
    url = config.get_api_url()
    key = config.get_api_key()
    if not url or not key:
        return Check("api auth", Health.FAIL, "skipped — no credentials", "See credentials above.")
    try:
        config.validate_api_url(url)
    except config.InvalidApiUrl:
        return Check(
            "api auth", Health.WARN, "skipped — invalid backend URL", "Fix backend URL above."
        )
    try:
        user = api.VardrMapClient(url, key).whoami()
        who = user.get("username") or user.get("github_id") or "unknown"
        return Check("api auth", Health.OK, f"authenticated as {redaction.redact_text(str(who))}")
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "?"
        return Check(
            "api auth",
            Health.FAIL,
            f"authentication failed (HTTP {code})",
            "Check the API key in Settings → API Keys; generate a new vmap_ key if revoked.",
        )
    except requests.RequestException as e:
        return Check(
            "api auth",
            Health.FAIL,
            f"backend unreachable: {redaction.redact_exception(e)}",
            "Check the backend URL and network connectivity.",
        )


def _check_daemon() -> Check:
    pid = daemon._read_pid()
    if pid is None:
        return Check("daemon", Health.OK, "not running")
    if daemon._process_alive(pid):
        return Check("daemon", Health.OK, f"running (pid {pid})")
    return Check(
        "daemon",
        Health.WARN,
        f"stale PID file (pid {pid} is not alive)",
        f"`vardrrunner daemon stop` or delete {daemon.PID_FILE}",
    )


def _check_run_dir() -> Check:
    runs = config.runs_dir()
    try:
        runs.mkdir(parents=True, exist_ok=True)
        probe = runs / ".doctor_write_test"
        probe.write_text("ok")
        probe.unlink()
        return Check("run dir writable", Health.OK, str(runs))
    except OSError as e:
        return Check(
            "run dir writable",
            Health.FAIL,
            f"{redaction.redact_text(str(runs))}: {redaction.redact_exception(e)}",
            "Ensure your home directory exists and is writable.",
        )


def _check_identity() -> Check:
    try:
        current = identity.load_or_create()
    except identity.IdentityError as e:
        return Check(
            "runner identity",
            Health.FAIL,
            redaction.redact_exception(e),
            f"Repair or remove {identity.identity_file()} and rerun doctor.",
        )
    return Check("runner identity", Health.OK, f"{current.name} ({current.runner_id})")


def _check_journal() -> Check:
    try:
        store = Journal(config.journal_file())
        store.list(limit=1)
    except (OSError, JournalError) as e:
        return Check(
            "execution journal",
            Health.FAIL,
            redaction.redact_exception(e),
            f"Ensure {config.journal_file().parent} is writable and the schema is compatible.",
        )
    return Check("execution journal", Health.OK, str(config.journal_file()))


def _check_service() -> Check:
    pid = daemon._read_pid()
    if pid and daemon._process_alive(pid):
        return Check("background service", Health.OK, f"daemon running (pid {pid})")
    try:
        plan = service.build_plan()
        active, _detail = service.status(plan)
    except service.ServiceError as e:
        return Check(
            "background service",
            Health.FAIL,
            redaction.redact_exception(e),
            "Install the package on PATH, then run `vardrrunner service install`.",
        )
    if active:
        return Check("background service", Health.OK, plan.kind)
    return Check(
        "background service",
        Health.FAIL,
        f"{plan.kind} is not active",
        "Run `vardrrunner service install` or start the daemon under your supervisor.",
    )


def _check_disk(production: bool = False) -> Check:
    target = config.runs_dir()
    while not target.exists():
        target = target.parent
    try:
        free = shutil.disk_usage(target).free
    except OSError as e:
        return Check(
            "disk space", Health.WARN, f"could not determine: {redaction.redact_exception(e)}"
        )
    human = f"{free / 1024**3:.1f} GiB free"
    fail_threshold = _PRODUCTION_DISK_FAIL_BYTES if production else _DISK_FAIL_BYTES
    warn_threshold = _PRODUCTION_DISK_WARN_BYTES if production else _DISK_WARN_BYTES
    if free < fail_threshold:
        return Check("disk space", Health.FAIL, human, "Free up disk before running scans.")
    if free < warn_threshold:
        return Check("disk space", Health.WARN, human, "Low disk — large scans may fill it.")
    return Check("disk space", Health.OK, human)


def _check_resource_policy() -> Check:
    try:
        limits = resources.load_limits()
    except resources.ResourceLimitError as e:
        return Check(
            "resource policy",
            Health.FAIL,
            redaction.redact_exception(e),
            "Correct the VARDRRUNNER_MAX_* and VARDRRUNNER_MIN_FREE_DISK_MB values.",
        )
    return Check(
        "resource policy",
        Health.OK,
        f"targets={limits.max_targets}, artifact={limits.max_artifact_bytes // 1024**2} MiB, "
        f"concurrency={limits.max_concurrent_jobs}, "
        f"disk-reserve={limits.min_free_disk_bytes // 1024**2} MiB",
    )


def _check_tools() -> list[Check]:
    checks: list[Check] = []
    available = 0
    for tool in runner.ALLOWED_TOOLS:
        if runner.tool_available(tool):
            available += 1
            checks.append(
                Check(f"tool: {tool}", Health.OK, runner.tool_version(tool) or "installed")
            )
        else:
            checks.append(
                Check(
                    f"tool: {tool}",
                    Health.WARN,
                    "not found on PATH",
                    f"Install {tool} and ensure it is on PATH.",
                )
            )
    if available == 0:
        checks.append(
            Check(
                "tools",
                Health.FAIL,
                "no scan tools installed — the runner can't do anything",
                "Install at least one of: " + ", ".join(runner.ALLOWED_TOOLS),
            )
        )
    return checks


def _check_pipelines() -> list[Check]:
    checks: list[Check] = []
    for name, stages in pipelines.PIPELINES.items():
        missing = sorted({s.tool for s in stages if not runner.tool_available(s.tool)})
        if missing:
            checks.append(
                Check(
                    f"pipeline: {name}",
                    Health.WARN,
                    f"missing {', '.join(missing)}",
                    f"Install {', '.join(missing)} to run this pipeline.",
                )
            )
        else:
            checks.append(Check(f"pipeline: {name}", Health.OK, "ready"))
    return checks


def _collect(production: bool = False) -> list[Check]:
    checks: list[Check] = []
    # Credential/permissions/auth checks all read the config file — if it's
    # corrupted we surface one clear FAIL and skip the auth attempt (which
    # would crash or mislead with a noisy follow-up error).
    try:
        checks += _check_credentials(production=production)
        checks.append(_check_permissions())
        checks.append(_check_auth())
    except config.InvalidConfigFile as e:
        checks.append(
            Check(
                "config file",
                Health.FAIL,
                redaction.redact_exception(e),
                f"Delete {config.CONFIG_FILE} or run `vardrrunner login vardrmap` to reset.",
            )
        )
    checks.append(_check_daemon())
    checks.append(_check_identity())
    checks.append(_check_journal())
    checks.append(_check_run_dir())
    checks.append(_check_resource_policy())
    checks.append(_check_disk(production=production))
    checks += _check_tools()
    checks += _check_pipelines()
    if production:
        checks.append(_check_service())
    return checks


# ── output ───────────────────────────────────────────────────────────────────

_GLYPH = {
    Health.OK: "[green]✓[/green]",
    Health.WARN: "[yellow]![/yellow]",
    Health.FAIL: "[red]✗[/red]",
}


def _print_text(checks: list[Check], failed: list[Check], warned: list[Check]) -> None:
    console.print("\n[bold]VardrRunner Doctor[/bold]")
    for c in checks:
        name = redaction.redact_rich_text(c.name)
        detail = redaction.redact_rich_text(c.detail)
        console.print(f"  {_GLYPH[c.status]} {name}: {detail}")
        if c.remediation and c.status is not Health.OK:
            console.print(f"      [dim]→ {redaction.redact_rich_text(c.remediation)}[/dim]")
    console.print()
    if failed:
        console.print(
            f"[red]✗ {len(failed)} failure(s)[/red], [yellow]{len(warned)} warning(s)[/yellow] "
            "— not ready for unattended use."
        )
    elif warned:
        console.print(
            f"[yellow]! {len(warned)} warning(s)[/yellow] — usable, but review the items above."
        )
    else:
        console.print("[green]✓ All checks passed — ready for unattended use.[/green]")


def run_doctor(as_json: bool = False, production: bool = False) -> None:
    """Run all checks, report, and exit non-zero if any check failed."""
    checks = _collect(production=production)
    failed = [c for c in checks if c.status is Health.FAIL]
    warned = [c for c in checks if c.status is Health.WARN]

    if as_json:
        payload = {
            "healthy": not failed,
            "profile": "production" if production else "standard",
            "summary": {
                "ok": sum(c.status is Health.OK for c in checks),
                "warn": len(warned),
                "fail": len(failed),
            },
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "detail": c.detail,
                    "remediation": c.remediation,
                }
                for c in checks
            ],
        }
        console.print_json(data=redaction.redact(payload))
    else:
        _print_text(checks, failed, warned)

    raise typer.Exit(1 if failed else 0)
