"""
Run a tool against targets fetched from VardrMap, then upload the results.
Tools execute locally — scan traffic comes from the user's machine.

Direct `run` commands share the same typed configs and tool handlers as backend
jobs and pipelines: they resolve targets (with the richer inline/file sources),
validate options through the handler's config, then reuse the handler's
execute + upload. So `run nmap --timing 9` is rejected exactly like a job would be.
"""

import datetime
import shutil
from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import api, config, configs, handlers, redaction, resources, runner, targets

_PRUNE_AFTER_DAYS = 7


def _prune_run_dirs() -> None:
    """Delete run directories older than _PRUNE_AFTER_DAYS days."""
    runs = config.runs_dir()
    if not runs.exists():
        return
    cutoff = datetime.datetime.now().timestamp() - _PRUNE_AFTER_DAYS * 86400
    for d in runs.iterdir():
        if d.is_dir() and d.stat().st_mtime < cutoff:
            shutil.rmtree(d, ignore_errors=True)


# Re-exported so existing call sites and tests can patch them here.
from vardrrunner.targets import _is_wildcard, _resolve_targets  # noqa: E402, F401

console = Console()

# Default cap on target count; 0 disables the check.
MAX_TARGETS_DEFAULT = 500


def validate_max_targets(max_targets: int) -> None:
    """Reject a negative cap.

    The cap checks are written as `max_targets > 0`, so any negative value skips
    them entirely — a silently disabled safety guard. Only 0 is documented as
    disabling the cap, and a disabled guard should be something the operator
    typed deliberately, not the result of a stray minus sign.
    """
    if max_targets < 0:
        console.print(
            f"[red]Aborted:[/red] --max-targets must be 0 or greater (got {max_targets}). "
            f"Pass [bold]--max-targets 0[/bold] to disable the cap."
        )
        raise typer.Exit(1)


def _check_target_cap(targets: list[str], max_targets: int) -> None:
    """Abort if target count exceeds max_targets. Skipped when max_targets == 0."""
    validate_max_targets(max_targets)
    if max_targets > 0 and len(targets) > max_targets:
        console.print(
            f"[red]Aborted:[/red] {len(targets)} targets exceeds --max-targets {max_targets}. "
            f"Pass [bold]--max-targets 0[/bold] to disable, or raise the limit explicitly."
        )
        raise typer.Exit(1)


def _make_run_dir() -> Path:
    _prune_run_dirs()
    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    run_dir = config.runs_dir() / ts
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _execute(run_callable):
    """Run a tool callable, exiting cleanly on timeout instead of dumping a traceback."""
    try:
        return run_callable()
    except runner.ToolTimeout as e:
        console.print(f"[red]{redaction.redact_rich_exception(e)}[/red]")
        raise typer.Exit(1) from e


def _confirm(targets: list[str], tool: str, yes: bool) -> None:
    """Show a dry-run preview and ask for confirmation unless --yes is passed."""
    console.print(f"\n[bold]Targets ({len(targets)}):[/bold]")
    for t in targets[:10]:
        console.print(f"  {redaction.redact_rich_text(t)}")
    if len(targets) > 10:
        console.print(f"  [dim]… and {len(targets) - 10} more[/dim]")

    if not yes:
        confirmed = typer.confirm(f"\nRun {tool} against {len(targets)} target(s)?", default=False)
        if not confirmed:
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit(0)


def _build_config(tool: str, raw: dict):
    """Validate CLI options through the tool's typed config; exit on bad values."""
    try:
        return handlers.REGISTRY[tool].parse_config(raw)
    except configs.ConfigError as e:
        console.print(f"[red]Invalid options:[/red] {redaction.redact_rich_exception(e)}")
        raise typer.Exit(1) from e


def _finish(tool: str, client: api.VardrMapClient, engagement_id: str, targets, tool_cfg, run_dir):
    """Execute a tool handler and upload its output — shared by every direct command."""
    handler = handlers.REGISTRY[tool]
    label = redaction.redact_rich_text(handler.running_label(targets, tool_cfg))
    safe_run_dir = redaction.redact_rich_text(str(run_dir))
    console.print(f"\nRunning {label}… → [dim]{safe_run_dir}[/dim]")
    try:
        limits = resources.load_limits()
        resources.ensure_free_space(run_dir, limits.min_free_disk_bytes)
    except resources.ResourceLimitError as e:
        console.print(f"[red]Resource policy blocked execution:[/red] {e}")
        raise typer.Exit(1) from e
    output = _execute(lambda: handler.execute(targets, run_dir, tool_cfg))

    if output is None or not output.exists() or output.stat().st_size == 0:
        console.print("[yellow]No output produced — nothing to upload.[/yellow]")
        raise typer.Exit(0)

    try:
        resources.enforce_artifact(output, limits.max_artifact_bytes)
    except resources.ResourceLimitError as e:
        console.print(f"[red]Artifact blocked:[/red] {redaction.redact_rich_exception(e)}")
        console.print(f"Raw output saved at [dim]{redaction.redact_rich_text(str(output))}[/dim]")
        raise typer.Exit(1) from e

    console.print("Uploading results…")
    try:
        summary = handler.upload(client, engagement_id, output)
    except Exception as e:
        console.print(f"[red]Upload failed:[/red] {redaction.redact_rich_exception(e)}")
        console.print(f"Raw output saved at [dim]{redaction.redact_rich_text(str(output))}[/dim]")
        raise typer.Exit(1) from e
    console.print(f"[green]Done.[/green] {redaction.redact_rich_text(str(summary))}")


def run_httpx(
    engagement_id: str,
    scope: bool = False,
    from_recon: bool = False,
    target: str | None = None,
    targets_file: Path | None = None,
    limit: int = 100,
    status_code: int | None = None,
    yes: bool = False,
    max_targets: int = MAX_TARGETS_DEFAULT,
):
    """Run httpx and upload results to VardrMap."""
    runner.check_tool("httpx")
    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)

    targets = _resolve_targets(
        client, engagement_id, scope, from_recon, target, targets_file, status_code, limit
    )
    if not targets:
        console.print("[yellow]No targets found.[/yellow]")
        raise typer.Exit(0)

    _check_target_cap(targets, max_targets)
    _confirm(targets, "httpx", yes)
    cfg = _build_config("httpx", {"limit": limit, "status_code": status_code})
    _finish("httpx", client, engagement_id, targets, cfg, _make_run_dir())


def run_subfinder(
    engagement_id: str,
    yes: bool = False,
    max_targets: int = MAX_TARGETS_DEFAULT,
):
    """Run subfinder against wildcard scope entries and upload discovered hosts as recon."""
    runner.check_tool("subfinder")
    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)

    cfg = _build_config("subfinder", {})
    try:
        domains = targets.validate_targets(
            handlers.REGISTRY["subfinder"].resolve_targets(client, engagement_id, "scope", cfg)
        )
    except targets.TargetValidationError as e:
        console.print(f"[red]Invalid scope target:[/red] {redaction.redact_rich_exception(e)}")
        raise typer.Exit(1) from e
    if not domains:
        console.print("[yellow]No wildcard scope entries found.[/yellow]")
        raise typer.Exit(0)

    _check_target_cap(domains, max_targets)
    _confirm(domains, "subfinder", yes)
    _finish("subfinder", client, engagement_id, domains, cfg, _make_run_dir())


def run_nuclei(
    engagement_id: str,
    scope: bool = False,
    from_recon: bool = False,
    target: str | None = None,
    targets_file: Path | None = None,
    limit: int = 100,
    status_code: int | None = None,
    severity: str | None = None,
    templates: str | None = None,
    yes: bool = False,
    max_targets: int = MAX_TARGETS_DEFAULT,
):
    """Run nuclei and upload results to VardrMap."""
    runner.check_tool("nuclei")
    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)

    targets = _resolve_targets(
        client, engagement_id, scope, from_recon, target, targets_file, status_code, limit
    )
    if not targets:
        console.print("[yellow]No targets found.[/yellow]")
        raise typer.Exit(0)

    _check_target_cap(targets, max_targets)
    _confirm(targets, "nuclei", yes)
    # Validates the severity filter (same as a job would) before any work.
    cfg = _build_config(
        "nuclei",
        {
            "limit": limit,
            "status_code": status_code,
            "severity": severity,
            "templates": templates,
        },
    )
    _finish("nuclei", client, engagement_id, targets, cfg, _make_run_dir())


def run_nmap(
    engagement_id: str,
    scope: bool = False,
    from_recon: bool = False,
    target: str | None = None,
    targets_file: Path | None = None,
    limit: int = 500,
    top_ports: int = 100,
    timing: int = 3,
    yes: bool = False,
    max_targets: int = MAX_TARGETS_DEFAULT,
):
    """Run nmap service discovery and upload open ports to VardrMap's services API."""
    runner.check_tool("nmap")
    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)

    targets = _resolve_targets(
        client, engagement_id, scope, from_recon, target, targets_file, None, limit
    )
    # nmap wants hostnames/IPs, not full URLs; normalize and de-duplicate.
    targets = list(dict.fromkeys(runner.strip_url_to_host(t) for t in targets if t.strip()))
    if not targets:
        console.print("[yellow]No targets found.[/yellow]")
        raise typer.Exit(0)

    _check_target_cap(targets, max_targets)
    _confirm(targets, "nmap", yes)
    # Validates timing (0-4) and top_ports up front — `--timing 9` is rejected, not clamped.
    cfg = _build_config("nmap", {"top_ports": top_ports, "timing": timing, "limit": limit})
    _finish("nmap", client, engagement_id, targets, cfg, _make_run_dir())


def run_dnsx(
    engagement_id: str,
    scope: bool = False,
    from_recon: bool = False,
    target: str | None = None,
    targets_file: Path | None = None,
    limit: int = 500,
    yes: bool = False,
    max_targets: int = MAX_TARGETS_DEFAULT,
):
    """Resolve hosts with dnsx and upload the resolvable ones as recon targets."""
    runner.check_tool("dnsx")
    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)

    raw = _resolve_targets(
        client, engagement_id, scope, from_recon, target, targets_file, None, limit
    )
    targets = list(dict.fromkeys(runner.strip_url_to_host(t) for t in raw if t.strip()))
    if not targets:
        console.print("[yellow]No targets found.[/yellow]")
        raise typer.Exit(0)

    _check_target_cap(targets, max_targets)
    _confirm(targets, "dnsx", yes)
    cfg = _build_config("dnsx", {"limit": limit})
    _finish("dnsx", client, engagement_id, targets, cfg, _make_run_dir())


def run_naabu(
    engagement_id: str,
    scope: bool = False,
    from_recon: bool = False,
    target: str | None = None,
    targets_file: Path | None = None,
    limit: int = 500,
    top_ports: int = 100,
    yes: bool = False,
    max_targets: int = MAX_TARGETS_DEFAULT,
):
    """Port-scan hosts with naabu and upload open ports to VardrMap's services API."""
    runner.check_tool("naabu")
    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)

    raw = _resolve_targets(
        client, engagement_id, scope, from_recon, target, targets_file, None, limit
    )
    targets = list(dict.fromkeys(runner.strip_url_to_host(t) for t in raw if t.strip()))
    if not targets:
        console.print("[yellow]No targets found.[/yellow]")
        raise typer.Exit(0)

    _check_target_cap(targets, max_targets)
    _confirm(targets, "naabu", yes)
    cfg = _build_config("naabu", {"top_ports": top_ports, "limit": limit})
    _finish("naabu", client, engagement_id, targets, cfg, _make_run_dir())
