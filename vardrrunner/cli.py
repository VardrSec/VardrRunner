"""
vardrrunner — local automation runner for the VardrSec product family.

Runs security tooling on the operator's machine and syncs results to a VardrSec
backend (today: VardrMap) over HTTP. See https://github.com/jorge-aquino/VardrRunner.
"""

from pathlib import Path

import typer
from rich.console import Console

from vardrrunner.commands import auth, engagements, imports, jobs, run
from vardrrunner.commands import daemon as daemon_cmd
from vardrrunner.commands import doctor as doctor_cmd
from vardrrunner.commands import heartbeat as heartbeat_cmd
from vardrrunner.commands import pipeline as pipeline_cmd
from vardrrunner.commands import status as status_cmd

console = Console()
app = typer.Typer(
    name="vardrrunner",
    help="Local runner for VardrMap. Runs tools locally, uploads results to your VardrMap instance.",
    no_args_is_help=True,
)

# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #

login_app = typer.Typer(help="Log in to a Vardr product.", no_args_is_help=True)
app.add_typer(login_app, name="login")
login_app.command("vardrmap")(auth.login_vardrmap)


@app.command()
def status():
    """Show config, API connectivity, and local tool availability."""
    status_cmd.run_status()


@app.command()
def doctor(
    as_json: bool = typer.Option(False, "--json", help="Emit a machine-readable JSON report"),
):
    """Deep preflight before unattended use — exits non-zero on actionable failures."""
    doctor_cmd.run_doctor(as_json=as_json)


@app.command()
def heartbeat():
    """Send a heartbeat to VardrMap — reports hostname, version, and tool status."""
    heartbeat_cmd.send_heartbeat(quiet=False)


@app.command()
def logout():
    """Remove stored credentials (keychain + config file); keep the API URL."""
    auth.logout()


@app.command()
def whoami():
    """Show the identity tied to the configured API key."""
    auth.whoami()


# --------------------------------------------------------------------------- #
# Programs
# --------------------------------------------------------------------------- #


@app.command()
def engagement_list():
    """List all engagements in VardrMap."""
    engagements.list_engagements()


# Alias `engagements` → `engagement-list` for a more natural UX
app.command(name="engagements")(engagement_list)
# Retired name, kept so existing habits and scripts do not break. Hidden from
# --help so only the current name is advertised.
app.command(name="programs", hidden=True)(engagement_list)


@app.command()
def scope(engagement_id: str = typer.Argument(..., help="Engagement UUID")):
    """Show in-scope and out-of-scope items for an engagement."""
    engagements.show_scope(engagement_id)


# --------------------------------------------------------------------------- #
# Import
# --------------------------------------------------------------------------- #

import_app = typer.Typer(help="Import tool output files into VardrMap.", no_args_is_help=True)
app.add_typer(import_app, name="import")


@import_app.command("nuclei")
def import_nuclei(
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    file: Path = typer.Option(..., "--file", "-f", help="Path to nuclei JSONL output"),
):
    """Import a nuclei output file."""
    imports.import_file("nuclei", engagement_id, file)


@import_app.command("httpx")
def import_httpx(
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    file: Path = typer.Option(..., "--file", "-f", help="Path to httpx JSON/JSONL output"),
):
    """Import an httpx output file."""
    imports.import_file("httpx", engagement_id, file)


@import_app.command("ffuf")
def import_ffuf(
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    file: Path = typer.Option(..., "--file", "-f", help="Path to ffuf JSON output"),
):
    """Import an ffuf output file."""
    imports.import_file("ffuf", engagement_id, file)


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# Daemon
# --------------------------------------------------------------------------- #

daemon_app = typer.Typer(
    help="Long-running background worker: polls jobs and sends heartbeats.", no_args_is_help=True
)
app.add_typer(daemon_app, name="daemon")


@daemon_app.command("start")
def daemon_start(
    detach: bool = typer.Option(False, "--detach", "-d", help="Run in background"),
    poll_interval: int = typer.Option(5, "--poll-interval", help="Seconds between job polls"),
    heartbeat_interval: int = typer.Option(
        60, "--heartbeat-interval", help="Seconds between heartbeats"
    ),
    log_file: Path | None = typer.Option(None, "--log-file", help="Append output to file"),
):
    """Start the daemon (foreground by default, use --detach for background)."""
    daemon_cmd.start(
        detach=detach,
        poll_interval=poll_interval,
        heartbeat_interval=heartbeat_interval,
        log_file=log_file,
    )


@daemon_app.command("stop")
def daemon_stop():
    """Stop a running daemon."""
    daemon_cmd.stop()


@daemon_app.command("status")
def daemon_status():
    """Show whether the daemon is running."""
    daemon_cmd.status()


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #

jobs_app = typer.Typer(help="Manage and execute scan job queue.", no_args_is_help=True)
app.add_typer(jobs_app, name="jobs")


@jobs_app.command("list")
def jobs_list():
    """List pending scan jobs."""
    jobs.list_jobs()


@jobs_app.command("run")
def jobs_run(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompts"),
):
    """Claim and execute all pending scan jobs."""
    jobs.run_jobs(yes=yes)


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #

run_app = typer.Typer(
    help="Run a tool locally and upload results to VardrMap.", no_args_is_help=True
)
app.add_typer(run_app, name="run")


@run_app.command("httpx")
def run_httpx(
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(100, "--limit", help="Max recon items to use (--from-recon only)"),
    status_code: int | None = typer.Option(
        None, "--status-code", help="Filter recon by HTTP status code"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Run httpx locally and upload results to VardrMap."""
    run.run_httpx(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        status_code=status_code,
        yes=yes,
    )


@run_app.command("subfinder")
def run_subfinder(
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Run subfinder against wildcard scope entries and import discovered hosts."""
    run.run_subfinder(engagement_id=engagement_id, yes=yes)


@run_app.command("nuclei")
def run_nuclei(
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(100, "--limit", help="Max recon items to use (--from-recon only)"),
    status_code: int | None = typer.Option(
        None, "--status-code", help="Filter recon by HTTP status code"
    ),
    severity: str | None = typer.Option(
        None, "--severity", help="Comma-separated severities, e.g. high,critical"
    ),
    templates: str | None = typer.Option(
        None, "--templates", "-t", help="Nuclei template path or tag"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Run nuclei locally and upload results to VardrMap."""
    run.run_nuclei(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        status_code=status_code,
        severity=severity,
        templates=templates,
        yes=yes,
    )


@run_app.command("nmap")
def run_nmap(
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(500, "--limit", help="Max recon items to use (--from-recon only)"),
    top_ports: int = typer.Option(100, "--top-ports", help="Number of most-common ports to scan"),
    timing: int = typer.Option(
        3, "--timing", help="nmap timing template (0-4; 5 is never allowed)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Run nmap service discovery locally and upload open ports to VardrMap."""
    run.run_nmap(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        top_ports=top_ports,
        timing=timing,
        yes=yes,
    )


@run_app.command("dnsx")
def run_dnsx(
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(500, "--limit", help="Max recon items to use (--from-recon only)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Resolve hosts with dnsx and upload the resolvable ones as recon targets."""
    run.run_dnsx(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        yes=yes,
    )


@run_app.command("naabu")
def run_naabu(
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(500, "--limit", help="Max recon items to use (--from-recon only)"),
    top_ports: int = typer.Option(100, "--top-ports", help="Number of most-common ports to scan"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Port-scan hosts with naabu locally and upload open ports to VardrMap."""
    run.run_naabu(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        top_ports=top_ports,
        yes=yes,
    )


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #

pipeline_app = typer.Typer(help="Run a chain of tools as one recon pipeline.", no_args_is_help=True)
app.add_typer(pipeline_app, name="pipeline")


@pipeline_app.command("list")
def pipeline_list():
    """List the available pipelines and their tool chains."""
    pipeline_cmd.list_pipelines()


@pipeline_app.command("run")
def pipeline_run(
    name: str = typer.Argument(..., help="Pipeline name (see `pipeline list`)"),
    engagement_id: str = typer.Option(
        ..., "--engagement", "--program", "-p", help="Engagement UUID"
    ),
    severity: str | None = typer.Option(
        None, "--severity", help="nuclei severity filter for the scan stage"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    continue_on_error: bool = typer.Option(
        False, "--continue-on-error", help="Keep going if a stage fails"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Resolve first-stage targets and print the plan without executing"
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit a machine-readable JSON result"),
):
    """Run every stage of a pipeline in order against an engagement."""
    pipeline_cmd.run_pipeline(
        name,
        engagement_id,
        severity=severity,
        yes=yes,
        continue_on_error=continue_on_error,
        dry_run=dry_run,
        as_json=as_json,
    )
