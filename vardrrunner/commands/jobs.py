"""
Job queue commands: list pending jobs and run them locally.

The UI creates job records; VardrRunner polls /jobs/pending, claims each job,
runs the matching tool handler, and reports lifecycle events. This module owns the
uniform *lifecycle* (availability → config → targets → claim → run → upload →
done/fail); the per-tool specifics live in ``vardrrunner.handlers``.
"""

import logging

import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import api, config, configs, handlers, runner
from vardrrunner.commands.heartbeat import send_heartbeat
from vardrrunner.commands.run import _confirm, _make_run_dir

console = Console()


def list_jobs() -> None:
    """Show all pending scan jobs for the authenticated user."""
    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)
    jobs = client.pending_jobs()

    if not jobs:
        console.print("[dim]No pending jobs.[/dim]")
        raise typer.Exit(0)

    table = Table(title="Pending Scan Jobs")
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Tool", style="bold")
    table.add_column("Source")
    table.add_column("Config", style="dim")
    table.add_column("Created")

    for j in jobs:
        cfg_str = "  ".join(f"{k}={v}" for k, v in (j.get("config") or {}).items())
        table.add_row(
            j["id"][:8] + "…",
            j["tool_type"],
            j["target_source"],
            cfg_str or "—",
            j.get("created_at", "")[:16],
        )

    console.print(table)


def _emit(client: api.VardrMapClient, job_id: str, kind: str, text: str = "") -> None:
    """Post a job event; log failures so operators can diagnose stuck jobs."""
    try:
        client.post_event(job_id, kind, text)
    except Exception as e:
        logging.warning("Failed to post event %r for job %s: %s", kind, job_id, e)


def _fail_job(client: api.VardrMapClient, con: Console, job_id: str, error: str) -> None:
    """Mark a job failed and emit the matching event — the single failure path."""
    con.print(f"[red]Job failed:[/red] {error}")
    client.complete_job(job_id, "failed", error=error[:500])
    _emit(client, job_id, "failed", error[:500])


def _complete_done(client: api.VardrMapClient, job_id: str, note: str = "") -> None:
    """Mark a job done and emit the matching event — the single success path."""
    client.complete_job(job_id, "done")
    _emit(client, job_id, "done", note)


def _execute_one(client: api.VardrMapClient, con: Console, job: dict, yes: bool) -> None:
    """Run a single job through the uniform lifecycle, delegating specifics to its handler."""
    # Validate the job envelope before touching any field — a drifted/partial payload
    # must fail cleanly, not crash the loop with a KeyError.
    try:
        env = configs.JobEnvelope.from_dict(job)
    except configs.ConfigError as e:
        job_id = job.get("id")
        if job_id:
            _fail_job(client, con, str(job_id), f"malformed job: {e}")
        else:
            con.print(f"[red]Skipping malformed job:[/red] {e}")
        return

    job_id = env.id
    tool_type = env.tool_type
    target_src = env.target_source
    engagement_id = env.engagement_id
    cfg = env.config

    con.rule(f"Job {job_id[:8]}… — {tool_type} / {target_src}")

    handler = handlers.REGISTRY.get(tool_type)
    if handler is None:
        _fail_job(client, con, job_id, f"unknown tool type {tool_type!r}")
        return
    # Capability check before claiming — never claim work this runner can't do.
    if not runner.tool_available(handler.tool):
        _fail_job(client, con, job_id, f"'{handler.tool}' not found on PATH")
        return

    try:
        tool_cfg = handler.parse_config(cfg)
    except configs.ConfigError as e:
        _fail_job(client, con, job_id, f"invalid config: {e}")
        return

    try:
        targets = handler.resolve_targets(client, engagement_id, target_src, tool_cfg)
    except Exception as e:  # resolution failure must not crash the loop
        _fail_job(client, con, job_id, f"failed to resolve targets: {e}")
        return

    if not targets:
        con.print("[yellow]No targets resolved — marking job done.[/yellow]")
        _complete_done(client, job_id, "no targets resolved")
        return

    _confirm(targets, tool_type, yes)

    try:
        client.claim_job(job_id)
    except Exception as e:
        # 409 = another runner won the race; just move on without failing the job.
        con.print(f"[red]Could not claim job:[/red] {e}")
        return

    _emit(client, job_id, "started", f"claimed job · {len(targets)} target(s) from {target_src}")
    _emit(client, job_id, "targets_resolved", f"{len(targets)} target(s) from {target_src}")

    run_dir = _make_run_dir()
    label = handler.running_label(targets, tool_cfg)
    try:
        con.print(f"Running {label}…")
        _emit(client, job_id, "running", f"running {label}")
        output = handler.execute(targets, run_dir, tool_cfg)

        if output is None or not output.exists() or output.stat().st_size == 0:
            con.print("[yellow]No output produced — nothing to upload.[/yellow]")
            _complete_done(client, job_id, f"{tool_type} produced no output")
            return

        con.print("Uploading results…")
        summary = handler.upload(client, engagement_id, output, job_id=job_id)
        con.print(f"[green]Done.[/green] {summary}")
        _emit(client, job_id, "uploaded", summary)
        _complete_done(client, job_id)
    except runner.ToolTimeout as e:
        _fail_job(client, con, job_id, str(e))
    except Exception as e:
        _fail_job(client, con, job_id, str(e))


def execute_pending_jobs(client: api.VardrMapClient, con: Console, yes: bool = True) -> int:
    """Claim and execute all pending jobs. Returns the number of jobs found (0 if empty)."""
    jobs_list = client.pending_jobs()
    if not jobs_list:
        return 0

    con.print(f"Found [bold]{len(jobs_list)}[/bold] pending job(s).")
    for job in jobs_list:
        _execute_one(client, con, job, yes)
    return len(jobs_list)


def run_jobs(yes: bool = False) -> None:
    """Claim and execute all pending jobs for the authenticated user."""
    send_heartbeat(quiet=True)
    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)
    executed = execute_pending_jobs(client, console, yes=yes)
    if executed == 0:
        console.print("[dim]No pending jobs.[/dim]")
        raise typer.Exit(0)
