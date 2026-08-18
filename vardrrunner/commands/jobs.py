"""
Job queue commands: list pending jobs and run them locally.

The UI creates job records; VardrRunner polls /jobs/pending, claims each job,
runs the matching tool handler, and reports lifecycle events. This module owns the
uniform *lifecycle* (availability → config → targets → claim → run → upload →
done/fail); the per-tool specifics live in ``vardrrunner.handlers``.
"""

import logging
import time
from collections.abc import Callable, MutableMapping

import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import api, config, configs, errors, handlers, policy, redaction, runner
from vardrrunner.commands.heartbeat import send_heartbeat
from vardrrunner.commands.run import _confirm, _make_run_dir

console = Console()

# Stop-work is rechecked periodically rather than every daemon poll.  A
# permanent in-memory block would leave work unavailable after the operator
# lifts the halt until someone notices and restarts the service.
STOP_WORK_RECHECK_SECONDS = 60.0


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
        safe_cfg = redaction.redact(j.get("config") or {})
        cfg_str = "  ".join(f"{k}={v}" for k, v in safe_cfg.items())
        table.add_row(
            redaction.redact_text(str(j["id"]))[:8] + "…",
            redaction.redact_text(str(j["tool_type"])),
            redaction.redact_text(str(j["target_source"])),
            cfg_str or "—",
            redaction.redact_text(str(j.get("created_at", "")))[:16],
        )

    console.print(table)


def _emit(client: api.VardrMapClient, job_id: str, kind: str, text: str = "") -> None:
    """Post a job event, sanitized.

    Event text is written to the backend and rendered in its Terminal, so this
    is a trust boundary: everything crossing it goes through the redactor first.
    Failures are logged rather than raised — a lost event must not fail a job
    that otherwise succeeded.
    """
    try:
        client.post_event(job_id, kind, redaction.redact_text(text))
    except Exception as e:
        logging.warning(
            "Failed to post event %r for job %s: %s", kind, job_id, redaction.redact_exception(e)
        )


def _fail_job(client: api.VardrMapClient, con: Console, job_id: str, error: str) -> None:
    """Mark a job failed and emit the matching event — the single failure path.

    The reason is sanitized before it reaches the terminal *or* the backend.
    Failure messages routinely quote the command, URL or payload that failed,
    which is precisely where a credential ends up.
    """
    safe = redaction.redact_text(error)[:500]
    con.print(f"[red]Job failed:[/red] {redaction.redact_rich_text(error)[:500]}")
    client.complete_job(job_id, "failed", error=safe)
    _emit(client, job_id, "failed", safe)


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
            con.print(f"[red]Skipping malformed job:[/red] {redaction.redact_rich_exception(e)}")
        return

    job_id = env.id
    tool_type = env.tool_type
    target_src = env.target_source
    engagement_id = env.engagement_id
    cfg = env.config

    con.rule(redaction.redact_rich_text(f"Job {job_id[:8]}… — {tool_type} / {target_src}"))

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
        claimed = client.claim_job(job_id)
    except errors.StopWorkError as e:
        # The operator's own halt switch. Never presented as a claim failure,
        # and never silently retried — see StopWork handling in the daemon.
        con.print(
            "[bold red]STOP-WORK — not running this job.[/bold red] "
            f"{redaction.redact_rich_text(str(e))}"
        )
        _emit(client, job_id, "blocked", f"stop-work engaged: {redaction.redact_text(str(e))}")
        raise
    except errors.ClaimRace as e:
        # Expected and benign: the job belongs to whoever won. Leave it pending
        # for them; marking it failed would destroy another runner's work.
        con.print(f"[dim]Skipping — {redaction.redact_rich_text(str(e))}[/dim]")
        return
    except errors.RunnerError as e:
        con.print(
            f"[red]Could not claim job ({e.category.value}):[/red] "
            f"{redaction.redact_rich_text(str(e))}"
        )
        return
    except Exception as e:
        # Daemon boundary: an unclassified claim failure must not kill the poll
        # loop or wrongly mark another runner's job failed. Logged for triage.
        safe = redaction.redact_exception(e)
        logging.warning("Unclassified claim failure for job %s: %s", job_id, safe)
        con.print(
            f"[red]Could not claim job ({errors.FailureCategory.UNKNOWN.value}):[/red] "
            f"{redaction.redact_rich_exception(e)}"
        )
        return

    # Advisory findings from the backend's policy evaluation. Shown before any
    # tool runs so the operator sees them while they can still intervene; they
    # do not block, by design (ADR 0001 amendment).
    warnings = policy.parse_warnings(claimed)
    if warnings:
        for line in policy.format_warnings(warnings):
            con.print(line)
        _emit(client, job_id, "policy_warning", policy.summarize(warnings))
        if policy.has_stop_work(warnings):
            reason = next(w.describe() for w in warnings if w.reason == "stop_work_active")
            safe_reason = redaction.redact_text(reason)
            con.print(
                "[bold red]STOP-WORK — not running this job.[/bold red] "
                f"{redaction.redact_rich_text(reason)}"
            )
            _emit(client, job_id, "blocked", safe_reason)
            # A warning arrives only after a successful claim, so release the
            # job back to pending before halting. Otherwise it would remain
            # stuck in running even though no subprocess started.
            try:
                client.complete_job(job_id, "pending")
            except Exception as release_error:
                logging.warning(
                    "Failed to release stop-work job %s: %s",
                    job_id,
                    redaction.redact_exception(release_error),
                )
            raise errors.StopWorkError(safe_reason, reason="stop_work_active")

    _emit(client, job_id, "started", f"claimed job · {len(targets)} target(s) from {target_src}")
    _emit(client, job_id, "targets_resolved", f"{len(targets)} target(s) from {target_src}")

    run_dir = _make_run_dir()
    label = redaction.redact_text(str(handler.running_label(targets, tool_cfg)))
    try:
        con.print(f"Running {redaction.redact_rich_text(label)}…")
        _emit(client, job_id, "running", f"running {label}")
        output = handler.execute(targets, run_dir, tool_cfg)

        if output is None or not output.exists() or output.stat().st_size == 0:
            con.print("[yellow]No output produced — nothing to upload.[/yellow]")
            _complete_done(client, job_id, f"{tool_type} produced no output")
            return

        con.print("Uploading results…")
        summary = handler.upload(client, engagement_id, output, job_id=job_id)
        safe_summary = redaction.redact_text(str(summary))
        con.print(f"[green]Done.[/green] {redaction.redact_rich_text(safe_summary)}")
        _emit(client, job_id, "uploaded", safe_summary)
        _complete_done(client, job_id)
    except runner.ToolTimeout as e:
        _fail_job(client, con, job_id, str(e))
    except Exception as e:
        _fail_job(client, con, job_id, str(e))


def execute_pending_jobs(
    client: api.VardrMapClient,
    con: Console,
    yes: bool = True,
    blocked_engagements: MutableMapping[str, float] | None = None,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Claim and execute all pending jobs. Returns the number of jobs found.

    ``blocked_engagements`` maps engagements whose stop-work switch is engaged
    to the monotonic time when they should be checked again. Pass a mapping that
    outlives the call (the daemon does) to avoid a refusal every poll while still
    discovering when the operator lifts stop-work. Omit it and suppression lasts
    for this batch only.
    """
    jobs_list = client.pending_jobs()
    if not jobs_list:
        return 0

    blocked = blocked_engagements if blocked_engagements is not None else {}
    now = monotonic()

    con.print(f"Found [bold]{len(jobs_list)}[/bold] pending job(s).")
    for job in jobs_list:
        engagement_id = str(job.get("engagement_id") or "")
        retry_at = blocked.get(engagement_id, 0.0) if engagement_id else 0.0
        if retry_at > now:
            remaining = max(1, int(retry_at - now))
            con.print(
                f"[dim]Skipping job {redaction.redact_rich_text(str(job.get('id', ''))[:8])}… — "
                "stop-work recheck for engagement "
                f"{redaction.redact_rich_text(engagement_id)} in {remaining}s.[/dim]"
            )
            continue
        if engagement_id:
            blocked.pop(engagement_id, None)
        try:
            _execute_one(client, con, job, yes)
        except errors.StopWorkError:
            # Reported already by _execute_one. Remember the engagement so the
            # daemon does not re-claim and re-refuse it on every poll, but set a
            # bounded recheck so lifting stop-work restores availability.
            if engagement_id:
                blocked[engagement_id] = monotonic() + STOP_WORK_RECHECK_SECONDS
            con.print(
                "[yellow]No further jobs will be claimed for this engagement "
                f"for {int(STOP_WORK_RECHECK_SECONDS)}s, then it will be rechecked.[/yellow]"
            )
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
