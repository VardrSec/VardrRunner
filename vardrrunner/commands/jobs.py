"""
Job queue commands: list pending jobs and run them locally.

The UI creates job records; VardrRunner polls /jobs/pending, claims each job,
runs the matching tool handler, and reports lifecycle events. This module owns the
uniform *lifecycle* (availability → config → targets → claim → run → upload →
done/fail); the per-tool specifics live in ``vardrrunner.handlers``.
"""

import json
import logging
import threading
import time
from collections.abc import Callable, MutableMapping
from concurrent.futures import ThreadPoolExecutor

import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import (
    api,
    compatibility,
    config,
    configs,
    errors,
    handlers,
    policy,
    redaction,
    resources,
    runner,
    target_safety,
)
from vardrrunner import targets as targets_module
from vardrrunner.commands.heartbeat import send_heartbeat
from vardrrunner.commands.run import _confirm, _make_run_dir
from vardrrunner.journal import Journal, Phase, RunRecord, utc_now
from vardrrunner.recovery import reconcile

console = Console()

# Stop-work is rechecked periodically rather than every daemon poll.  A
# permanent in-memory block would leave work unavailable after the operator
# lifts the halt until someone notices and restarts the service.
STOP_WORK_RECHECK_SECONDS = 60.0

_AUDIT_CONFIG_FIELDS = frozenset(
    {"limit", "status_code", "severity", "templates", "timeout", "top_ports", "timing"}
)


def _journal_profile(tool_type: str, cfg: dict) -> dict:
    """Keep operational settings while excluding targets, requests, and credentials."""
    profile = {key: cfg[key] for key in _AUDIT_CONFIG_FIELDS if key in cfg}
    if tool_type == "vardrgate_api_test" and isinstance(cfg.get("execution"), dict):
        profile["execution"] = redaction.redact(cfg["execution"])
    return profile


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


def _execute_one(
    client: api.VardrMapClient,
    con: Console,
    job: dict,
    yes: bool,
    journal_store: Journal | None = None,
    backend_url: str | None = None,
    limits: resources.RunnerLimits = resources.DEFAULT_LIMITS,
) -> None:
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

    record: RunRecord | None = None
    if journal_store is not None:
        record = journal_store.begin(
            job_id=job_id,
            backend_url=backend_url or str(client.base),
            engagement_id=engagement_id,
            job_type=tool_type,
            tool=tool_type,
            target_source=target_src,
            command_profile=_journal_profile(tool_type, cfg),
            job_schema_version=env.schema_version,
        )
        if record.phase != Phase.DISCOVERED:
            raise errors.RunnerError(
                f"job {job_id} already has unfinished journal run {record.run_id}"
            )
        record = journal_store.transition(record.run_id, Phase.VALIDATING)

    def finish(
        phase: Phase,
        status: str,
        category: errors.FailureCategory | None = None,
        reason: str = "",
    ) -> None:
        if journal_store is not None and record is not None:
            journal_store.finish(
                record.run_id,
                phase,
                status=status,
                failure_category=category.value if category else None,
                failure_reason=reason or None,
            )

    def fail(category: errors.FailureCategory, reason: str) -> None:
        _fail_job(client, con, job_id, reason)
        finish(Phase.FAILED, "failed", category, reason)

    con.rule(redaction.redact_rich_text(f"Job {job_id[:8]}… — {tool_type} / {target_src}"))

    handler = handlers.REGISTRY.get(tool_type)
    if handler is None:
        fail(errors.FailureCategory.UNSUPPORTED_JOB, f"unknown tool type {tool_type!r}")
        return
    # Capability check before claiming — never claim work this runner can't do.
    if not runner.tool_available(handler.tool):
        fail(errors.FailureCategory.TOOL_MISSING, f"'{handler.tool}' not found on PATH")
        return

    try:
        tool_cfg = handler.parse_config(cfg)
    except configs.ConfigError as e:
        fail(errors.FailureCategory.INVALID_CONFIG, f"invalid config: {e}")
        return

    try:
        targets = handler.resolve_targets(client, engagement_id, target_src, tool_cfg)
    except Exception as e:  # resolution failure must not crash the loop
        fail(errors.FailureCategory.TARGET_RESOLUTION, f"failed to resolve targets: {e}")
        return
    try:
        targets = targets_module.validate_targets(targets)
    except targets_module.TargetValidationError as e:
        fail(errors.FailureCategory.TARGET_VALIDATION, str(e))
        return
    if len(targets) > limits.max_targets:
        fail(
            errors.FailureCategory.TARGET_LIMIT,
            f"resolved target count {len(targets)} exceeds local limit {limits.max_targets}",
        )
        return

    # Advisory classification (loopback / link-local / cloud metadata). Shown and
    # recorded, never blocking — the operator owns where they aim, exactly as
    # with the backend's scope findings.
    for finding in target_safety.assess(targets):
        con.print(f"[yellow]⚠ {finding.describe()}[/yellow]")
        _emit(client, job_id, "target_warning", finding.describe())

    # Local deny rules are the one thing that blocks, and only when the operator
    # configured them. The override is an env var so it also works on this,
    # the unattended path, where there is no command line.
    denied: tuple[target_safety.TargetFinding, ...] = ()
    rules = target_safety.load_deny_rules()
    if rules:
        allowed, denied = target_safety.apply_deny_rules(targets, rules)
        if denied and target_safety.override_enabled():
            for finding in denied:
                _emit(client, job_id, "deny_override", finding.describe())
            denied = ()
        elif denied:
            for finding in denied:
                con.print(f"[red]blocked:[/red] {finding.describe()}")
                _emit(client, job_id, "target_blocked", finding.describe())
            if not allowed:
                fail(
                    errors.FailureCategory.TARGET_DENIED,
                    f"all {len(targets)} target(s) blocked by local deny rules",
                )
                return
            targets = allowed

    stats = target_safety.summarize(targets, targets)
    _emit(client, job_id, "target_stats", stats.summary())

    if journal_store is not None and record is not None:
        record = journal_store.transition(
            record.run_id, Phase.TARGETS_RESOLVED, target_count=len(targets)
        )

    if not targets:
        con.print("[yellow]No targets resolved — marking job done.[/yellow]")
        if journal_store is not None and record is not None:
            record = journal_store.transition(record.run_id, Phase.FINALIZING)
        _complete_done(client, job_id, "no targets resolved")
        finish(Phase.DONE, "done")
        return

    _confirm(targets, tool_type, yes)

    try:
        resources.ensure_free_space(config.runs_dir(), limits.min_free_disk_bytes)
    except resources.ResourceLimitError as e:
        fail(errors.FailureCategory.RESOURCE_LIMIT, str(e))
        return

    if journal_store is not None and record is not None:
        record = journal_store.transition(record.run_id, Phase.CLAIMING)

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
        finish(Phase.STOP_WORK, "not_claimed", errors.FailureCategory.STOP_WORK, str(e))
        raise
    except errors.ClaimRace as e:
        # Expected and benign: the job belongs to whoever won. Leave it pending
        # for them; marking it failed would destroy another runner's work.
        con.print(f"[dim]Skipping — {redaction.redact_rich_text(str(e))}[/dim]")
        finish(Phase.SKIPPED, "claim_race", errors.FailureCategory.CLAIM_RACE, str(e))
        return
    except errors.RunnerError as e:
        con.print(
            f"[red]Could not claim job ({e.category.value}):[/red] "
            f"{redaction.redact_rich_text(str(e))}"
        )
        finish(Phase.FAILED, "claim_failed", e.category, str(e))
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
        finish(
            Phase.FAILED,
            "claim_failed",
            errors.FailureCategory.UNKNOWN,
            redaction.redact_exception(e),
        )
        return

    if journal_store is not None and record is not None:
        record = journal_store.transition(record.run_id, Phase.CLAIMED, claimed_at=utc_now())

    # Advisory findings from the backend's policy evaluation. Shown before any
    # tool runs so the operator sees them while they can still intervene; they
    # do not block, by design (ADR 0001 amendment).
    warnings = policy.parse_warnings(claimed)
    if warnings:
        if journal_store is not None and record is not None:
            record = journal_store.transition(
                record.run_id,
                Phase.CLAIMED,
                warnings_json=json.dumps(redaction.redact([w.__dict__ for w in warnings])),
            )
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
            finish(
                Phase.STOP_WORK,
                "released",
                errors.FailureCategory.STOP_WORK,
                safe_reason,
            )
            raise errors.StopWorkError(safe_reason, reason="stop_work_active")

    _emit(client, job_id, "started", f"claimed job · {len(targets)} target(s) from {target_src}")
    _emit(client, job_id, "targets_resolved", f"{len(targets)} target(s) from {target_src}")

    run_dir = _make_run_dir()
    if journal_store is not None and record is not None:
        record = journal_store.transition(
            record.run_id,
            Phase.EXECUTING,
            run_dir=str(run_dir),
            last_event="tool execution started",
        )
    label = redaction.redact_text(str(handler.running_label(targets, tool_cfg)))
    stage = Phase.EXECUTING
    try:
        con.print(f"Running {redaction.redact_rich_text(label)}…")
        _emit(client, job_id, "running", f"running {label}")
        if journal_store is not None and record is not None:
            run_id = record.run_id

            def record_pid(pid: int) -> None:
                journal_store.transition(run_id, Phase.EXECUTING, pid=pid)

            with runner.observe_process(record_pid):
                output = handler.execute(targets, run_dir, tool_cfg)
        else:
            output = handler.execute(targets, run_dir, tool_cfg)

        if output is None or not output.exists() or output.stat().st_size == 0:
            con.print("[yellow]No output produced — nothing to upload.[/yellow]")
            if journal_store is not None and record is not None:
                record = journal_store.transition(
                    record.run_id, Phase.FINALIZING, pid=None, last_event="no artifact produced"
                )
            _complete_done(client, job_id, f"{tool_type} produced no output")
            finish(Phase.DONE, "done")
            return

        try:
            resources.enforce_artifact(output, limits.max_artifact_bytes)
        except resources.ResourceLimitError as e:
            _fail_job(client, con, job_id, str(e))
            finish(Phase.FAILED, "failed", errors.FailureCategory.ARTIFACT_LIMIT, str(e))
            return

        if journal_store is not None and record is not None:
            record = journal_store.attach_artifact(record.run_id, output)
            stage = Phase.ARTIFACT_READY
        con.print("Uploading results…")
        if journal_store is not None and record is not None:
            record = journal_store.transition(
                record.run_id,
                Phase.UPLOADING,
                pid=None,
                upload_state="in_progress",
                last_event="artifact upload started",
            )
            stage = Phase.UPLOADING
        summary = handler.upload(client, engagement_id, output, job_id=job_id)
        safe_summary = redaction.redact_text(str(summary))
        con.print(f"[green]Done.[/green] {redaction.redact_rich_text(safe_summary)}")
        _emit(client, job_id, "uploaded", safe_summary)
        if journal_store is not None and record is not None:
            record = journal_store.transition(
                record.run_id,
                Phase.FINALIZING,
                upload_state="succeeded",
                last_event=safe_summary,
            )
            stage = Phase.FINALIZING
        _complete_done(client, job_id)
        finish(Phase.DONE, "done")
    except runner.ToolTimeout as e:
        _fail_job(client, con, job_id, str(e))
        finish(Phase.FAILED, "failed", errors.FailureCategory.TOOL_TIMEOUT, str(e))
    except Exception as e:
        _fail_job(client, con, job_id, str(e))
        category = (
            errors.FailureCategory.UPLOAD_FAILED
            if stage in {Phase.ARTIFACT_READY, Phase.UPLOADING, Phase.FINALIZING}
            else errors.FailureCategory.TOOL_FAILED
        )
        finish(Phase.FAILED, "failed", category, str(e))


def execute_pending_jobs(
    client: api.VardrMapClient,
    con: Console,
    yes: bool = True,
    blocked_engagements: MutableMapping[str, float] | None = None,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    journal_store: Journal | None = None,
    backend_url: str | None = None,
    limits: resources.RunnerLimits = resources.DEFAULT_LIMITS,
    client_factory: Callable[[], api.VardrMapClient] | None = None,
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
    blocked_lock = threading.Lock()
    now = monotonic()

    con.print(
        f"Found [bold]{len(jobs_list)}[/bold] pending job(s) · "
        f"concurrency {limits.max_concurrent_jobs}."
    )

    def execute_group(group: list[dict], worker_client: api.VardrMapClient) -> None:
        for job in group:
            execute_job(job, worker_client)

    def execute_job(job: dict, worker_client: api.VardrMapClient) -> None:
        engagement_id = str(job.get("engagement_id") or "")
        with blocked_lock:
            retry_at = blocked.get(engagement_id, 0.0) if engagement_id else 0.0
        if retry_at > now:
            remaining = max(1, int(retry_at - now))
            con.print(
                f"[dim]Skipping job {redaction.redact_rich_text(str(job.get('id', ''))[:8])}… — "
                "stop-work recheck for engagement "
                f"{redaction.redact_rich_text(engagement_id)} in {remaining}s.[/dim]"
            )
            return
        if engagement_id:
            with blocked_lock:
                blocked.pop(engagement_id, None)
        try:
            _execute_one(
                worker_client,
                con,
                job,
                yes,
                journal_store=journal_store,
                backend_url=backend_url,
                limits=limits,
            )
        except errors.StopWorkError:
            # Reported already by _execute_one. Remember the engagement so the
            # daemon does not re-claim and re-refuse it on every poll, but set a
            # bounded recheck so lifting stop-work restores availability.
            if engagement_id:
                with blocked_lock:
                    blocked[engagement_id] = monotonic() + STOP_WORK_RECHECK_SECONDS
            con.print(
                "[yellow]No further jobs will be claimed for this engagement "
                f"for {int(STOP_WORK_RECHECK_SECONDS)}s, then it will be rechecked.[/yellow]"
            )

    groups: dict[str, list[dict]] = {}
    for index, job in enumerate(jobs_list):
        engagement = str(job.get("engagement_id") or "")
        key = engagement or f"__unscoped_{index}"
        groups.setdefault(key, []).append(job)

    workers = min(limits.max_concurrent_jobs, len(groups))
    if workers <= 1:
        for group in groups.values():
            execute_group(group, client)
    else:
        if client_factory is None:
            raise resources.ResourceLimitError(
                "concurrent execution requires an isolated API client factory"
            )
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vardrrunner-job") as pool:
            futures = [
                pool.submit(execute_group, group, client_factory()) for group in groups.values()
            ]
            for future in futures:
                future.result()
    return len(jobs_list)


def run_jobs(yes: bool = False) -> None:
    """Claim and execute all pending jobs for the authenticated user."""
    report = send_heartbeat(quiet=True)
    if isinstance(report, compatibility.CompatibilityReport) and not report.compatible:
        console.print(
            "[red]Jobs blocked by backend compatibility policy:[/red] "
            f"{redaction.redact_rich_text('; '.join(report.messages))}"
        )
        raise typer.Exit(1)
    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)
    journal_store = Journal(config.journal_file())
    try:
        limits = resources.load_limits()
    except resources.ResourceLimitError as exc:
        console.print(
            f"[red]Invalid runner resource policy:[/red] {redaction.redact_rich_exception(exc)}"
        )
        raise typer.Exit(1) from exc
    reconcile(journal_store, client, url, console)
    executed = execute_pending_jobs(
        client,
        console,
        yes=yes,
        journal_store=journal_store,
        backend_url=url,
        limits=limits,
        client_factory=lambda: api.VardrMapClient(url, key),
    )
    if executed == 0:
        console.print("[dim]No pending jobs.[/dim]")
        raise typer.Exit(0)
