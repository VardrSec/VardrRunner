"""Crash reconciliation for journaled backend jobs.

Recovery is deliberately conservative around non-idempotent uploads. Work that
was definitely not uploaded can resume from its artifact; an upload whose
response was lost is never repeated automatically.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from vardrrunner import api, errors, handlers, redaction
from vardrrunner.journal import Journal, Phase, RunRecord, normalize_backend_url


@dataclass(frozen=True)
class ReconciliationResult:
    examined: int = 0
    recovered: int = 0
    failed: int = 0
    deferred: int = 0
    foreign_backend: int = 0


_ARTIFACT_NAMES = {
    "httpx": "httpx.jsonl",
    "nuclei": "nuclei.jsonl",
    "nmap": "nmap.xml",
    "subfinder": "subfinder_httpx.jsonl",
    "dnsx": "dnsx_httpx.jsonl",
    "naabu": "naabu.json",
    "vardrgate_api_test": "vardrgate_result.json",
}


def process_alive(pid: int | None) -> bool:
    """Return whether ``pid`` exists without signaling it on Windows."""
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        still_active = 259
        process_query_limited_information = 0x1000
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _artifact_for(record: RunRecord) -> Path | None:
    if record.artifact_path:
        candidate = Path(record.artifact_path)
    elif record.run_dir and record.tool in _ARTIFACT_NAMES:
        candidate = Path(record.run_dir) / _ARTIFACT_NAMES[record.tool]
    else:
        return None
    try:
        return candidate if candidate.is_file() and candidate.stat().st_size > 0 else None
    except OSError:
        return None


def _fail_claimed(
    store: Journal,
    client: api.VardrMapClient,
    record: RunRecord,
    category: errors.FailureCategory,
    reason: str,
) -> bool:
    safe = redaction.redact_text(reason)[:500]
    try:
        client.complete_job(record.job_id, "failed", error=safe)
    except Exception as exc:
        store.transition(
            record.run_id,
            record.phase,
            last_event=f"reconciliation deferred: {redaction.redact_exception(exc)}",
        )
        return False
    store.finish(
        record.run_id,
        Phase.INTERRUPTED,
        status="failed",
        failure_category=category.value,
        failure_reason=safe,
    )
    return True


def _resume_artifact(
    store: Journal,
    client: api.VardrMapClient,
    record: RunRecord,
    artifact: Path,
) -> bool:
    handler = handlers.REGISTRY.get(record.tool)
    if handler is None:
        return _fail_claimed(
            store,
            client,
            record,
            errors.FailureCategory.UNSUPPORTED_JOB,
            f"cannot recover unsupported tool {record.tool!r}",
        )
    current = record
    if current.phase == Phase.EXECUTING:
        current = store.attach_artifact(current.run_id, artifact)
    current = store.transition(
        current.run_id,
        Phase.UPLOADING,
        upload_state="in_progress",
        last_event="reconciliation upload started",
    )
    try:
        handler.upload(client, current.engagement_id, artifact, job_id=current.job_id)
    except Exception as exc:
        # The request may have reached the backend. Keep the ambiguous UPLOADING
        # phase so the next pass refuses to duplicate it.
        store.transition(
            current.run_id,
            Phase.UPLOADING,
            upload_state="outcome_unknown",
            last_event=f"upload outcome unknown: {redaction.redact_exception(exc)}",
        )
        return False
    store.transition(
        current.run_id,
        Phase.FINALIZING,
        upload_state="succeeded",
        last_event="reconciliation upload succeeded",
    )
    try:
        client.complete_job(current.job_id, "done")
    except Exception as exc:
        store.transition(
            current.run_id,
            Phase.FINALIZING,
            last_event=f"finalization deferred: {redaction.redact_exception(exc)}",
        )
        return False
    store.finish(current.run_id, Phase.DONE, status="done")
    return True


def reconcile(
    store: Journal,
    client: api.VardrMapClient,
    backend_url: str,
    console: Console | None = None,
) -> ReconciliationResult:
    """Reconcile every unfinished run belonging to the configured backend."""
    counts = {"examined": 0, "recovered": 0, "failed": 0, "deferred": 0, "foreign": 0}
    expected_backend = normalize_backend_url(backend_url)
    for record in store.unfinished():
        counts["examined"] += 1
        if record.backend_url != expected_backend:
            counts["foreign"] += 1
            continue
        if record.phase in {Phase.DISCOVERED, Phase.VALIDATING, Phase.TARGETS_RESOLVED}:
            store.finish(
                record.run_id,
                Phase.INTERRUPTED,
                status="not_claimed",
                failure_category=errors.FailureCategory.UNKNOWN.value,
                failure_reason="runner stopped before claiming the job",
            )
            counts["failed"] += 1
            continue
        if record.phase == Phase.EXECUTING and process_alive(record.pid):
            counts["deferred"] += 1
            continue
        if record.phase in {Phase.EXECUTING, Phase.ARTIFACT_READY}:
            artifact = _artifact_for(record)
            if artifact:
                if _resume_artifact(store, client, record, artifact):
                    resolved = store.get(record.run_id)
                    if resolved and resolved.phase == Phase.DONE:
                        counts["recovered"] += 1
                    else:
                        counts["failed"] += 1
                else:
                    counts["deferred"] += 1
            elif _fail_claimed(
                store,
                client,
                record,
                errors.FailureCategory.TOOL_FAILED,
                "runner stopped before producing a recoverable artifact",
            ):
                counts["failed"] += 1
            else:
                counts["deferred"] += 1
            continue
        if record.phase == Phase.FINALIZING:
            try:
                client.complete_job(record.job_id, "done")
            except Exception as exc:
                store.transition(
                    record.run_id,
                    Phase.FINALIZING,
                    last_event=f"finalization deferred: {redaction.redact_exception(exc)}",
                )
                counts["deferred"] += 1
            else:
                store.finish(record.run_id, Phase.DONE, status="done")
                counts["recovered"] += 1
            continue
        category = (
            errors.FailureCategory.UPLOAD_FAILED
            if record.phase == Phase.UPLOADING
            else errors.FailureCategory.UNKNOWN
        )
        reason = (
            "upload outcome is unknown after runner interruption; automatic replay was refused"
            if record.phase == Phase.UPLOADING
            else "runner stopped while claiming the job"
        )
        if _fail_claimed(store, client, record, category, reason):
            counts["failed"] += 1
        else:
            counts["deferred"] += 1
    result = ReconciliationResult(
        examined=counts["examined"],
        recovered=counts["recovered"],
        failed=counts["failed"],
        deferred=counts["deferred"],
        foreign_backend=counts["foreign"],
    )
    if console and result.examined:
        console.print(
            "[dim]Reconciliation: "
            f"{result.recovered} recovered, {result.failed} closed, "
            f"{result.deferred} deferred, {result.foreign_backend} other backend.[/dim]"
        )
    return result
