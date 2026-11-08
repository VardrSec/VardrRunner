"""Explicit standalone fixed-Gate consumer; no issuance, enrollment or Map transport."""

from __future__ import annotations

import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import config, execution_control, identity, launch_guard, resources, runner
from vardrrunner.authorization.codec import decoded, digest, encoded, require, verify
from vardrrunner.authorization.contracts import ValidationContext, approved, timestamp, validate
from vardrrunner.authorization.documents import read_anchors, read_bytes, read_document
from vardrrunner.authorization.ledger import AuthorizationLedger
from vardrrunner.authorization.plan import PROFILE, origin
from vardrrunner.authorization.recon_plan import RUNTIME_PROFILE
from vardrrunner.authorization.recon_runtime import execute_recon, qualified_tools
from vardrrunner.authorization.runtime import execute_gate
from vardrrunner.journal import Journal, Phase, RunRecord, utc_now
from vardrrunner.workspaces import Workspaces, validate_id

console = Console()


def run(
    workspace_id: str,
    *,
    approval: Path,
    contract: Path,
    plan: Path,
    case: Path,
    execution: Path,
    trust: Path,
    output: Path,
    provisioned_issuer: bool = False,
    allow_recon: bool = False,
) -> RunRecord:
    """Use existing signed permission; never issue or elevate it."""
    record = None
    journal = None
    try:
        validate_id(workspace_id)
        require(sys.stdin.isatty(), "interactive_operator_required")
        require(execution_control.available(), "controlled_process_tree_unsupported")
        output = output.absolute()
        journal = Journal(config.journal_file())
        require(Workspaces(journal).get(workspace_id) is not None, "unknown_workspace")
        anchors = read_anchors(trust)  # Explicit operator-selected public reference trust.
        receipt, envelope = read_document(approval), read_document(contract)
        plan_bytes = read_bytes(plan)
        compiled, case_input, options = (
            decoded(plan_bytes),
            read_document(case),
            read_document(execution),
        )
        require(plan_bytes == encoded(compiled), "plan_bytes_changed")
        require(
            compiled.get("profile") in ({PROFILE, RUNTIME_PROFILE} if allow_recon else {PROFILE}),
            "unsupported_enforcement",
        )
        recon = compiled["profile"] == RUNTIME_PROFILE
        tool_sha256, dnsx_sha256 = compiled["tool_sha256"], None
        if recon:
            _, hashes = qualified_tools()
            tool_sha256, dnsx_sha256 = hashes["httpx"], hashes["dnsx"]
        signed = verify(envelope, anchors, "contract")
        permission = approved(receipt, anchors)["context"]
        current = ValidationContext(
            runner_id=identity.load_or_create().runner_id,
            engagement_id=workspace_id,
            job_id=signed["job_id"],
            attempt_id=signed["attempt_id"],
            fence=signed["fence"],
            origin="standalone",
            now=datetime.now(timezone.utc),
            authority_revision=permission["authority_revision"],
            tool_sha256=tool_sha256,
            dnsx_sha256=dnsx_sha256,
            authority_sha256=permission["authority_sha256"],
            capabilities=frozenset({compiled["profile"]}),
        )
        validate(envelope, receipt, compiled, case_input, options, anchors, current)
        if provisioned_issuer:
            from vardrrunner.commands.workspace_authority import _check_authority_binding

            _check_authority_binding(signed, permission, anchors)
        # No trusted capabilities, time, identity or managed status come from a context file.
        require(not output.exists() and not output.is_symlink(), "exclusive_output_required")
        resources.ensure_free_space(output.parent, resources.load_limits().min_free_disk_bytes)
        console.print(f"Workspace: {workspace_id}")
        console.print(f"Reviewed plan SHA-256: {digest(plan_bytes)}")
        console.print(f"Fixed HTTP dispatch ceiling: {compiled['max_http_dispatches']}")
        require(
            typer.confirm("Use the existing signed approval for this execution?", default=False),
            "operator_declined",
        )
        # Atomic directory creation also refuses a concurrent creator; nothing is deleted.
        output.mkdir(mode=0o700)
        journal_key = "standalone:" + uuid.uuid4().hex
        record = journal.begin(
            job_id=journal_key,
            backend_url="",
            engagement_id=workspace_id,
            job_type="recon" if recon else "vardrgate_api_test",
            tool="recon" if recon else "vardrgate_api_test",
            target_source="explicit",
            command_profile={
                "standalone_profile": compiled["profile"],
                "origin": "standalone",
                "controlled": True,
                "contract_sha256": digest(encoded(envelope)),
                "plan_sha256": digest(plan_bytes),
                "signed_job_id": signed["job_id"],
                "attempt_id": signed["attempt_id"],
                "fence": signed["fence"],
                "grant_policy": "none/1" if recon else "expiring/1",
            },
        )
        journal.transition(
            record.run_id, Phase.VALIDATING, run_dir=str(output), upload_state="not_applicable"
        )
        journal.transition(
            record.run_id,
            Phase.TARGETS_RESOLVED,
            target_count=len(case_input["hostnames"])
            if recon
            else len({origin(d["request"]["url"]) for d in compiled["dispatches"]}),
        )
        journal.transition(record.run_id, Phase.CLAIMING)
        console.print(f"Local run: {record.run_id}")

        def reserved() -> None:
            assert journal is not None and record is not None
            journal.transition(record.run_id, Phase.CLAIMED, claimed_at=utc_now())
            journal.transition(record.run_id, Phase.EXECUTING)

        ledger = AuthorizationLedger(journal, clock=lambda: datetime.now(timezone.utc))
        control = _local_control(
            ledger,
            current,
            signed["issuer"]["id"],
            {
                **permission,
                "max_duration_seconds": min(
                    permission["max_duration_seconds"], options["timeout_seconds"]
                ),
            }
            if recon
            else permission,
            record.run_id,
            min(timestamp(signed["expires_at"]), timestamp(options["deadline"]))
            if recon
            else timestamp(signed["expires_at"]),
        )

        def observed(pid: int) -> None:
            assert journal is not None and record is not None
            journal.transition(record.run_id, Phase.EXECUTING, pid=pid)

        # Reuse the native control path; there is no legacy or Docker fallback.
        assert control.lease_deadline is not None
        with (
            execution_control.controlled(control),
            launch_guard.monotonic_deadline(control.lease_deadline()),
            runner.observe_process(observed),
        ):
            output_file = (execute_recon if recon else execute_gate)(
                ledger,
                envelope,
                receipt,
                compiled,
                case_input,
                options,
                anchors,
                current,
                output,
                expiring_grants=True,
                on_reserved=reserved,
            )
        journal.transition(record.run_id, Phase.EXECUTING, pid=None)
        journal.attach_artifact(record.run_id, output_file)
        finished = journal.finish(record.run_id, Phase.DONE, status="done")
        console.print_json(
            json.dumps(
                {
                    "run_id": finished.run_id,
                    "workspace_id": workspace_id,
                    "artifact_sha256": finished.artifact_sha256,
                    "status": "done",
                }
            )
        )
        return finished
    except execution_control.ExecutionStopped as stopped:
        if journal is not None and record is not None:
            _retain_pid(journal, record.run_id, stopped.pid)
            _failed(journal, record.run_id, confirmed=stopped.confirmed is True)
        console.print(
            "[red]Standalone execution stopped or uncertain; retain local evidence.[/red]"
        )
        raise typer.Exit(1) from None
    except KeyboardInterrupt:
        # A consumed/possibly started attempt is never automatically replayable.
        if journal is not None and record is not None:
            _failed(journal, record.run_id)
        console.print("[red]Standalone execution interrupted; retain local evidence.[/red]")
        raise typer.Exit(1) from None
    except Exception:
        # Inputs, providers and paths can contain secrets. Never echo an exception.
        if journal is not None and record is not None:
            _failed(journal, record.run_id)
        console.print(
            "[red]Standalone execution refused or incomplete; retain local evidence.[/red]"
        )
        raise typer.Exit(1) from None


def _local_control(
    ledger: AuthorizationLedger,
    context: ValidationContext,
    issuer: str,
    permission: dict,
    run_id: str,
    contract_deadline: datetime,
) -> execution_control.Control:
    started = time.monotonic()
    now = datetime.now(timezone.utc)
    until = min(
        contract_deadline, timestamp(permission["expires_at"]), timestamp(permission["testing_end"])
    )
    cap = started + max(0.0, min(permission["max_duration_seconds"], (until - now).total_seconds()))
    binding = {"run_id": run_id}

    def refresh() -> dict:
        return {**binding, "action": "continue", "lease_seconds": 10}

    def local_stop() -> bool:
        try:
            # Read-only validation is also safe inside the existing grant launch
            # transaction. Never reacquire a SQLite writer while it is held.
            ledger.check_state(context, issuer)
            return ledger.journal.stop_requested(run_id)
        except Exception:
            return True

    return execution_control.Control(
        refresh,
        binding,
        10,
        started=started,
        local_stop=local_stop,
        lease_deadline=lambda: cap,
    )


def _retain_pid(journal: Journal, run_id: str, pid: int | None) -> None:
    if type(pid) is not int or pid <= 0:
        return
    try:
        current = journal.get(run_id)
        if current is not None:
            if current.pid is None or current.pid == pid:
                journal.transition(run_id, current.phase, pid=pid)
            else:
                journal.transition(
                    run_id,
                    current.phase,
                    warnings_json=json.dumps(
                        [
                            *current.warnings,
                            {"code": "standalone_pid_conflict", "pid": str(pid)},
                        ]
                    ),
                )
    except Exception:
        # No durable proof is inferred on storage failure; consumption stays held.
        pass


def _failed(journal: Journal, run_id: str, *, confirmed: bool = False) -> None:
    try:
        if confirmed:
            current = journal.get(run_id)
            if current is not None:
                journal.transition(run_id, current.phase, pid=None)
        journal.finish(
            run_id,
            Phase.STOP_WORK if confirmed else Phase.FAILED,
            status="stopped" if confirmed else "failed_or_uncertain",
            failure_category="unknown",
            failure_reason="standalone_execution_incomplete",
        )
    except Exception:
        # Preserve unfinished state for explicit reconciliation, never legacy recovery.
        pass
