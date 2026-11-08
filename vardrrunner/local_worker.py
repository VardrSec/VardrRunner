"""Explicit one-shot local worker; only the credentialed native owner can enable it."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
import uuid
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vardrrunner import (
    config,
    credential_grants,
    execution_control,
    handlers,
    identity,
    launch_guard,
    resources,
    runner,
    worker_lifecycle,
)
from vardrrunner.authorization.codec import digest, encoded, require, verify
from vardrrunner.authorization.contracts import ValidationContext, approved, validate
from vardrrunner.authorization.documents import read_anchors, read_bytes, read_document
from vardrrunner.authorization.ledger import AuthorizationLedger
from vardrrunner.authorization.local_admission import LocalAdmission
from vardrrunner.authorization.plan import PROFILE, origin
from vardrrunner.authorization.recon_plan import RUNTIME_PROFILE
from vardrrunner.authorization.recon_runtime import execute_recon, qualified_tools
from vardrrunner.authorization.runtime import execute_gate
from vardrrunner.commands.audit import export_run
from vardrrunner.commands.workspace_authority import _check_authority_binding
from vardrrunner.commands.workspace_gate import _failed, _retain_pid
from vardrrunner.journal import Journal, Phase, utc_now
from vardrrunner.workspaces import Workspaces, validate_id

BUNDLE = Path("/run/vardr-local")
EXPORT = Path("/exports")
FILES = frozenset(
    {"approval.json", "contract.json", "plan.json", "case.json", "execution.json", "trust.json"}
)


def _inputs():
    require(BUNDLE.is_dir() and not BUNDLE.is_symlink(), "local_bundle_required")
    require({p.name for p in BUNDLE.iterdir()} == FILES, "local_bundle_fields")
    require(os.statvfs(BUNDLE).f_flag & os.ST_RDONLY, "local_bundle_readonly_required")  # type: ignore[attr-defined]
    for name in FILES:
        info = (BUNDLE / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "local_bundle_file")
    anchors = read_anchors(BUNDLE / "trust.json")
    envelope, approval = (
        read_document(BUNDLE / name) for name in ("contract.json", "approval.json")
    )
    plan_bytes = read_bytes(BUNDLE / "plan.json")
    plan = read_document(BUNDLE / "plan.json")
    require(plan.get("profile") in {PROFILE, RUNTIME_PROFILE}, "unsupported_enforcement")
    recon = plan["profile"] == RUNTIME_PROFILE
    tool_sha256, dnsx_sha256 = plan["tool_sha256"], None
    if recon:
        _, hashes = qualified_tools()
        tool_sha256, dnsx_sha256 = hashes["httpx"], hashes["dnsx"]
    require(plan_bytes == encoded(plan), "plan_bytes_changed")
    case, execution = (read_document(BUNDLE / name) for name in ("case.json", "execution.json"))
    payload, permission = (
        verify(envelope, anchors, "contract"),
        approved(approval, anchors)["context"],
    )
    workspace_id = validate_id(permission["engagement_id"])
    context = ValidationContext(
        runner_id=identity.load_or_create().runner_id,
        engagement_id=workspace_id,
        job_id=payload["job_id"],
        attempt_id=payload["attempt_id"],
        fence=payload["fence"],
        origin="standalone",
        now=datetime.now(timezone.utc),
        authority_revision=permission["authority_revision"],
        authority_sha256=permission["authority_sha256"],
        tool_sha256=tool_sha256,
        dnsx_sha256=dnsx_sha256,
        capabilities=frozenset({plan["profile"]}),
    )
    validate(envelope, approval, plan, case, execution, anchors, context)
    _check_authority_binding(payload, permission, anchors)
    return envelope, approval, plan, case, execution, anchors, context, payload, permission


def run() -> dict:
    envelope, approval, plan, case, execution, anchors, context, payload, permission = _inputs()
    recon = plan["profile"] == RUNTIME_PROFILE
    sites = sorted({origin(d["request"]["url"]) for d in plan["dispatches"]})
    references = [] if recon else handlers.credential_references(case)
    journal = Journal(config.journal_file())
    ledger = AuthorizationLedger(journal, clock=lambda: datetime.now(timezone.utc))
    require(Workspaces(journal).get(context.engagement_id) is not None, "unknown_workspace")
    ledger.check_state(context, payload["issuer"]["id"])
    admission = LocalAdmission.verified(payload, permission, plan, now=context.now)
    output = config.runs_dir() / ("local-" + uuid.uuid4().hex)
    resources.ensure_free_space(output.parent, resources.load_limits().min_free_disk_bytes)
    record = None
    with worker_lifecycle.connect(admission) as owner:
        require(type(owner) is worker_lifecycle.SequentialWorkerOwner, "local_owner_required")
        assert isinstance(owner, worker_lifecycle.SequentialWorkerOwner)
        epoch = owner.begin_attempt(1)
        try:
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            output.mkdir(mode=0o700)
            record = journal.begin(
                job_id="standalone:" + uuid.uuid4().hex,
                backend_url="",
                engagement_id=context.engagement_id,
                job_type="recon" if recon else "vardrgate_api_test",
                tool="recon" if recon else "vardrgate_api_test",
                target_source="explicit",
                command_profile={
                    "standalone_profile": plan["profile"],
                    "origin": "standalone",
                    "controlled": True,
                    "local_worker": True,
                    "contract_sha256": digest(encoded(envelope)),
                    "plan_sha256": digest(encoded(plan)),
                    "signed_job_id": payload["job_id"],
                    "attempt_id": payload["attempt_id"],
                    "fence": payload["fence"],
                    "grant_policy": "none/1" if recon else "expiring/1",
                },
            )
            run_id = record.run_id
            journal.transition(
                run_id, Phase.VALIDATING, run_dir=str(output), upload_state="not_applicable"
            )
            journal.transition(
                run_id,
                Phase.TARGETS_RESOLVED,
                target_count=len(case["hostnames"]) if recon else len(sites),
            )
            journal.transition(run_id, Phase.CLAIMING)
            entered, anchor = time.monotonic(), datetime.now(timezone.utc)
            with ExitStack() as stack:
                policy = stack.enter_context(credential_grants.required("standalone"))
                if recon:
                    policy.check(context.engagement_id, sites, [])
                else:
                    handlers.check_gate_case(case, context.engagement_id)
                # The inherited native ceiling and every renewal only shorten this cap.
                work_until = min(
                    admission.expires_at
                    - timedelta(seconds=worker_lifecycle.REPORT_RUNWAY_SECONDS),
                    context.now
                    + timedelta(
                        seconds=min(
                            permission["max_duration_seconds"], plan["execution"]["timeout_seconds"]
                        )
                    ),
                )
                if recon:
                    from vardrrunner.authorization.contracts import timestamp

                    work_until = min(work_until, timestamp(execution["deadline"]))
                hard_end = entered + max(0.0, (work_until - anchor).total_seconds())
                if policy.expires_at is not None:
                    hard_end = min(hard_end, entered + (policy.expires_at - anchor).total_seconds())
                binding = {
                    "origin": "standalone",
                    "job_id": context.job_id,
                    "runner_id": context.runner_id,
                    "contract_id": payload["contract_id"],
                    "attempt_id": context.attempt_id,
                    "fence": context.fence,
                    "contract_sha256": digest(encoded(envelope)),
                }
                control_binding = {k: v for k, v in binding.items() if k != "contract_sha256"}
                control_binding.update(
                    authority_revision=context.authority_revision,
                    authority_sha256=context.authority_sha256,
                )

                def current(*, grants: bool = True):
                    now = max(
                        datetime.now(timezone.utc),
                        anchor + timedelta(seconds=time.monotonic() - entered),
                    )
                    validate(
                        envelope,
                        approval,
                        plan,
                        case,
                        execution,
                        anchors,
                        replace(context, now=now),
                    )
                    ledger.check_state(context, payload["issuer"]["id"])
                    if grants:
                        policy.check(
                            context.engagement_id,
                            sites,
                            references,
                        )
                    require(not journal.stop_requested(run_id), "local_emergency_stop")
                    end = min(time.monotonic() + 9, hard_end)
                    epoch.verified_lease(binding, end, hard_end)
                    return {
                        **control_binding,
                        "action": "continue",
                        "lease_seconds": end - time.monotonic(),
                    }

                control = execution_control.Control(
                    current,
                    control_binding,
                    min(9, hard_end - entered),
                    started=entered,
                    local_stop=lambda: journal.stop_requested(run_id),
                    lease_deadline=lambda: hard_end,
                )

                def reserved():
                    journal.transition(run_id, Phase.CLAIMED, claimed_at=utc_now())
                    journal.transition(run_id, Phase.EXECUTING)
                    current()  # Consumption has committed before the first native LEASE.
                    stack.enter_context(execution_control.controlled(control))

                def finished(artifact: Path):
                    resources.enforce_artifact(artifact, resources.load_limits().max_artifact_bytes)
                    control.quiesce(hard_end)
                    require(not control.stop_reason(), "local_completion_expired_or_stopped")
                    epoch.seal()
                    proof = (
                        epoch.finished()
                    )  # Descendant drain and native ACK precede ledger completion.
                    journal.transition(
                        run_id, Phase.EXECUTING, last_event="native_done_ack:" + proof
                    )

                def observed(pid):
                    journal.transition(run_id, Phase.EXECUTING, pid=pid)

                with (
                    launch_guard.monotonic_deadline(hard_end),
                    launch_guard.revalidation(lambda: current(grants=False)),
                    runner.observe_process(observed),
                ):
                    artifact = (execute_recon if recon else execute_gate)(
                        ledger,
                        envelope,
                        approval,
                        plan,
                        case,
                        execution,
                        anchors,
                        context,
                        output,
                        on_reserved=reserved,
                        before_finish=finished,
                    )
            journal.transition(run_id, Phase.EXECUTING, pid=None)
            journal.attach_artifact(run_id, artifact)
            terminal = journal.finish(run_id, Phase.DONE, status="done")
        except execution_control.ExecutionStopped as stopped:
            if record is not None:
                _retain_pid(journal, run_id, stopped.pid)
                _failed(journal, run_id, confirmed=stopped.confirmed is True)
            raise
        except BaseException:
            if record is not None:
                _failed(journal, run_id)
            raise
    # Execution is terminal and the native owner channel is closed. Export failure
    # changes only delivery status; it never relabels DONE or reexecutes the job.
    result = {
        "run_id": terminal.run_id,
        "workspace_id": context.engagement_id,
        "artifact_sha256": terminal.artifact_sha256,
        "status": "done",
        "export_status": "not_requested",
    }
    if EXPORT.is_dir() and not os.statvfs(EXPORT).f_flag & os.ST_RDONLY:  # type: ignore[attr-defined]
        try:
            export_run(terminal.run_id, EXPORT / "result")
            result["export_status"] = "completed"
        except Exception:
            result["export_status"] = "held"
    return result


def main(argv: list[str] | None = None) -> int:
    if sys.argv[1:] if argv is None else argv:
        print("local_worker_arguments_refused")
        return 1
    try:
        result = run()
        print(json.dumps(result, sort_keys=True))
        return 2 if result.get("export_status") == "held" else 0
    except (Exception, KeyboardInterrupt):
        print("local_worker_held")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
