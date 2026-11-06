"""Explicit one-attempt managed worker composition; inactive on ordinary startup."""

from __future__ import annotations

import argparse
import os
import re
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn, Protocol

from vardrrunner import api, config, execution_control, identity
from vardrrunner.authorization.claim import ManagedEntry, ManagedRun
from vardrrunner.authorization.codec import (
    AuthorizationError,
    TrustAnchor,
    digest,
    encoded,
    fields,
    integer,
    require,
)
from vardrrunner.authorization.documents import read_anchors, read_document
from vardrrunner.authorization.reconciliation import local_holds
from vardrrunner.authorization.results import BINDING
from vardrrunner.authorization.worker_admission import Admission
from vardrrunner.authorization.worker_binding import WorkerStore
from vardrrunner.journal import Journal, Phase, RunRecord

ADMISSION_PATH = Path("/run/vardr-worker-admission/admission.json")
TRUST_PATH = Path("/run/vardr-worker-admission/trust.json")
STARTUP_SECONDS = 120


def await_admission(
    path: Path,
    seconds: int,
    *,
    clock: Callable[[], datetime] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Admission:
    """Await only absence of an atomically published public record, not bad data."""
    integer(seconds, 1, 90)
    clock = clock or (lambda: datetime.now(timezone.utc))
    entered, wall = monotonic(), clock()
    while True:
        elapsed = monotonic() - entered
        require(elapsed >= 0, "worker_clock_rollback")
        remaining = min(seconds - elapsed, seconds - (clock() - wall).total_seconds())
        require(remaining > 0, "worker_admission_unavailable")
        try:
            admission = Admission.parse(read_document(path), now=clock())
        except FileNotFoundError:
            sleep(min(0.25, remaining))
            continue
        require(
            monotonic() - entered < seconds and (clock() - wall).total_seconds() < seconds,
            "worker_admission_unavailable",
        )
        return admission


class Owner(Protocol):
    """Actual lifecycle adapter supplies proof and activates native control."""

    def require_ready(self, admission: Admission) -> None: ...

    def require_allocation(self, seconds: int) -> None: ...

    def verified_lease(self, binding: dict, lease_end: float, hard_end: float) -> None: ...

    def finished(self) -> None: ...


def _job_id(value: object) -> str:
    require(
        type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is not None,
        "worker_job_identity",
    )
    return str(value)


class Worker:
    """Use one existing ManagedEntry; neither loop claims nor recover execution."""

    def __init__(
        self,
        client: api.VardrMapClient,
        journal: Journal,
        admission: Admission,
        anchors: tuple[TrustAnchor, ...],
        owner: Owner,
        *,
        runner_id: str,
        principal_sha256: str,
        allocated_seconds: int,
        output_root: Path,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.client, self.journal, self.admission = client, journal, admission
        self.anchors, self.owner = anchors, owner
        self.runner_id, self.principal_sha256 = runner_id, principal_sha256
        self.allocated_seconds = integer(allocated_seconds, 1, 86400)
        self.output_root = output_root
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.monotonic, self.sleep = monotonic, sleep
        self.store = WorkerStore(journal)
        self._used = False

    def _ready(self) -> None:
        self.admission.require_current(
            now=self.clock(), origin=self.client.base, runner_id=self.runner_id
        )
        self.owner.require_ready(self.admission)
        # On Linux this is supplied only by the actual verified owner context;
        # an admission file, environment variable or callback cannot enable it.
        require(execution_control.available(), "controlled_process_tree_unsupported")

    def _discover(self, wait_seconds: int, poll_seconds: float) -> dict | None:
        entered, wall = self.monotonic(), self.clock()
        cursor = None

        def remaining() -> float:
            elapsed = self.monotonic() - entered
            require(elapsed >= 0, "worker_clock_rollback")
            return min(
                wait_seconds - elapsed,
                wait_seconds - (self.clock() - wall).total_seconds(),
            )

        while True:
            self._ready()
            left = remaining()
            if left <= 0:
                return None
            body = {"origin": self.admission.origin, "runner_id": self.runner_id, "limit": 1}
            if cursor is not None:
                body["after"] = cursor
            reply = self.client.managed_post("/jobs/managed/pending", body)
            if remaining() <= 0:
                return None  # A late discovery reply never authorizes a later claim.
            fields(reply, {"jobs", "next_after"})
            require(type(reply["jobs"]) is list and len(reply["jobs"]) <= 1, "worker_pending_size")
            cursor = None if reply["next_after"] is None else _job_id(reply["next_after"])
            if reply["jobs"]:
                return fields(
                    reply["jobs"][0],
                    {
                        "id",
                        "program_id",
                        "tool_type",
                        "authorization_contract_required",
                        "config",
                        "plan",
                    },
                )
            left = remaining()
            if left <= 0:
                return None
            self.sleep(min(poll_seconds, left))

    def run(self, *, wait_seconds: int = 30, poll_seconds: float = 1.0) -> RunRecord | None:
        require(not self._used, "single_worker_invocation")
        self._used = True
        integer(wait_seconds, 1, 60)
        require(
            type(poll_seconds) in (int, float) and 0.1 <= poll_seconds <= 30,
            "worker_poll_interval",
        )
        self._ready()
        require(local_holds(self.journal) == 0, "worker_unresolved_local_attempt")
        self.store.reserve_runtime(self.admission.runtime_id, self.admission.runtime_sha256)
        job = self._discover(wait_seconds, poll_seconds)
        if job is None:
            return None
        self._ready()
        job_id = _job_id(job["id"])
        engagement_id = _job_id(job["program_id"])
        require(
            job["authorization_contract_required"] is True
            and job["tool_type"] == "vardrgate_api_test",
            "worker_managed_gate_required",
        )
        case = fields(job["config"], {"test_case"})["test_case"]
        plan = job["plan"]
        require(
            type(plan) is dict
            and plan.get("profile") == "gate-fixed-http/1"
            and type(plan.get("execution")) is dict,
            "worker_fixed_plan_required",
        )
        self.output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = self.output_root / ("managed-" + uuid.uuid4().hex)
        directory.mkdir(mode=0o700)

        def post(operation: str, body: dict) -> dict:
            return self.client.managed_post(f"/jobs/{job_id}/managed/{operation}", body)

        handle: ManagedRun

        def consume(body: dict) -> dict:
            self._ready()
            reply = post("consume", body)
            expected = {
                **handle.gate.binding,
                "schema": "vardr.managed-consumption/1",
                "contract_sha256": digest(encoded(handle.gate.envelope)),
                "consumed": True,
            }
            fields(reply, set(expected))
            integer(reply["fence"], 1)
            integer(reply["authority_revision"])
            require(reply == expected and reply["consumed"] is True, "managed_consumption_binding")
            binding = {key: expected[key] for key in BINDING}
            binding.update(
                runtime_id=self.admission.runtime_id,
                runtime_sha256=self.admission.runtime_sha256,
            )
            self.store.prepare_binding(handle.run_id, binding)
            self._ready()
            acknowledgement = post(
                "runtime-bind",
                {
                    **body,
                    "runtime_id": binding["runtime_id"],
                    "runtime_sha256": binding["runtime_sha256"],
                },
            )
            self.store.acknowledge_binding(handle.run_id, binding, acknowledgement)
            return reply

        def preclaim_check() -> None:
            self._ready()
            # The independent owner checks its immutable suspend-aware ceiling
            # immediately before the only claim RPC. A file/boolean cannot arm it.
            self.owner.require_allocation(self.allocated_seconds)

        def claim(body: dict) -> dict:
            return post(
                "claim",
                {
                    **body,
                    "runtime_id": self.admission.runtime_id,
                    "runtime_sha256": self.admission.runtime_sha256,
                },
            )

        entry = ManagedEntry(
            self.journal,
            map_origin=self.admission.origin,
            runner_id=self.runner_id,
            engagement_id=engagement_id,
            job_id=job_id,
            principal_sha256=self.principal_sha256,
            case=case,
            execution=plan["execution"],
            allocated_seconds=self.allocated_seconds,
            anchors=self.anchors,
            claim=claim,
            current=lambda body: post("refresh", body),
            consume=consume,
            verified_lease=self.owner.verified_lease,
            preclaim_check=preclaim_check,
            before_claim_send=lambda con, run_id: self.store.prepare_claim(
                con,
                run_id,
                runtime_id=self.admission.runtime_id,
                runtime_sha256=self.admission.runtime_sha256,
                runner_id=self.runner_id,
                enrollment_id=self.admission.enrollment_id,
            ),
            clock=self.clock,
            monotonic=self.monotonic,
        )
        handle = entry.acquire(directory)
        try:
            handle.execute(directory)
        except BaseException:
            # Existing native ownership/proof decides whether any stop may be
            # reported. Unknown state stays held; no second claim or RPC replay.
            try:
                handle.report_stop(lambda body: post("stopped", body))
            except Exception:
                pass
            raise
        handle.finalize(lambda body: post("result", body), lambda body: post("finish", body))
        self.owner.finished()
        record = self.journal.get(handle.run_id)
        require(record is not None, "worker_terminal_record_missing")
        return record


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise AuthorizationError("worker_arguments")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--admission", type=Path, default=ADMISSION_PATH)
    parser.add_argument("--trust", type=Path, default=TRUST_PATH)
    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=os.environ.get("VARDRRUNNER_WORKER_DURATION_SECONDS", "30"),
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=os.environ.get("VARDRRUNNER_WORKER_WAIT_SECONDS", "30"),
    )
    parser.add_argument(
        "--admission-wait-seconds",
        type=int,
        default=os.environ.get("VARDRRUNNER_WORKER_ADMISSION_WAIT_SECONDS", "60"),
    )
    try:
        entered, wall = time.monotonic(), datetime.now(timezone.utc)
        args = parser.parse_args(argv)
        integer(args.duration_seconds, 1, 86400)
        integer(args.wait_seconds, 1, 60)
        integer(args.admission_wait_seconds, 1, 90)
        # This factory must establish the actual owner channel/native context;
        # public metadata and caller flags never supply its readiness proof.
        from vardrrunner.worker_lifecycle import connect

        url, key = config.require_auth()
        runner_id = identity.load_or_create().runner_id
        admission = await_admission(args.admission, args.admission_wait_seconds)
        admission.require_current(now=datetime.now(timezone.utc), origin=url, runner_id=runner_id)
        with connect(admission) as owner:
            remaining = int(
                min(
                    args.wait_seconds,
                    STARTUP_SECONDS - (time.monotonic() - entered),
                    STARTUP_SECONDS - (datetime.now(timezone.utc) - wall).total_seconds(),
                )
            )
            require(remaining > 0, "worker_startup_expired")
            record = Worker(
                api.VardrMapClient(url, key),
                Journal(config.journal_file()),
                admission,
                read_anchors(args.trust),
                owner,
                runner_id=runner_id,
                principal_sha256=digest(("Bearer " + key).encode()),
                allocated_seconds=args.duration_seconds,
                output_root=config.runs_dir(),
            ).run(wait_seconds=remaining)
        return 0 if record is None or record.phase == Phase.DONE else 1
    except (Exception, KeyboardInterrupt):
        # No transport body, target, credential, pathname or raw exception output.
        print("managed_worker_held")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
