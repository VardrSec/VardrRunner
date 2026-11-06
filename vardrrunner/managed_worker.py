"""Explicit one-attempt managed worker composition; inactive on ordinary startup."""

from __future__ import annotations

import argparse
import os
import re
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn, Protocol, cast

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
from vardrrunner.authorization.worker_binding import SequenceStore, WorkerStore, sequence_holds
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


class Epoch(Protocol):
    def require_active(self) -> None: ...
    def verified_lease(self, binding: dict, lease_end: float, hard_end: float) -> None: ...
    def seal(self) -> None: ...
    def quiescence_deadline(self) -> float: ...
    def finished(self) -> str: ...


class SequenceOwner(Owner, Protocol):
    def begin_attempt(self, runtime_sequence: int) -> Epoch: ...


class _EpochRefresh:
    """Pin one immutable epoch across even a blocked refresh RPC."""

    def __init__(self, epoch: Epoch, send: Callable[[dict], dict]):
        self.epoch, self.send = epoch, send
        self._lock = threading.Lock()
        self._in_flight = 0

    def __call__(self, body: dict) -> dict:
        with self._lock:
            self.epoch.require_active()
            self._in_flight += 1
        try:
            reply = self.send(body)
            self.epoch.require_active()
            return reply
        finally:
            with self._lock:
                self._in_flight -= 1

    def require_quiescent(self) -> None:
        with self._lock:
            require(self._in_flight == 0, "worker_refresh_in_flight")


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
        self.store: WorkerStore | SequenceStore = (
            WorkerStore(journal) if admission.max_attempts is None else SequenceStore(journal)
        )
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
        with self.journal._connection() as con:
            require(sequence_holds(con) == 0, "worker_unresolved_local_attempt")
        if isinstance(self.store, WorkerStore):
            self.store.reserve_runtime(self.admission.runtime_id, self.admission.runtime_sha256)
            job = self._discover(wait_seconds, poll_seconds)
            return None if job is None else self._run_job(job)
        maximum = self.admission.max_attempts
        require(maximum is not None, "worker_sequence_admission_required")
        assert maximum is not None
        self.store.reserve_runtime(
            self.admission.runtime_id, self.admission.runtime_sha256, maximum
        )
        last = None
        for sequence in range(1, maximum + 1):
            require(local_holds(self.journal) == 0, "worker_unresolved_local_attempt")
            with self.journal._connection() as con:
                require(sequence_holds(con) == 0, "worker_unresolved_local_attempt")
            job = self._discover(wait_seconds, poll_seconds)
            if job is None:
                return last
            # The callback captures this epoch before Entry/Gate construction.
            epoch = cast(SequenceOwner, self.owner).begin_attempt(sequence)
            epoch.require_active()
            last = self._run_job(job, sequence=sequence, epoch=epoch)
        return last

    def _run_job(
        self, job: dict, *, sequence: int | None = None, epoch: Epoch | None = None
    ) -> RunRecord:
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

        refresh = (
            _EpochRefresh(epoch, lambda body: post("refresh", body)) if epoch is not None else None
        )

        def prepare_claim(con, run_id):
            public = dict(
                runtime_id=self.admission.runtime_id,
                runtime_sha256=self.admission.runtime_sha256,
                runner_id=self.runner_id,
                enrollment_id=self.admission.enrollment_id,
            )
            if isinstance(self.store, SequenceStore):
                require(sequence is not None, "worker_sequence_required")
                assert sequence is not None
                self.store.prepare_claim(con, run_id, runtime_sequence=sequence, **public)
            else:
                self.store.prepare_claim(con, run_id, **public)

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
            if sequence is not None:
                binding["runtime_sequence"] = sequence
            self.store.prepare_binding(handle.run_id, binding)
            self._ready()
            acknowledgement = post(
                "runtime-bind",
                {
                    **body,
                    "runtime_id": binding["runtime_id"],
                    "runtime_sha256": binding["runtime_sha256"],
                    **({"runtime_sequence": sequence} if sequence is not None else {}),
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
                    **({"runtime_sequence": sequence} if sequence is not None else {}),
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
            current=refresh if refresh is not None else lambda body: post("refresh", body),
            consume=consume,
            verified_lease=self.owner.verified_lease if epoch is None else None,
            verified_runtime_lease=epoch.verified_lease if epoch is not None else None,
            preclaim_check=preclaim_check,
            before_claim_send=prepare_claim,
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
                if not handle.finalize_stopped(
                    lambda body: post("result", body), lambda body: post("finish", body)
                ):
                    handle.report_stop(lambda body: post("stopped", body))
            except BaseException:
                pass
            raise
        completion = handle.finalize(
            lambda body: post("result", body), lambda body: post("finish", body)
        )
        if epoch is None:
            self.owner.finished()
        else:
            require(
                isinstance(self.store, SequenceStore) and refresh is not None,
                "worker_sequence_required",
            )
            assert isinstance(self.store, SequenceStore) and refresh is not None
            require(completion["outcome"] == "completed", "worker_healthy_completion_required")
            self.store.completion(handle.run_id, completion)
            epoch.seal()
            require(handle.gate.control is not None, "worker_control_missing")
            assert handle.gate.control is not None
            # No owner/Gate/refresh mutex is held across this bounded join.
            handle.gate.control.quiesce(epoch.quiescence_deadline())
            refresh.require_quiescent()
            self.store.done(handle.run_id, epoch.finished())
            expected = self.store.prepare_release(handle.run_id)
            self._ready()
            acknowledgement = post(
                "runtime-idle-release",
                {
                    **handle.gate.request,
                    "contract_sha256": expected["binding"]["contract_sha256"],
                    **{
                        key: expected[key]
                        for key in (
                            "runtime_id",
                            "runtime_sha256",
                            "runtime_sequence",
                            "terminal_receipt_sha256",
                            "native_done_sha256",
                        )
                    },
                },
            )
            self.store.acknowledge_release(handle.run_id, acknowledgement)
        record = self.journal.get(handle.run_id)
        require(record is not None, "worker_terminal_record_missing")
        assert record is not None
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
        require(admission.max_attempts is not None, "worker_sequence_admission_required")
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
