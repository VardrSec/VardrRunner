"""Unregistered one-shot managed handoff; explicit receipts, no automatic recovery."""

from __future__ import annotations

import copy
import json
import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from vardrrunner import (
    configs,
    credential_grants,
    execution_control,
    handlers,
    resources,
    runner,
    target_budget,
    target_safety,
)
from vardrrunner.journal import Journal, Phase, normalize_backend_url, utc_now

from .codec import (
    AuthorizationError,
    TrustAnchor,
    digest,
    encoded,
    fields,
    integer,
    require,
    verify,
)
from .contracts import ValidationContext, approved
from .ledger import AuthorizationLedger
from .managed import ManagedGate
from .plan import compile_gate_plan

PROFILE = "managed-claim/1"


class ClaimError(AuthorizationError):
    """Fixed local reason; never a raw transport or journal exception."""


class ClaimStore:
    """Additive tombstones in the SAME journal; no capability or signed payload."""

    def __init__(self, journal: Journal):
        self.journal = journal
        with journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("""CREATE TABLE IF NOT EXISTS managed_claim_intents (
                run_id TEXT PRIMARY KEY, backend TEXT NOT NULL, job TEXT NOT NULL,
                owner TEXT NOT NULL, state TEXT NOT NULL, plan_sha256 TEXT NOT NULL,
                case_sha256 TEXT NOT NULL, tool_sha256 TEXT NOT NULL, association_sha256 TEXT NOT NULL,
                utc_anchor TEXT, mono_anchor REAL, issuer TEXT, contract TEXT,
                attempt TEXT, fence INTEGER, approval_sha256 TEXT,
                authority_sha256 TEXT,
                UNIQUE(backend,job))""")
            columns = {
                row["name"] for row in con.execute("PRAGMA table_info(managed_claim_intents)")
            }
            require("association_sha256" in columns, "unsupported_managed_claim_schema")
            # Additive audit markers survive a later held state. They never
            # reconstruct permission, transport capabilities, or retry rights.
            for name in ("consumption_sent", "consumption_acknowledged"):
                if name not in columns:
                    con.execute(
                        f"ALTER TABLE managed_claim_intents ADD COLUMN {name} INTEGER NOT NULL DEFAULT 0"
                    )

    def reserve(self, run_id: str, fingerprint: dict, identity: dict) -> str:
        owner = uuid.uuid4().hex
        try:
            with self.journal._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                row = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
                require(row is not None, "managed_run_missing")
                require(
                    set(identity)
                    == {
                        "backend_url",
                        "job_id",
                        "engagement_id",
                        "job_type",
                        "tool",
                        "target_source",
                    }
                    and all(row[key] == value for key, value in identity.items()),
                    "managed_run_identity",
                )
                profile = json.loads(row["command_profile"])
                require(
                    profile.get("managed_profile") == PROFILE
                    and all(profile.get(k) == v for k, v in fingerprint.items()),
                    "managed_run_binding",
                )
                require(
                    row["phase"]
                    in {
                        Phase.DISCOVERED.value,
                        Phase.VALIDATING.value,
                        Phase.TARGETS_RESOLVED.value,
                    },
                    "managed_run_already_started",
                )
                con.execute(
                    "INSERT INTO managed_claim_intents (run_id,backend,job,owner,state,plan_sha256,case_sha256,tool_sha256,association_sha256) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        run_id,
                        row["backend_url"],
                        row["job_id"],
                        owner,
                        "reserved",
                        fingerprint["plan_sha256"],
                        fingerprint["case_sha256"],
                        fingerprint["tool_sha256"],
                        fingerprint["association_sha256"],
                    ),
                )
        except sqlite3.IntegrityError:
            raise ClaimError("managed_claim_already_reserved") from None
        return owner

    def prepare_send(
        self,
        run_id: str,
        owner: str,
        utc: datetime,
        mono: float,
        before_claim_send: Callable[[sqlite3.Connection, str], None] | None = None,
    ) -> None:
        require(
            utc.tzinfo is not None and type(mono) in {int, float} and math.isfinite(mono),
            "invalid_claim_clock",
        )
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            changed = con.execute(
                "UPDATE managed_claim_intents SET state='claim_in_flight',utc_anchor=?,mono_anchor=? WHERE run_id=? AND owner=? AND state='reserved'",
                (utc.isoformat(), mono, run_id, owner),
            ).rowcount
            require(changed == 1, "managed_claim_not_owned")
            changed = con.execute(
                "UPDATE runs SET phase=?,last_event=?,updated_at=? WHERE run_id=? AND phase=?",
                (
                    Phase.CLAIMING.value,
                    "managed_claim_send_reserved",
                    utc_now(),
                    run_id,
                    Phase.TARGETS_RESOLVED.value,
                ),
            ).rowcount
            require(changed == 1, "managed_claim_phase")
            if before_claim_send is not None:
                # Trusted metadata-only hook on this exact transaction. No
                # transport/second connection may intervene before its commit.
                before_claim_send(con, run_id)

    def hold(self, run_id: str, owner: str, state: str) -> None:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            changed = con.execute(
                "UPDATE managed_claim_intents SET state=? WHERE run_id=? AND owner=? AND state IN ('reserved','claim_in_flight','bound','consume_in_flight','consume_acknowledged')",
                (state, run_id, owner),
            ).rowcount
            require(changed == 1, "managed_claim_not_owned")
            con.execute(
                "UPDATE runs SET status=?,last_event=?,updated_at=? WHERE run_id=?",
                (state, state, utc_now(), run_id),
            )

    def bind(self, run_id: str, owner: str, gate: ManagedGate) -> None:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            p = gate.payload
            changed = con.execute(
                "UPDATE managed_claim_intents SET state='bound',issuer=?,contract=?,attempt=?,fence=?,approval_sha256=?,authority_sha256=? WHERE run_id=? AND owner=? AND state='claim_in_flight'",
                (
                    p["issuer"]["id"],
                    p["contract_id"],
                    p["attempt_id"],
                    p["fence"],
                    digest(encoded(gate.approval)),
                    gate.context.authority_sha256,
                    run_id,
                    owner,
                ),
            ).rowcount
            require(changed == 1, "managed_claim_not_owned")
            con.execute(
                "UPDATE runs SET phase=?,claimed_at=?,last_event=?,updated_at=? WHERE run_id=?",
                (Phase.CLAIMED.value, utc_now(), "managed_claim_bound", utc_now(), run_id),
            )

    def consumption(self, run_id: str, owner: str, *, acknowledged: bool) -> None:
        before, after = (
            ("consume_in_flight", "consume_acknowledged")
            if acknowledged
            else ("bound", "consume_in_flight")
        )
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            changed = con.execute(
                "UPDATE managed_claim_intents SET state=?,consumption_sent=1,consumption_acknowledged=? WHERE run_id=? AND owner=? AND state=?",
                (after, int(acknowledged), run_id, owner, before),
            ).rowcount
            require(changed == 1, "managed_consumption_not_owned")


class ManagedRun:
    """In-memory capability handle. Durable state never reconstructs this handle."""

    def __init__(
        self,
        gate: ManagedGate,
        store: ClaimStore,
        run_id: str,
        owner: str,
        artifact_limit: int,
        consume: Callable[[dict], dict] | None = None,
    ):
        self.gate, self.store, self.run_id, self._owner = gate, store, run_id, owner
        self._artifact_limit = artifact_limit
        self._used, self._lock = False, threading.Lock()
        self._consume = consume
        self._returned_artifact: tuple[Path, str, int] | None = None
        self._confirmed_stop: tuple[str, str] | None = None

    def _acknowledge(self, request: dict) -> None:
        require(self._consume is not None, "managed_consumption_transport_required")
        assert self._consume is not None
        self.store.consumption(self.run_id, self._owner, acknowledged=False)
        try:
            reply = self._consume(request)
        except Exception:
            raise ClaimError("managed_consumption_outcome_unknown") from None
        expected = {
            **self.gate.binding,
            "schema": "vardr.managed-consumption/1",
            "contract_sha256": digest(encoded(self.gate.envelope)),
            "consumed": True,
        }
        fields(reply, set(expected))
        integer(reply["fence"], 1)
        integer(reply["authority_revision"])
        require(reply["consumed"] is True and reply == expected, "managed_consumption_binding")
        self.store.consumption(self.run_id, self._owner, acknowledged=True)

    def execute(self, directory: Path) -> Path:
        with self._lock:
            require(not self._used, "single_managed_execution")
            self._used = True
        journal = self.store.journal

        def observed(pid: int) -> None:
            # WindowsJob's grant transaction has ended before this observer.
            journal.transition(self.run_id, Phase.EXECUTING, pid=pid)

        try:
            journal.transition(
                self.run_id,
                Phase.EXECUTING,
                run_dir=str(directory),
                last_event="managed_local_execution",
            )
            with runner.observe_process(observed):
                output = self.gate.execute(directory, consume=self._acknowledge)
            resources.enforce_artifact(
                output, min(self._artifact_limit, self.gate.permission["max_artifact_bytes"])
            )
            record = journal.transition(
                self.run_id,
                Phase.ARTIFACT_READY,
                pid=None,
                artifact_path=str(output),
                artifact_sha256=digest(output.read_bytes()),
                artifact_size=output.stat().st_size,
                status="local_artifact_held",
                last_event="managed_artifact_not_uploaded",
            )
            self._returned_artifact = (
                output,
                record.artifact_sha256 or "",
                record.artifact_size or 0,
            )
            return output
        except BaseException as exc:
            if isinstance(exc, execution_control.ExecutionStopped) and exc.confirmed is True:
                from .stops import CANCEL_CAUSES, CAUSES

                cause = exc.args[0] if len(exc.args) == 1 else None
                if type(cause) is str and cause in CAUSES:
                    try:
                        journal.transition(
                            self.run_id,
                            Phase.EXECUTING,
                            last_event="managed_native_stop_confirmed",
                        )
                        self._confirmed_stop = (
                            "cancelled" if cause in CANCEL_CAUSES else "failed",
                            cause,
                        )
                    except Exception:
                        pass  # Lost durable proof is a hold, never a report right.
            try:
                self.store.hold(self.run_id, self._owner, "held_after_claim")
            except Exception:
                pass
            raise

    def finalize(self, submit: Callable[[dict], dict], finish: Callable[[dict], dict]) -> dict:
        from .results import finalize

        return finalize(self, submit, finish)

    def report_stop(self, send: Callable[[dict], dict]) -> None:
        from .stops import report

        report(self, send)


class ManagedEntry:
    """One explicit claim invocation; finalization uses the returned one-shot handle."""

    def __init__(
        self,
        journal: Journal,
        *,
        map_origin: str,
        runner_id: str,
        engagement_id: str,
        job_id: str,
        principal_sha256: str,
        case: dict,
        execution: dict,
        allocated_seconds: int,
        anchors: tuple[TrustAnchor, ...],
        claim: Callable[[dict], dict],
        current: Callable[[dict], dict],
        consume: Callable[[dict], dict] | None = None,
        verified_lease: Callable[[dict, float, float], None] | None = None,
        verified_runtime_lease: Callable[[dict, float, float], None] | None = None,
        preclaim_check: Callable[[], None] | None = None,
        before_claim_send: Callable[[sqlite3.Connection, str], None] | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.journal, self.store = journal, ClaimStore(journal)
        self.origin = normalize_backend_url(map_origin)
        require(self.origin == map_origin, "configured_origin_required")
        self.runner_id, self.engagement_id, self.job_id = runner_id, engagement_id, job_id
        self.principal_sha256, self.anchors = principal_sha256, anchors
        self.case, self.execution = copy.deepcopy(case), copy.deepcopy(execution)
        self.allocated_seconds = allocated_seconds
        self._claim, self._current = claim, current
        self._consume = consume
        self._verified_lease = verified_lease
        self._verified_runtime_lease = verified_runtime_lease
        self._preclaim_check = preclaim_check
        self._before_claim_send = before_claim_send
        self.clock, self.monotonic = clock or (lambda: datetime.now(timezone.utc)), monotonic
        self._used = False
        self._artifact_limit: int | None = None
        self._invocation = uuid.uuid4().hex
        self.run_id: str | None = None

    def _check(self, directory: Path, plan: dict | None = None):
        require(execution_control.available(), "controlled_process_tree_unsupported")
        integer(self.allocated_seconds, 1, 86400)
        cfg = configs.VardrGateConfig.from_dict(
            {"test_case": self.case, "execution": self.execution}
        )
        handlers.check_gate_case(self.case, self.engagement_id)
        binding, compiled = target_budget.prepare(cfg)
        require(
            encoded(
                compile_gate_plan(self.case, self.execution, tool_sha256=compiled["tool_sha256"])
            )
            == encoded(compiled),
            "local_private_option_mismatch",
        )
        require(plan is None or encoded(plan) == encoded(compiled), "execution_plan_changed")
        targets = [d["request"]["url"] for d in compiled["dispatches"]]
        rules = target_safety.load_deny_rules()
        _, denied = target_safety.apply_deny_rules(targets, rules)
        require(not denied or target_safety.override_enabled(), "local_target_denied")
        limits = resources.load_limits()
        self._artifact_limit = (
            min(self._artifact_limit, limits.max_artifact_bytes)
            if self._artifact_limit is not None
            else limits.max_artifact_bytes
        )
        require(len(binding["origins"]) <= limits.max_targets, "local_target_limit")
        resources.ensure_free_space(directory, limits.min_free_disk_bytes)
        require(
            directory.is_dir() and not (directory / "vardrgate_result.json").exists(),
            "exclusive_output_required",
        )
        return binding, compiled

    def acquire(self, directory: Path) -> ManagedRun:
        require(not self._used, "single_managed_claim")
        self._used = True
        with credential_grants.required(self.origin) as policy:
            binding, plan = self._check(directory)
            fingerprints = {
                "plan_sha256": digest(encoded(plan)),
                "case_sha256": plan["case_hash"],
                "tool_sha256": plan["tool_sha256"],
                "association_sha256": digest(
                    encoded(
                        {
                            "origin": self.origin,
                            "runner_id": self.runner_id,
                            "principal_sha256": self.principal_sha256,
                        }
                    )
                ),
            }
            record = self.journal.begin(
                job_id=self.job_id,
                backend_url=self.origin,
                engagement_id=self.engagement_id,
                job_type="vardrgate_api_test",
                tool="vardrgate_api_test",
                target_source="case",
                command_profile={
                    "controlled": True,
                    "grant_policy": "expiring/1",
                    "managed_profile": PROFILE,
                    "managed_invocation": self._invocation,
                    **fingerprints,
                },
            )
            self.run_id = record.run_id
            require(
                record.command_profile.get("managed_invocation") == self._invocation,
                "managed_claim_existing_invocation",
            )
            try:
                owner = self.store.reserve(
                    record.run_id,
                    fingerprints,
                    {
                        "backend_url": self.origin,
                        "job_id": self.job_id,
                        "engagement_id": self.engagement_id,
                        "job_type": "vardrgate_api_test",
                        "tool": "vardrgate_api_test",
                        "target_source": "case",
                    },
                )  # A begin return is NOT ownership.
            except ClaimError as error:
                if error.args == ("managed_claim_already_reserved",):
                    try:
                        from .reconciliation import retire_reserve_conflict

                        retire_reserve_conflict(
                            self.journal, record.run_id, self._invocation, self.origin, self.job_id
                        )
                    except Exception:
                        pass  # Uncertain metadata stays held; no RPC has been attempted.
                raise
            try:
                self.journal.transition(record.run_id, Phase.VALIDATING)
                self.journal.transition(record.run_id, Phase.TARGETS_RESOLVED)
                mono, utc = self.monotonic(), self.clock()
                require(utc.tzinfo is not None, "invalid_claim_clock")
                self.store.prepare_send(record.run_id, owner, utc, mono, self._before_claim_send)
                self._check(directory, plan)  # No journal writer held while checking grants.
                require(not self.journal.stop_requested(record.run_id), "local_stop_before_claim")
                handlers.check_gate_case(
                    self.case, self.engagement_id
                )  # Last blocking check after all preparation/journal waits.
                if self._preclaim_check is not None:
                    # Trusted local-only check, inside the known pre-RPC guard.
                    # Opaque claim callback failures below remain unknown sends.
                    self._preclaim_check()
            except Exception:
                try:
                    self.store.hold(record.run_id, owner, "denied_before_rpc")
                    from .reconciliation import retire_preclaim

                    retire_preclaim(self.journal, record.run_id)
                except Exception:
                    pass
                raise ClaimError("local_claim_denied_before_rpc") from None
            try:
                reply = self._claim(
                    {
                        "runner_id": self.runner_id,
                        "origin": self.origin,
                        "concurrency_budget": True,
                        "duration_seconds": self.allocated_seconds,
                        "target_binding": binding,
                    }
                )
            except Exception:
                try:
                    self.store.hold(record.run_id, owner, "claim_unknown")
                except Exception:
                    pass
                raise ClaimError("claim_outcome_unknown") from None
            try:
                require(
                    encoded(reply["config"]["test_case"]) == encoded(self.case),
                    "claimed_case_changed",
                )
                wire = reply["managed_authorization"]
                payload = verify(wire["contract"], self.anchors, "contract")
                permission = approved(wire["approval"], self.anchors)["context"]
                context = ValidationContext(
                    self.runner_id,
                    self.engagement_id,
                    self.job_id,
                    payload["attempt_id"],
                    payload["fence"],
                    "map",
                    utc,
                    permission["authority_revision"],
                    plan["tool_sha256"],
                    permission["authority_sha256"],
                )
                gate = ManagedGate(
                    reply,
                    self.anchors,
                    AuthorizationLedger(self.journal, clock=self.clock, monotonic=self.monotonic),
                    context,
                    self.case,
                    self.execution,
                    map_origin=self.origin,
                    principal_sha256=self.principal_sha256,
                    claim_started=mono,
                    allocated_seconds=self.allocated_seconds,
                    current=self._current,
                    local_stop=lambda: self.journal.stop_requested(record.run_id),
                    claim_anchor_utc=utc,
                    grant_snapshot=dict(policy.expected or {}),
                    grant_expiry=policy.expires_at,
                    verified_lease=self._verified_lease,
                    verified_runtime_lease=self._verified_runtime_lease,
                )
                handlers.check_gate_case(self.case, self.engagement_id)
                gate.refresh()  # Full signed/owned/current validation before durable binding; consumes nothing.
                self.store.bind(record.run_id, owner, gate)
            except Exception:
                try:
                    self.store.hold(record.run_id, owner, "reply_or_binding_unknown")
                except Exception:
                    pass
                raise ClaimError("claimed_handoff_held") from None
            assert self._artifact_limit is not None
            return ManagedRun(
                gate, self.store, record.run_id, owner, self._artifact_limit, self._consume
            )
