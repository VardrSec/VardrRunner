"""Unregistered managed Gate composition; no HTTP, CLI, queue or enrollment.

A trusted adapter supplies a verified transport, immutable claimed data and local
identity. Existing shared validation, journal, grants and native control own policy.
"""

from __future__ import annotations

import os
import shutil
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from vardrrunner import (
    configs,
    credential_grants,
    execution_control,
    handlers,
    launch_guard,
    resources,
    runner,
    target_budget,
)
from vardrrunner.controlled_jobs import _duration_matches

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
from .contracts import ValidationContext, approved, timestamp, validate
from .ledger import AuthorizationLedger
from .plan import compile_gate_plan


class ManagedGate:
    """One claimed physical attempt; successful artifacts are LOCAL ONLY.

    This does not acknowledge Map consumption, upload or complete a managed job.
    A failed/ambiguous launch remains consumed and is never automatically retried.
    """

    def __init__(
        self,
        claim: dict,
        anchors: tuple[TrustAnchor, ...],
        ledger: AuthorizationLedger,
        context: ValidationContext,
        case: dict,
        execution: dict,
        *,
        map_origin: str,
        principal_sha256: str,
        claim_started: float,
        allocated_seconds: int,
        current: Callable[[dict], dict],
        local_stop: Callable[[], bool] = lambda: False,
        claim_anchor_utc: datetime | None = None,
        grant_snapshot: dict[str, str] | None = None,
        grant_expiry: datetime | None = None,
        verified_lease: Callable[[dict, float, float], None] | None = None,
        verified_runtime_lease: Callable[[dict, float, float], None] | None = None,
    ):
        require(context.origin == "map", "managed_origin_required")
        require(
            claim_anchor_utc is None or claim_anchor_utc.tzinfo is not None, "invalid_claim_clock"
        )
        self._entered = claim_started if claim_anchor_utc is not None else time.monotonic()
        self._anchor = claim_anchor_utc or datetime.now(timezone.utc)
        self._grant_snapshot = None if grant_snapshot is None else dict(grant_snapshot)
        require(grant_expiry is None or grant_expiry.tzinfo is not None, "invalid_grant_clock")
        self._grant_expiry = grant_expiry
        self.anchors, self.ledger, self.context = anchors, ledger, context
        self.case, self.execution = case, execution
        wire = claim["managed_authorization"]
        self.envelope, self.approval = wire["contract"], wire["approval"]
        self.payload = verify(self.envelope, anchors, "contract")
        self.permission = approved(self.approval, anchors)["context"]
        snapshot = wire["authority_snapshot"]
        require(
            snapshot["origin"] == map_origin
            and snapshot["enrollment"]["runner_id"] == context.runner_id
            and snapshot["enrollment"]["principal_sha256"] == principal_sha256
            and digest(encoded(snapshot)) == context.authority_sha256,
            "managed_snapshot_binding",
        )
        self.plan = compile_gate_plan(case, execution, tool_sha256=context.tool_sha256)
        require(encoded(self.plan) == encoded(wire["plan"]), "execution_plan_changed")
        receipt = claim["execution_control"]
        self.binding: dict = {
            "origin": map_origin,
            "job_id": context.job_id,
            "runner_id": context.runner_id,
        }
        require(all(receipt.get(k) == v for k, v in self.binding.items()), "owned_binding")
        require(
            type(receipt.get("token")) is str and 32 <= len(receipt["token"]) <= 100, "owned_token"
        )
        require(receipt.get("capacity_reserved") is True, "capacity_required")
        integer(allocated_seconds, 1, 86400)
        require(
            _duration_matches(receipt.get("duration_budget"), allocated_seconds), "duration_binding"
        )
        expected, target_plan = target_budget.prepare(
            configs.VardrGateConfig.from_dict({"test_case": case, "execution": execution})
        )
        require(encoded(target_plan) == encoded(self.plan), "execution_plan_changed")
        require(
            target_budget.receipt_matches(receipt.get("target_budget"), expected), "target_binding"
        )
        lease = integer(receipt["lease_seconds"], 1, 10)
        self.request = {
            "origin": map_origin,
            "runner_id": context.runner_id,
            "token": receipt["token"],
            **{k: self.payload[k] for k in ("contract_id", "attempt_id", "fence")},
        }
        self.binding.update({k: self.payload[k] for k in ("contract_id", "attempt_id", "fence")})
        self.binding.update(
            authority_revision=context.authority_revision, authority_sha256=context.authority_sha256
        )
        self.until = min(
            timestamp(self.payload["expires_at"]),
            *(timestamp(self.permission[k]) for k in ("expires_at", "testing_end")),
            *(timestamp(g["expires_at"]) for g in self.permission["credential_grants"]),
        )
        if grant_expiry is not None:
            self.until = min(self.until, grant_expiry)
        self.hard_end = min(
            claim_started + allocated_seconds,
            claim_started + self.permission["max_duration_seconds"],
            claim_started + self.plan["execution"]["timeout_seconds"],
            time.monotonic() + self.until.timestamp() - self.now().timestamp(),
        )
        self._lease_end = min(claim_started + lease, self.hard_end)
        self._state_lock, self._refresh_lock = threading.Lock(), threading.Lock()
        self._current, self._local_stop = current, local_stop
        self._verified_lease = verified_lease
        self._verified_runtime_lease = verified_runtime_lease
        require(
            verified_lease is None or verified_runtime_lease is None, "worker_lease_hook_conflict"
        )
        self._used = self._denied = False
        self._policy: credential_grants.Policy | None = None
        self.control: execution_control.Control | None = None

    def now(self) -> datetime:
        from datetime import timedelta

        return max(
            datetime.now(timezone.utc),
            self._anchor + timedelta(seconds=time.monotonic() - self._entered),
        )

    def lease_deadline(self) -> float:
        with self._state_lock:
            return min(self._lease_end, self.hard_end)

    def stopped(self) -> bool:
        return self._denied or self._local_stop()

    def _tool(self) -> None:
        path = Path(shutil.which(runner.program("vardrgate_api_test")) or "")
        require(
            path.is_file() and digest(path.read_bytes()) == self.context.tool_sha256, "tool_changed"
        )

    def refresh(self, *, grants: bool = True) -> dict:
        # Never hold the HTTP mutex while waiting for the grant journal writer:
        # native launch holds that writer while it revalidates managed authority.
        if grants and self._policy is not None:
            try:
                self._policy.check(
                    self.context.engagement_id,
                    handlers._case_origins(self.case),
                    handlers.credential_references(self.case),
                )
            except credential_grants.GrantError:
                self._denied = True
                raise
        with self._refresh_lock:
            require(
                not self.stopped() and time.monotonic() < self.lease_deadline(),
                "managed_lease_expired_or_stopped",
            )
            started = time.monotonic()
            try:
                reply = self._current(dict(self.request))
            except Exception:
                raise AuthorizationError("managed_control_unavailable") from None
            fields(reply, {*self.binding, "action", "lease_seconds", "lease_expires_at"})
            integer(reply["fence"], 1)
            integer(reply["authority_revision"])
            require(
                all(reply[k] == v for k, v in self.binding.items())
                and reply["action"] == "continue",
                "managed_current_binding",
            )
            lease = integer(reply["lease_seconds"], 1, 10)
            end = min(
                started + lease,
                time.monotonic()
                + (timestamp(reply["lease_expires_at"]) - self.now()).total_seconds(),
                self.hard_end,
            )
            require(
                time.monotonic() < min(end, self.lease_deadline()),
                "managed_lease_expired_or_stopped",
            )
            checked = replace(self.context, now=self.now(), managed_status_verified=True)
            validate(
                self.envelope,
                self.approval,
                self.plan,
                self.case,
                self.execution,
                self.anchors,
                checked,
            )
            if self._verified_lease is not None or self._verified_runtime_lease is not None:
                try:
                    if self._verified_runtime_lease is not None:
                        from .results import BINDING

                        worker_binding = {
                            key: self.binding[key] for key in BINDING - {"contract_sha256"}
                        }
                        worker_binding["contract_sha256"] = digest(encoded(self.envelope))
                        self._verified_runtime_lease(worker_binding, end, self.hard_end)
                    elif self._verified_lease is not None:
                        self._verified_lease(dict(self.binding), end, self.hard_end)
                except Exception:
                    self._denied = True
                    raise AuthorizationError("worker_owner_control_unavailable") from None
                require(
                    time.monotonic() < min(end, self.lease_deadline()),
                    "managed_lease_expired_or_stopped",
                )
            with self._state_lock:
                self._lease_end = end
            # Only shortens the verified interval. Control also receives end as
            # an absolute cap, including after any subsequent rejected refresh.
            return {
                **self.binding,
                "action": "continue",
                "lease_seconds": min(lease, end - time.monotonic()),
            }

    def _launch_check(self) -> None:
        self._tool()
        self.refresh(grants=False)  # The enclosing grant transaction rechecks locally.
        if self.control is not None:
            execution_control.require_permission(self.control)

    def execute(self, run_dir: Path, *, consume: Callable[[dict], None] | None = None) -> Path:
        with self._state_lock:
            require(not self._used, "single_managed_attempt")
            self._used = True
        require(execution_control.available(), "controlled_process_tree_unsupported")
        require(
            run_dir.is_dir() and not (run_dir / "vardrgate_result.json").exists(),
            "exclusive_output_required",
        )
        with credential_grants.required(self.binding["origin"]) as policy:
            if self._grant_snapshot is not None:
                policy.expected = dict(self._grant_snapshot)
                policy.expires_at = self._grant_expiry
            self._policy = policy
            handlers.check_gate_case(self.case, self.context.engagement_id)
            expected = set((policy.expected or {}).values())
            rows = (
                [row for row in policy.store.entries() if row["id"] in expected] if expected else []
            )
            require({row["id"] for row in rows} == expected, "grant_binding_changed")
            if rows:
                self.until = min(
                    self.until, *(credential_grants.timestamp(r["expires_at"]) for r in rows)
                )
                self.hard_end = min(
                    self.hard_end,
                    time.monotonic() + self.until.timestamp() - self.now().timestamp(),
                )
            self._tool()
            require(
                self.plan["execution"]["allow_private_targets"]
                == (os.environ.get("VARDRRUNNER_ALLOW_PRIVATE_TARGETS") == "1"),
                "local_private_option_mismatch",
            )
            self.refresh()
            checked = replace(self.context, now=self.now(), managed_status_verified=True)
            self.ledger.set_state(
                self.payload["issuer"]["id"],
                checked.engagement_id,
                checked.authority_revision,
                False,
                checked.authority_sha256,
            )
            self.ledger.consume(
                self.envelope,
                self.approval,
                self.plan,
                self.case,
                self.execution,
                self.anchors,
                checked,
            )
            if consume is not None:
                consume({**self.request, "contract_sha256": digest(encoded(self.envelope))})
                # The acknowledgement is not a renewal. RPC/journal delays count
                # against the last verified lease; recheck before native launch.
                self.refresh()
            entered = time.monotonic()
            self.control = execution_control.Control(
                self.refresh,
                self.binding,
                self.lease_deadline() - entered,
                started=entered,
                local_stop=self.stopped,
                lease_deadline=self.lease_deadline,
            )
            cfg = configs.VardrGateConfig.from_dict(
                {"test_case": self.case, "execution": self.plan["execution"]}
            )
            cfg = replace(cfg, engagement_id=checked.engagement_id)
            with (
                launch_guard.deadline(self.until.timestamp()),
                launch_guard.monotonic_deadline(self.hard_end),
                launch_guard.revalidation(self._launch_check),
                execution_control.controlled(self.control),
            ):
                output = handlers.VardrGateHandler().execute(
                    [self.case["request"]["url"]],
                    run_dir,
                    cfg,
                    request_guard=self.plan,
                    total_timeout=self.permission["max_duration_seconds"],
                    execution_deadline=self.until.timestamp(),
                )
            require(output is not None, "missing_artifact")
            assert output is not None
            resources.enforce_artifact(output, self.permission["max_artifact_bytes"])
            # Local reservation and Map capacity remain retained. A local Gate
            # artifact is not a managed upload/completion or distributed ACK.
            return output
