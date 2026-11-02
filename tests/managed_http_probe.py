"""Synthetic integration probe only: no CLI, queue, process or target dispatch.

The opt-in Map ASGI harness supplies an HTTP transport and public fixture trust.
This is not a production managed adapter or a distributed consumption protocol.
"""

from dataclasses import replace
from datetime import timedelta

from vardrrunner import launch_guard
from vardrrunner.authorization.codec import digest, encoded, fields, integer, require, verify
from vardrrunner.authorization.contracts import ValidationContext, approved, timestamp, validate
from vardrrunner.authorization.plan import compile_gate_plan


class Probe:
    def __init__(
        self,
        http,
        anchors,
        ledger,
        *,
        origin,
        runner_id,
        job_id,
        engagement_id,
        principal_sha256,
        case,
        execution,
        tool_sha256,
        clock,
        monotonic,
    ):
        self.http, self.anchors, self.ledger = http, anchors, ledger
        self.origin, self.runner_id, self.job_id = origin, runner_id, job_id
        self.engagement_id, self.principal_sha256 = engagement_id, principal_sha256
        self.case, self.execution, self.tool_sha256 = case, execution, tool_sha256
        self.clock, self.monotonic = clock, monotonic
        self.anchor, self.entered = clock(), monotonic()
        self.plan = compile_gate_plan(case, execution, tool_sha256=tool_sha256)
        self.claim_attempted = self.launch_attempted = self.consumed = False

    def now(self):
        elapsed = self.monotonic() - self.entered
        require(elapsed >= 0, "clock_rollback")
        return max(self.clock(), self.anchor + timedelta(seconds=elapsed))

    def post(self, path, body):
        try:
            response = self.http.post(path, json=body)
        except Exception:
            require(False, "synthetic_transport_failed")
        require(response.status_code == 200, "synthetic_http_refused")
        try:
            value = response.json()
        except Exception:
            require(False, "synthetic_response_failed")
        require(isinstance(value, dict), "synthetic_response_failed")
        return value

    def claim(self, body):
        require(not self.claim_attempted, "single_claim_only")
        self.claim_attempted = True  # A dropped response never permits a retry.
        self.claim_started = self.monotonic()
        claimed = self.post("/fixture/claim", body)
        wire = fields(
            claimed["managed_authorization"],
            {
                "approval",
                "contract",
                "plan",
                "authority_snapshot",
            },
        )
        self.approval, self.envelope = wire["approval"], wire["contract"]
        self.payload = verify(self.envelope, self.anchors, "contract")
        self.permission = approved(self.approval, self.anchors)["context"]
        snapshot = wire["authority_snapshot"]
        require(snapshot["origin"] == self.origin, "origin_mismatch")
        require(
            snapshot["enrollment"]["principal_sha256"] == self.principal_sha256,
            "principal_mismatch",
        )
        require(snapshot["enrollment"]["runner_id"] == self.runner_id, "runner_mismatch")
        require(
            digest(encoded(snapshot)) == self.permission["authority_sha256"],
            "authority_snapshot_changed",
        )
        require(encoded(wire["plan"]) == encoded(self.plan), "execution_plan_changed")
        receipt = claimed["execution_control"]
        self.binding = {
            "job_id": self.job_id,
            "runner_id": self.runner_id,
            "origin": self.origin,
        }
        require(all(receipt.get(k) == v for k, v in self.binding.items()), "control_binding")
        require(
            type(receipt.get("token")) is str and 32 <= len(receipt["token"]) <= 100,
            "control_token",
        )
        require(receipt.get("capacity_reserved") is True, "capacity_required")
        integer(receipt["lease_seconds"], 1, 10)
        allocated = integer(receipt["duration_budget"]["allocated_seconds"], 1, 86400)
        require(allocated == body["duration_seconds"], "duration_binding")
        require(receipt["target_budget"]["binding"] == body["target_binding"], "target_binding")
        self.request = {
            "runner_id": self.runner_id,
            "origin": self.origin,
            "token": receipt["token"],
            **{k: self.payload[k] for k in ("contract_id", "attempt_id", "fence")},
        }
        self.lease_end = self.claim_started + receipt["lease_seconds"]
        self.context = ValidationContext(
            self.runner_id,
            self.engagement_id,
            self.job_id,
            self.payload["attempt_id"],
            self.payload["fence"],
            "map",
            self.now(),
            self.permission["authority_revision"],
            self.tool_sha256,
            self.permission["authority_sha256"],
        )
        self.absolute_end = min(
            timestamp(self.payload["expires_at"]),
            *(timestamp(self.permission[k]) for k in ("expires_at", "testing_end")),
            *(timestamp(g["expires_at"]) for g in self.permission["credential_grants"]),
        ).timestamp()
        self.hard_end = min(
            self.claim_started + allocated,
            self.claim_started + self.permission["max_duration_seconds"],
            self.claim_started + self.plan["execution"]["timeout_seconds"],
            self.monotonic() + self.absolute_end - self.now().timestamp(),
        )
        return claimed

    def revalidate(self):
        require(self.monotonic() < min(self.lease_end, self.hard_end), "permission_expired")
        started = self.monotonic()  # Response latency consumes the returned lease.
        reply = self.post("/fixture/current", self.request)
        fields(
            reply,
            {
                *self.binding,
                "contract_id",
                "attempt_id",
                "fence",
                "authority_revision",
                "authority_sha256",
                "action",
                "lease_seconds",
                "lease_expires_at",
            },
        )
        integer(reply["fence"], 1)
        integer(reply["authority_revision"])
        expected = {
            **self.binding,
            **{k: self.payload[k] for k in ("contract_id", "attempt_id", "fence")},
            "authority_revision": self.context.authority_revision,
            "authority_sha256": self.context.authority_sha256,
            "action": "continue",
        }
        require(all(reply[k] == v for k, v in expected.items()), "current_binding")
        lease = integer(reply["lease_seconds"], 1, 10)
        # A captured response retains its original server expiry. Request-start
        # anchoring alone would turn old JSON into a new ten-second lease.
        remaining = (timestamp(reply["lease_expires_at"]) - self.now()).total_seconds()
        renewed_end = min(started + lease, self.monotonic() + remaining)
        require(
            self.monotonic() < min(self.lease_end, self.hard_end, renewed_end),
            "permission_expired",
        )
        self.lease_end = renewed_end
        # Only this verified, exact current-control response can establish status.
        current = replace(self.context, now=self.now(), managed_status_verified=True)
        validate(
            self.envelope,
            self.approval,
            self.plan,
            self.case,
            self.execution,
            self.anchors,
            current,
        )
        self.ledger.set_state(
            self.payload["issuer"]["id"],
            self.engagement_id,
            current.authority_revision,
            False,
            current.authority_sha256,
        )
        self.context = current
        return current

    def reserve(self):
        current = self.revalidate()
        self.ledger.consume(
            self.envelope,
            self.approval,
            self.plan,
            self.case,
            self.execution,
            self.anchors,
            current,
        )
        self.consumed = True

    def launch(self, sentinel):
        require(self.consumed and not self.launch_attempted, "single_launch_only")
        self.launch_attempted = True  # Ambiguity never releases or reopens permission.
        with (
            launch_guard.deadline(self.absolute_end),
            launch_guard.monotonic_deadline(min(self.hard_end, self.lease_end)),
            launch_guard.revalidation(self.revalidate),
            launch_guard.boundary(),
        ):
            sentinel()  # Inert: absolutely no subprocess or target dispatch here.
