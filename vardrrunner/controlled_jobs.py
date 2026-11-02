"""Owned control facade for explicit jobs run --controlled (no polling worker)."""

from __future__ import annotations

import time
from contextlib import contextmanager

from vardrrunner import api, execution_control, identity


class OwnedClient:
    def __init__(self, client: api.VardrMapClient):
        self.client = client
        self.base = client.base
        self.binding: dict = {}
        self.payload: dict = {}
        self.started = 0.0
        self.control: execution_control.Control | None = None

    def __getattr__(self, name):
        return getattr(self.client, name)

    def claim_job(self, job_id: str):
        runner_id = identity.load_or_create().runner_id
        self.started = time.monotonic()
        claimed = self.client.claim_controlled(job_id, runner_id)
        self.binding = {"job_id": job_id, "runner_id": runner_id, "origin": self.base}
        receipt = claimed.get("execution_control", {})
        if (
            any(receipt.get(k) != v for k, v in self.binding.items())
            or receipt.get("lease_seconds") != 10
            or not isinstance(receipt.get("token"), str)
            or len(receipt["token"]) < 32
        ):
            raise ValueError("matching execution control capability required; no legacy fallback")
        self.payload = {"runner_id": runner_id, "origin": self.base, "token": receipt["token"]}
        return claimed

    def complete_job(self, job_id: str, status: str, error: str = ""):
        if not self.payload:
            return self.client.complete_job(job_id, status, error=error)
        if job_id != self.binding["job_id"]:
            raise ValueError("cross-job completion refused")
        if status == "done" and self.control is not None:
            reason = self.control.stop_reason()
            if reason:
                raise execution_control.ExecutionStopped(reason, True)
        outcome = "completed" if status == "done" else "failed"
        return self.finalize(outcome)

    def finalize(self, outcome: str):
        return self.client.execution_control(
            self.binding["job_id"], {**self.payload, "outcome": outcome}, finish=True
        )

    @contextmanager
    def monitor(self, local_stop):
        control = execution_control.Control(
            lambda: self.client.execution_control(self.binding["job_id"], self.payload),
            self.binding,
            10,
            started=self.started,
            local_stop=local_stop,
        )
        self.control = control
        with execution_control.controlled(control):
            yield control
