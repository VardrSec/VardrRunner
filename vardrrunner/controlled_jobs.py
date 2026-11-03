"""Owned control facade for explicit jobs run --controlled (no polling worker)."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Any

from vardrrunner import api, execution_control, identity, launch_guard, target_budget


class OwnedClient:
    def __init__(
        self,
        client: api.VardrMapClient,
        *,
        concurrency_budget: bool = False,
        duration_seconds: int | None = None,
    ):
        if duration_seconds is not None and (
            type(duration_seconds) is not int or not 1 <= duration_seconds <= 86400
        ):
            raise ValueError("finite duration allocation required")
        self.client = client
        self.duration_seconds = duration_seconds
        self.concurrency_budget = concurrency_budget
        self.base = client.base
        self.binding: dict = {}
        self.payload: dict = {}
        self.started = 0.0
        self._claim_attempted = False
        self._claim_lock = threading.Lock()
        self._monitor_attempted = False
        self.control: execution_control.Control | None = None
        self.target_binding: dict | None = None

    def __getattr__(self, name):
        return getattr(self.client, name)

    def claim_job(self, job_id: str):
        with self._claim_lock:
            if self._claim_attempted:
                raise ValueError("owned execution claim is single-use; no legacy fallback")
            self._claim_attempted = True
        runner_id = identity.load_or_create().runner_id
        self.started = time.monotonic()
        options: dict[str, Any] = {}
        if self.concurrency_budget:
            options["concurrency_budget"] = True
        if self.target_binding is not None:
            options["target_binding"] = self.target_binding
        if self.duration_seconds is not None:
            options["duration_seconds"] = self.duration_seconds
        claimed = self.client.claim_controlled(job_id, runner_id, **options)
        self.binding = {"job_id": job_id, "runner_id": runner_id, "origin": self.base}
        receipt = claimed.get("execution_control", {})
        if (
            any(receipt.get(k) != v for k, v in self.binding.items())
            or receipt.get("lease_seconds") != 10
            or not isinstance(receipt.get("token"), str)
            or len(receipt["token"]) < 32
            or (self.concurrency_budget and receipt.get("capacity_reserved") is not True)
            or (
                self.target_binding is not None
                and not target_budget.receipt_matches(
                    receipt.get("target_budget"), self.target_binding
                )
            )
            or (
                self.duration_seconds is not None
                and not _duration_matches(receipt.get("duration_budget"), self.duration_seconds)
            )
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
        with self._claim_lock:
            if not self.payload or self._monitor_attempted or self.control is not None:
                raise ValueError("owned receipt and single-use monitor required")
            self._monitor_attempted = True
        control = execution_control.Control(
            lambda: self.client.execution_control(self.binding["job_id"], self.payload),
            self.binding,
            10,
            started=self.started,
            local_stop=local_stop,
        )
        self.control = control
        until = self.started + self.duration_seconds if self.duration_seconds is not None else None
        with launch_guard.monotonic_deadline(until), execution_control.controlled(control):
            yield control


def _duration_matches(receipt, requested: int) -> bool:
    if not isinstance(receipt, dict):
        return False
    allocated, total, limit = (
        receipt.get(key)
        for key in ("allocated_seconds", "total_allocated_seconds", "limit_seconds")
    )
    if type(allocated) is not int or type(total) is not int or type(limit) is not int:
        return False
    return allocated == requested and allocated <= total <= limit <= 1000000000
