"""Single-use local authority binding; never a Map enrollment or admission."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from .codec import digest, encoded, require
from .contracts import timestamp
from .worker_admission import _uuid


@dataclass(frozen=True)
class LocalAdmission:
    """Built only after shared signature/plan validation, without signing material."""

    runtime_id: str
    runtime_sha256: str
    runner_id: str
    expires_at: datetime
    origin: str = "standalone"
    max_attempts: int = 1
    mode: None = None
    idle_timeout_seconds: None = None

    @classmethod
    def verified(
        cls, payload: dict, permission: dict, plan: dict, *, now: datetime
    ) -> LocalAdmission:
        require(now.tzinfo is not None and payload["origin"] == "standalone", "local_origin")
        require(permission["control"] == "local_offline", "local_control_required")
        runner_id = _uuid(payload["runner_id"])
        for key in ("contract_id", "attempt_id"):
            _uuid(payload[key])
        ending = min(
            timestamp(payload["expires_at"]),
            *(timestamp(permission[key]) for key in ("expires_at", "testing_end")),
            *(timestamp(grant["expires_at"]) for grant in permission["credential_grants"]),
            now
            + timedelta(
                seconds=min(
                    permission["max_duration_seconds"], plan["execution"]["timeout_seconds"]
                )
            ),
        )
        require(now < ending, "local_authority_expired")
        runtime_id = str(uuid.uuid4())
        binding = {
            "schema": "vardr.local-worker-admission/1",
            "runtime_id": runtime_id,
            "runner_id": runner_id,
            "contract_sha256": digest(encoded(payload)),
            "plan_sha256": digest(encoded(plan)),
        }
        # The existing owner reserves 150 seconds for final evidence/closure;
        # subtracting that same runway leaves exactly the authorized work ceiling.
        from vardrrunner.worker_lifecycle import REPORT_RUNWAY_SECONDS

        return cls(
            runtime_id,
            digest(encoded(binding)),
            runner_id,
            ending + timedelta(seconds=REPORT_RUNWAY_SECONDS),
        )
