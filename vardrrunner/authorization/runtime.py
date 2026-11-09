"""Explicit standalone Gate execution; never called by queue or MCP paths."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from vardrrunner import configs, credential_grants, handlers, resources, runner

from .codec import TrustAnchor, digest, require
from .contracts import ValidationContext, approved, timestamp
from .ledger import AuthorizationLedger
from .plan import PROFILE


def execute_gate(
    ledger: AuthorizationLedger,
    envelope: dict,
    approval: dict,
    plan: dict,
    case: dict,
    execution: dict,
    anchors: tuple[TrustAnchor, ...],
    context: ValidationContext,
    run_dir: Path,
    *,
    expiring_grants: bool = False,
    on_reserved: Callable[[], None] | None = None,
    before_finish: Callable[[Path], None] | None = None,
) -> Path:
    """Validate/reserve, reuse local secret approvals and execute a guarded Gate.

    This standalone prototype supplies no Mapless workspace or managed control.
    Operator invocation and a signed approval are both required by the caller.
    """
    require(isinstance(plan, dict) and plan.get("profile") == PROFILE, "unsupported_enforcement")
    if expiring_grants:
        with credential_grants.required("standalone"):
            return execute_gate(
                ledger,
                envelope,
                approval,
                plan,
                case,
                execution,
                anchors,
                context,
                run_dir,
                on_reserved=on_reserved,
                before_finish=before_finish,
            )
    require(context.origin == "standalone", "managed_control_unsupported")
    require(
        run_dir.is_dir() and not (run_dir / "vardrgate_result.json").exists(),
        "exclusive_output_required",
    )
    binary = runner.program("vardrgate_api_test")
    path = Path(shutil.which(binary) or binary)
    actual_digest = digest(path.read_bytes())
    require(actual_digest == context.tool_sha256, "tool_changed")
    local_private = os.environ.get("VARDRRUNNER_ALLOW_PRIVATE_TARGETS") == "1"
    require(
        plan["execution"]["allow_private_targets"] == local_private, "local_private_option_mismatch"
    )
    current = replace(context, now=datetime.now(timezone.utc), managed_status_verified=False)
    permission = approved(approval, anchors)["context"]
    # Existing local grant checks run before reservation, then again at resolution.
    handlers.check_gate_case(case, current.engagement_id)
    current = replace(current, now=datetime.now(timezone.utc))
    claimed = ledger.consume(envelope, approval, plan, case, execution, anchors, current)
    # Trusted local journal bridge only. Failure spends permission without launch;
    # no cross-table atomicity or automatic recovery/replay is claimed.
    if on_reserved is not None:
        on_reserved()
    deadline = min(
        timestamp(claimed["expires_at"]),
        timestamp(permission["expires_at"]),
        timestamp(permission["testing_end"]),
    )
    remaining = int((deadline - datetime.now(timezone.utc)).total_seconds())
    timeout = min(permission["max_duration_seconds"], remaining)
    require(timeout > 0, "execution_deadline")
    cfg = configs.VardrGateConfig.from_dict({"test_case": case, "execution": plan["execution"]})
    cfg = replace(cfg, engagement_id=current.engagement_id)
    output = handlers.VardrGateHandler().execute(
        [case["request"]["url"]],
        run_dir,
        cfg,
        request_guard=plan,
        total_timeout=timeout,
        execution_deadline=deadline.timestamp(),
        tool_provenance={
            "sha256": actual_digest,
            "version": "unknown",
            "hash_basis": "verified_runtime_binary",
        },
    )
    if before_finish is not None:
        require(output is not None, "missing_artifact")
        assert output is not None
        resources.enforce_artifact(output, permission["max_artifact_bytes"])
        before_finish(output)
    ledger.finish(claimed)
    require(output is not None, "missing_artifact")
    assert output is not None
    resources.enforce_artifact(output, permission["max_artifact_bytes"])
    return output
