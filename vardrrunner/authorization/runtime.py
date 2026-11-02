"""Explicit standalone reference execution; never called by CLI queue/MCP paths."""

from __future__ import annotations

import os
import shutil
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from vardrrunner import configs, handlers, resources, runner

from .codec import TrustAnchor, digest, require
from .contracts import ValidationContext, approved, timestamp
from .ledger import AuthorizationLedger


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
) -> Path:
    """Validate/reserve, reuse local secret approvals and execute a guarded Gate.

    This standalone prototype supplies no Mapless workspace or managed control.
    Operator invocation and a signed approval are both required by the caller.
    """
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
    deadline = min(timestamp(permission["expires_at"]), timestamp(permission["testing_end"]))
    remaining = int((deadline - current.now).total_seconds())
    timeout = min(permission["max_duration_seconds"], remaining)
    require(timeout > 0, "execution_deadline")
    # Existing local grant checks run before reservation, then again at resolution.
    handlers.check_gate_case(case, current.engagement_id)
    claimed = ledger.consume(envelope, approval, plan, case, execution, anchors, current)
    cfg = configs.VardrGateConfig.from_dict({"test_case": case, "execution": plan["execution"]})
    cfg = replace(cfg, engagement_id=current.engagement_id)
    output = handlers.VardrGateHandler().execute(
        [case["request"]["url"]], run_dir, cfg, request_guard=plan, total_timeout=timeout
    )
    ledger.finish(claimed)
    require(output is not None, "missing_artifact")
    assert output is not None
    resources.enforce_artifact(output, permission["max_artifact_bytes"])
    return output
