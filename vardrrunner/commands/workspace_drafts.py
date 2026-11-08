"""Local, nonrunnable Gate drafts derived from verified finite Recon evidence."""

from pathlib import Path

from vardrrunner import config
from vardrrunner.authorization.codec import require
from vardrrunner.authorization.recon_plan import RUNTIME_PROFILE, _hostname
from vardrrunner.commands import audit
from vardrrunner.journal import Journal, Phase, RunRecord, journal_path_identity
from vardrrunner.workspaces import Workspaces, validate_id


def _drafts(workspace_id: str, record: RunRecord, document: dict) -> dict:
    """Project facts, never infer identities, ownership or access decisions."""
    import re

    def sha(value: object) -> bool:
        return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None

    profile = record.command_profile
    require(record.engagement_id == workspace_id, "source_workspace_mismatch")
    require(
        record.phase == Phase.DONE
        and record.status == "done"
        and record.pid is None
        and record.job_type == "recon"
        and record.tool == "recon"
        and profile.get("standalone_profile") == RUNTIME_PROFILE
        and profile.get("origin") == "standalone"
        and profile.get("controlled") is True,
        "successful_finite_recon_required",
    )
    require(
        document.get("schema") == "vardr.recon-evidence/1"
        and document.get("profile") == RUNTIME_PROFILE
        and sha(document.get("plan_sha256"))
        and document["plan_sha256"] == profile.get("plan_sha256")
        and sha(document.get("case_hash")),
        "source_recon_binding_mismatch",
    )
    tools = document.get("tools")
    require(
        isinstance(tools, dict)
        and set(tools) == {"httpx_sha256", "dnsx_sha256"}
        and all(sha(value) for value in tools.values()),
        "source_tool_binding_unavailable",
    )
    handoff = document.get("handoff")
    rows = document.get("http")
    require(
        isinstance(handoff, dict)
        and handoff.get("requires_new_review") is True
        and handoff.get("execution_authority") is False
        and isinstance(handoff.get("candidate_urls"), list)
        and isinstance(rows, list)
        and len(rows) <= 1000,
        "source_handoff_unavailable",
    )
    assert isinstance(rows, list) and isinstance(handoff, dict)
    cases: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        require(isinstance(row, dict), "invalid_recon_observation")
        candidate = row.get("candidate")
        require(isinstance(candidate, dict), "invalid_recon_candidate")
        hostname = _hostname(candidate.get("hostname"))
        logical_url = f"https://{hostname}:443/"
        require(
            candidate
            == {"hostname": hostname, "scheme": "https", "port": 443, "path": "/", "method": "GET"}
            and row.get("logical_url") == logical_url,
            "source_logical_candidate_mismatch",
        )
        observations = row.get("observations")
        require(
            isinstance(observations, list) and len(observations) <= 1, "invalid_recon_observation"
        )
        observed = any(
            isinstance(item, dict)
            and type(item.get("status_code")) is int
            and 100 <= item["status_code"] <= 599
            for item in observations
        )
        if not observed:
            continue
        require(
            row.get("outcome") == "response_observed"
            and logical_url in handoff["candidate_urls"]
            and logical_url not in seen,
            "source_observation_handoff_mismatch",
        )
        seen.add(logical_url)
        cases.append(
            {
                "name": f"Review GET {logical_url}",
                "description": "Observed HTTPS response only; identity, ownership and access policy require operator review.",
                "spec": {
                    "id": f"recon-draft-{len(cases) + 1}",
                    "request": {"method": "GET", "url": logical_url},
                    "identities": [],
                    "expected_access": [],
                    "mutating": False,
                },
            }
        )
    require(bool(cases), "observed_http_candidate_required")
    return {
        "schema": "vardr.gate-drafts/1",
        "workspace_id": workspace_id,
        "requires_review": True,
        "execution_authority": False,
        "missing_context": [
            "identities",
            "expected_access",
            "ownership_or_tenant_boundary",
            "reviewed_authorization",
        ],
        "source": {
            "run_id": record.run_id,
            "artifact_sha256": record.artifact_sha256,
            "plan_sha256": document["plan_sha256"],
            "case_hash": document["case_hash"],
            "tools": tools,
            "started_at": record.started_at,
            "completed_at": record.completed_at,
        },
        "cases": cases,
    }


def draft_gate(workspace_id: str, run_id: str, output: Path) -> None:
    """Use the existing integrity reader and protected portable-export publisher."""

    def project(record: RunRecord, document: dict) -> dict:
        validate_id(workspace_id)
        path = config.journal_file()
        journal = Journal.open_existing(path, expected_identity=journal_path_identity(path))
        require(Workspaces(journal).get(workspace_id) is not None, "unknown_workspace")
        return _drafts(workspace_id, record, document)

    audit.export_run(run_id, output, artifact_projector=project)
