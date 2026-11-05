"""Reference approval and execution validation; no network or target execution."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

from .codec import TrustAnchor, digest, encoded, fields, identifier, integer, require, sign, verify
from .plan import PROFILE, compile_gate_plan, origin

_CONTEXT = {
    "runner_id",
    "engagement_id",
    "job_id",
    "authority_revision",
    "authority_sha256",
    "plan_sha256",
    "mode",
    "scope",
    "exceptions",
    "not_before",
    "expires_at",
    "testing_start",
    "testing_end",
    "max_executions",
    "max_duration_seconds",
    "max_http_dispatches",
    "max_artifact_bytes",
    "credential_grants",
    "control",
}


def timestamp(value: str) -> datetime:
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is not None,
        "invalid_time",
    )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        from .codec import AuthorizationError

        raise AuthorizationError("invalid_time") from exc


def hash_field(value: str) -> None:
    require(
        isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None,
        "invalid_digest",
    )


def validate_context(context: dict) -> None:
    fields(context, _CONTEXT)
    for name in ("runner_id", "engagement_id", "job_id"):
        identifier(context[name])
    for name in ("authority_sha256", "plan_sha256"):
        hash_field(context[name])
    integer(context["authority_revision"])
    for name, maximum in (
        ("max_executions", 1000),
        ("max_duration_seconds", 86400),
        ("max_http_dispatches", 100000),
        ("max_artifact_bytes", 1024**3),
    ):
        integer(context[name], 1, maximum)
    require(
        isinstance(context["mode"], str)
        and context["mode"] in {"strict", "advisory"}
        and isinstance(context["control"], str)
        and context["control"] in {"local_offline", "managed_online"},
        "unsupported_mode",
    )
    for name in ("not_before", "expires_at", "testing_start", "testing_end"):
        timestamp(context[name])
    require(
        timestamp(context["not_before"]) < timestamp(context["expires_at"])
        and timestamp(context["testing_start"]) < timestamp(context["testing_end"]),
        "invalid_window",
    )
    for name in ("scope", "exceptions"):
        require(isinstance(context[name], list) and len(context[name]) <= 1000, "invalid_scope")
        for rule in context[name]:
            fields(rule, {"origin", "path", "method", "excluded", "reason"})
            require(origin(rule["origin"]) == rule["origin"], "noncanonical_origin")
            require(
                isinstance(rule["path"], str)
                and rule["path"].startswith("/")
                and "?" not in rule["path"]
                and "%" not in rule["path"]
                and "\\" not in rule["path"],
                "invalid_scope_path",
            )
            require(
                isinstance(rule["method"], str)
                and rule["method"] in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
                and type(rule["excluded"]) is bool
                and isinstance(rule["reason"], str)
                and len(rule["reason"]) <= 500,
                "invalid_scope_rule",
            )
            if name == "exceptions":
                require(bool(rule["reason"]) and rule["excluded"] is False, "invalid_exception")
    require(context["mode"] != "strict" or not context["exceptions"], "strict_exception")
    grants = context["credential_grants"]
    require(isinstance(grants, list) and len(grants) <= 100, "invalid_grants")
    for grant in grants:
        fields(grant, {"identity_id", "source", "name", "revision", "expires_at"})
        identifier(grant["identity_id"])
        require(
            isinstance(grant["source"], str)
            and grant["source"] in {"value_env", "value_keychain"}
            and isinstance(grant["name"], str)
            and 0 < len(grant["name"]) <= 200,
            "invalid_grants",
        )
        integer(grant["revision"], 1)
        timestamp(grant["expires_at"])
    require(
        len({(g["identity_id"], g["source"], g["name"]) for g in grants}) == len(grants),
        "duplicate_grant",
    )


def approve(
    context: dict,
    issuer: dict,
    origin_kind: str,
    approver_id: str,
    approval_id: str,
    approved_at: str,
    private_key: bytes,
) -> dict:
    """Operator-only primitive; access to the approval key is the trust boundary."""
    validate_context(context)
    fields(issuer, {"id", "key_id"})
    identifier(issuer["id"])
    identifier(issuer["key_id"])
    require(origin_kind in {"standalone", "map"}, "invalid_origin")
    identifier(approver_id)
    identifier(approval_id)
    timestamp(approved_at)
    return sign(
        {
            "schema": "vardr.execution-approval/1",
            "issuer": issuer,
            "origin": origin_kind,
            "approval_id": approval_id,
            "approver_id": approver_id,
            "approved_at": approved_at,
            "context": context,
        },
        private_key,
        "approval",
    )


def approved(envelope: dict, anchors: tuple[TrustAnchor, ...]) -> dict:
    payload = verify(envelope, anchors, "approval")
    fields(
        payload,
        {"schema", "issuer", "origin", "approval_id", "approver_id", "approved_at", "context"},
    )
    require(payload["schema"] == "vardr.execution-approval/1", "unsupported_schema")
    identifier(payload["approval_id"])
    identifier(payload["approver_id"])
    timestamp(payload["approved_at"])
    validate_context(payload["context"])
    require(
        (payload["origin"] == "standalone") == (payload["context"]["control"] == "local_offline"),
        "origin_control_mismatch",
    )
    return payload


@dataclass(frozen=True)
class ValidationContext:
    runner_id: str
    engagement_id: str
    job_id: str
    attempt_id: str
    fence: int
    origin: str
    now: datetime
    authority_revision: int
    tool_sha256: str
    authority_sha256: str
    revoked: bool = False
    stop_work: bool = False
    revoked_grants: frozenset[tuple[str, str, str]] = frozenset()
    capabilities: frozenset[str] = frozenset({PROFILE})
    # Production managed status/leases are deliberately not implemented in NM-1.
    managed_status_verified: bool = False
    # Explicit secondary artifact for the dormant finite recon projection only.
    dnsx_sha256: str | None = None


def _matches(rule: dict, request: dict) -> bool:
    return (
        rule["origin"] == origin(request["url"])
        and rule["method"] == request["method"]
        and rule["path"] == (urlsplit(request["url"]).path or "/")
    )


def validate(
    envelope: dict,
    approval: dict,
    plan: dict,
    case: dict,
    execution: dict,
    anchors: tuple[TrustAnchor, ...],
    context: ValidationContext,
) -> dict:
    payload = verify(envelope, anchors, "contract")
    fields(
        payload,
        {
            "schema",
            "issuer",
            "origin",
            "contract_id",
            "approval_sha256",
            "approval_id",
            "execution_index",
            "plan_sha256",
            "runner_id",
            "engagement_id",
            "job_id",
            "attempt_id",
            "fence",
            "issued_at",
            "expires_at",
            "authority_revision",
        },
    )
    require(payload["schema"] == "vardr.authorization/1", "unsupported_schema")
    for name in (
        "contract_id",
        "approval_id",
        "runner_id",
        "engagement_id",
        "job_id",
        "attempt_id",
    ):
        identifier(payload[name])
    for name in ("approval_sha256", "plan_sha256"):
        hash_field(payload[name])
    integer(payload["fence"], 1)
    integer(payload["authority_revision"])
    receipt = approved(approval, anchors)
    permission = receipt["context"]
    require(
        payload["issuer"]["id"] == receipt["issuer"]["id"]
        and payload["origin"] == receipt["origin"],
        "approval_issuer_mismatch",
    )
    require(
        payload["approval_id"] == receipt["approval_id"]
        and payload["approval_sha256"] == digest(encoded(approval)),
        "approval_mismatch",
    )
    integer(payload["execution_index"], 1, permission["max_executions"])
    for name in ("runner_id", "engagement_id", "job_id"):
        require(payload[name] == getattr(context, name) == permission[name], "binding_mismatch")
    for name in ("attempt_id", "fence", "origin", "authority_revision"):
        require(payload[name] == getattr(context, name), "binding_mismatch")
    require(payload["authority_revision"] == permission["authority_revision"], "authority_changed")
    require(
        context.authority_sha256 == permission["authority_sha256"], "authority_snapshot_changed"
    )
    require(not context.revoked and not context.stop_work, "revoked_or_stopped")
    require(context.now.tzinfo is not None, "invalid_clock")
    now = context.now.astimezone(timezone.utc)
    require(
        timestamp(receipt["approved_at"]) <= timestamp(payload["issued_at"]) <= now,
        "invalid_issuance_time",
    )
    require(
        timestamp(permission["not_before"])
        <= now
        < timestamp(payload["expires_at"])
        <= timestamp(permission["expires_at"]),
        "expired_or_not_yet_valid",
    )
    require(
        timestamp(permission["testing_start"]) <= now < timestamp(permission["testing_end"]),
        "outside_testing_window",
    )
    require(
        payload["plan_sha256"] == permission["plan_sha256"] == digest(encoded(plan)),
        "plan_digest_mismatch",
    )
    from .recon_plan import PROFILE as RECON_PROFILE
    from .recon_plan import compile_recon_plan

    recon = isinstance(plan, dict) and plan.get("profile") == RECON_PROFILE
    if recon:
        require(RECON_PROFILE in context.capabilities, "unsupported_enforcement")
        require(
            permission["mode"] == "strict"
            and permission["control"] == "local_offline"
            and context.origin == "standalone"
            and not permission["credential_grants"],
            "unsupported_recon_authority",
        )
        expected = compile_recon_plan(
            case, execution, tool_sha256=context.tool_sha256, dnsx_sha256=context.dnsx_sha256
        )
        require(
            now
            < timestamp(expected["execution"]["deadline"])
            <= min(timestamp(payload["expires_at"]), timestamp(permission["testing_end"])),
            "recon_deadline_denied",
        )
        require(
            expected["execution"]["max_artifact_bytes"] <= permission["max_artifact_bytes"],
            "artifact_limit",
        )
    else:
        expected = compile_gate_plan(case, execution, tool_sha256=context.tool_sha256)
    require(encoded(plan) == encoded(expected), "execution_plan_changed")
    require(plan["profile"] in context.capabilities, "unsupported_enforcement")
    if permission["control"] == "managed_online":
        require(context.managed_status_verified, "managed_control_unsupported")
    require(plan["max_http_dispatches"] <= permission["max_http_dispatches"], "dispatch_limit")
    require(
        plan["execution"]["timeout_seconds"] <= permission["max_duration_seconds"], "duration_limit"
    )
    for entry in plan["dispatches"]:
        request = entry["request"]
        path = urlsplit(request["url"]).path or "/"
        require(
            path == unquote(path)
            and "\\" not in path
            and not any(s in {".", ".."} for s in path.split("/")),
            "ambiguous_path",
        )
        excluded = any(r["excluded"] and _matches(r, request) for r in permission["scope"])
        included = any(not r["excluded"] and _matches(r, request) for r in permission["scope"])
        exception = permission["mode"] == "advisory" and any(
            _matches(r, request) for r in permission["exceptions"]
        )
        require((included and not excluded) or exception, "scope_denied")
        host = urlsplit(request["url"]).hostname or ""
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None:
            require(
                not (address.is_unspecified or address.is_link_local or address.is_multicast),
                "hard_network_denied",
            )
            require(
                address.is_global or plan["execution"]["allow_private_targets"],
                "private_target_denied",
            )
    grants = {
        (g["identity_id"], g["source"], g["name"]): g for g in permission["credential_grants"]
    }
    for reference in plan["credential_references"]:
        key = (reference["identity_id"], reference["source"], reference["name"])
        require(key in grants and key not in context.revoked_grants, "credential_not_approved")
        require(now < timestamp(grants[key]["expires_at"]), "credential_expired")
    return payload
