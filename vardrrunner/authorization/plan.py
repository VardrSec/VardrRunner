"""Conservative fixed-request Gate profile, compiled from unresolved input."""

from __future__ import annotations

import copy
import ipaddress
from typing import Any
from urllib.parse import urlsplit

from .codec import digest, encoded, integer, require

PROFILE = "gate-fixed-http/1"
_CASE_FIELDS = {
    "require_identity_preflight",
    "id",
    "description",
    "identities",
    "request",
    "resource",
    "role_hierarchy",
    "sensitive_fields",
    "deny_status",
    "unauthorized_is_denial",
    "deny_when",
    "mutating",
    "write_verification",
    "setup",
    "cors",
    "expected_access",
}
_SECRET_NAMES = {
    "authorization",
    "cookie",
    "x-api-key",
    "password",
    "secret",
    "access_token",
    "refresh_token",
}


def origin(url: Any) -> str:
    require(
        isinstance(url, str)
        and len(url) <= 2048
        and not any(ord(c) <= 32 or c == "\\" for c in url),
        "invalid_url",
    )
    try:
        u = urlsplit(url)
        require(u.port is None or 1 <= u.port <= 65535, "invalid_url")
        port = u.port or (443 if u.scheme == "https" else 80)
        require(
            u.scheme in {"http", "https"}
            and bool(u.hostname)
            and u.username is None
            and u.password is None
            and not u.fragment,
            "invalid_url",
        )
        host = u.hostname or ""
        require(host.isascii() and not host.endswith(".") and "%" not in host, "unsupported_host")
        if ":" in host:
            host = "[" + str(ipaddress.IPv6Address(host)) + "]"
        return f"{u.scheme}://{host.lower()}:{port}"
    except ValueError as exc:
        from .codec import AuthorizationError

        raise AuthorizationError("invalid_url") from exc


def _fixed(value: Any) -> None:
    if isinstance(value, str):
        require("{{" not in value and "${" not in value, "unsupported_substitution")
    elif isinstance(value, dict):
        for key, item in value.items():
            _fixed(key)
            _fixed(item)
    elif isinstance(value, list):
        for item in value:
            _fixed(item)


def _request(raw: Any) -> dict:
    require(
        isinstance(raw, dict) and set(raw) <= {"method", "url", "headers", "query_params", "body"},
        "invalid_request",
    )
    method = raw.get("method", "GET")
    require(
        isinstance(method, str)
        and method in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"},
        "unsupported_method",
    )
    url = raw.get("url")
    origin(url)
    headers = raw.get("headers") or {}
    query = raw.get("query_params") or {}
    require(isinstance(headers, dict) and isinstance(query, dict), "invalid_request")
    normalized = {}
    for key, value in headers.items():
        require(
            isinstance(key, str) and isinstance(value, str) and key.lower() not in normalized,
            "invalid_headers",
        )
        require(
            key.lower() not in _SECRET_NAMES and key.lower() != "host",
            "literal_secret_or_authority",
        )
        normalized[key.lower()] = value
    require(
        all(
            isinstance(k, str) and isinstance(v, str) and k.lower() not in _SECRET_NAMES
            for k, v in query.items()
        ),
        "invalid_query",
    )
    return {
        "method": method,
        "url": url,
        "headers": normalized,
        "query_params": query,
        "body": raw.get("body"),
    }


def compile_gate_plan(case: dict, execution: dict | None = None, *, tool_sha256: str) -> dict:
    import re

    require(
        isinstance(tool_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", tool_sha256) is not None,
        "invalid_tool_digest",
    )
    require(isinstance(case, dict) and set(case) <= _CASE_FIELDS, "unsupported_case_fields")
    _fixed(case)
    execution = execution or {}
    require(
        isinstance(execution, dict)
        and set(execution) <= {"timeout_seconds", "max_response_bytes", "allow_private_targets"},
        "unsupported_execution",
    )
    timeout = integer(execution.get("timeout_seconds", 30), 1, 600)
    response_bytes = integer(execution.get("max_response_bytes", 5 * 1024**2), 1, 5 * 1024**2)
    private = execution.get("allow_private_targets", False)
    require(type(private) is bool, "invalid_private_option")
    identities = case.get("identities")
    require(isinstance(identities, list) and 1 <= len(identities) <= 100, "invalid_identities")
    assert isinstance(identities, list)
    ids = [i.get("id") for i in identities if isinstance(i, dict)]
    require(
        len(ids) == len(identities)
        and all(isinstance(i, str) and i for i in ids)
        and len(set(ids)) == len(ids),
        "invalid_identities",
    )
    verifier = case.get("write_verification")
    all_identities = list(identities)
    if verifier is not None:
        require(
            isinstance(verifier, dict) and isinstance(verifier.get("identity"), dict),
            "invalid_verifier",
        )
        all_identities.append(verifier["identity"])
    grants = []
    for identity in all_identities:
        cred = identity.get("credential") or {}
        require(isinstance(cred, dict) and not cred.get("value"), "literal_credential")
        require(not (cred.get("value_env") and cred.get("value_keychain")), "ambiguous_credential")
        for source in ("value_env", "value_keychain"):
            if cred.get(source):
                require(isinstance(cred[source], str), "invalid_credential_reference")
                grants.append(
                    {"identity_id": identity["id"], "source": source, "name": cred[source]}
                )
    entries: list[dict[str, Any]] = []

    def add(phase: str, actor: Any, request: Any, maximum: int = 1) -> None:
        require(isinstance(actor, str) and 0 < len(actor) <= 200, "invalid_actor")
        entries.append(
            {
                "phase": phase,
                "identity_id": actor,
                "request": _request(request),
                "max_dispatches": maximum,
            }
        )

    for index, step in enumerate(case.get("setup") or []):
        require(isinstance(step, dict) and not step.get("capture"), "unsupported_capture")
        require(isinstance(step.get("name", ""), str), "invalid_setup_name")
        actor = step.get("as") or "setup:" + (step.get("name") or f"setup[{index}]")
        require(not step.get("as") or actor in ids, "unknown_setup_identity")
        add("setup", actor, step.get("request"))
    for identity in all_identities:
        if identity.get("preflight") is not None:
            p = identity["preflight"]
            require(
                isinstance(p, dict) and origin(p.get("url")) == origin(case["request"]["url"]),
                "invalid_preflight",
            )
            add("preflight", identity["id"], {"method": "GET", "url": p["url"]})
    expected = case.get("expected_access") or []
    require(
        isinstance(expected, list)
        and all(
            isinstance(e, dict)
            and e.get("identity_id") in ids
            and isinstance(e.get("decision"), str)
            and e.get("decision") in {"allow", "deny", "skip"}
            for e in expected
        ),
        "invalid_expectations",
    )
    require(len({e["identity_id"] for e in expected}) == len(expected), "invalid_expectations")
    verified = sum(e["decision"] != "skip" for e in expected)
    primary = copy.deepcopy(case.get("request"))
    require(isinstance(primary, dict), "invalid_request")
    assert isinstance(primary, dict)
    cors = case.get("cors")
    if cors is not None:
        require(
            isinstance(cors, dict) and isinstance(cors.get("probe_origin"), str), "invalid_cors"
        )
        headers = {k: v for k, v in (primary.get("headers") or {}).items() if k.lower() != "origin"}
        primary["headers"] = {**headers, "Origin": cors["probe_origin"]}
    for identity_id in ids:
        add("resource", identity_id, primary)
    if verifier is not None and verified:
        require(case.get("mutating") is True, "mutation_not_approved")
        request = verifier.get("request")
        require(isinstance(request, dict), "invalid_verifier")
        assert isinstance(request, dict)
        require(origin(request.get("url")) == origin(primary["url"]), "invalid_verifier")
        add("verification", verifier["identity"]["id"], request, 3 * verified)
        reset = verifier.get("reset")
        if reset is not None:
            require(isinstance(reset, dict) and not reset.get("capture"), "unsupported_capture")
            require(origin(reset["request"]["url"]) == origin(primary["url"]), "invalid_reset")
            require(not reset.get("as") or reset["as"] in ids, "unknown_reset_identity")
            add("reset", reset.get("as") or "verification-reset", reset["request"], verified)
    for entry in entries:
        if entry["request"]["method"] in {"POST", "PUT", "PATCH", "DELETE"}:
            require(case.get("mutating") is True, "mutation_not_approved")
    return {
        "schema": "vardr.execution-plan/1",
        "profile": PROFILE,
        "tool_sha256": tool_sha256,
        "case_hash": digest(encoded(case)),
        "execution": {
            "timeout_seconds": timeout,
            "max_response_bytes": response_bytes,
            "allow_private_targets": private,
        },
        "credential_references": grants,
        "dispatches": entries,
        "max_http_dispatches": sum(e["max_dispatches"] for e in entries),
    }
