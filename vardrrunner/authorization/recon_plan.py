"""Dormant finite recon projection. No subprocess, resolution or execution authority."""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import cast

from .codec import AuthorizationError, digest, encoded, fields, integer, require

PROFILE = "finite-dns-http/1"
RUNTIME_PROFILE = "finite-dns-http/2"
# These exact Linux release ELFs are the only artifacts covered by the request model.
DNSX_SHA256 = "5fca43ddfe95922d8d88a859c1fcc59fee327bf39ae574db66d391c6675b8ba3"
HTTPX_SHA256 = "6d78b83b4da452a7e0bd3613c4fae04cbf523209f083904b563f4d4406a680b0"
_BLOCKED = tuple(
    ipaddress.IPv4Network(n)
    for n in ("0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "100.100.100.200/32")
)


def _hostname(value: object) -> str:
    require(
        isinstance(value, str)
        and 1 <= len(value) <= 253
        and all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        )
        and not value.replace(".", "").isdigit(),
        "invalid_recon_hostname",
    )
    return cast(str, value)


def _sequence(value: object, maximum: int = 1000) -> list:
    require(isinstance(value, list) and 1 <= len(value) <= maximum, "invalid_recon_list")
    value = cast(list, value)
    require(len({encoded(item) for item in value}) == len(value), "duplicate_recon_input")
    return value


def _network(value: object, private: bool) -> ipaddress.IPv4Network:
    require(isinstance(value, str), "invalid_recon_network")
    try:
        net = ipaddress.IPv4Network(value, strict=True)
    except (ValueError, TypeError) as exc:
        raise AuthorizationError("invalid_recon_network") from exc
    require(str(net) == value, "noncanonical_recon_network")
    require(not any(net.overlaps(blocked) for blocked in _BLOCKED), "hard_network_denied")
    # Both ends must be global: broad CIDRs must not smuggle private destinations.
    require(
        (net.network_address.is_global and net.broadcast_address.is_global) or private,
        "private_target_denied",
    )
    # With private disabled reject overlap, including ranges whose ends are global.
    if not private:
        for reserved in (
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
        ):
            require(not net.overlaps(ipaddress.IPv4Network(reserved)), "private_target_denied")
    return net


def compile_recon_plan(
    case: dict, execution: dict, *, tool_sha256: str, dnsx_sha256: str | None
) -> dict:
    """Compile a reviewable immutable unit; this does not enable a recon runtime.

    First slice: A-only DNS inputs and explicit HTTPS/443 GET-root candidates,
    IPv4 destination networks and numeric IPv4 UDP/TCP resolver endpoints only.
    """
    from .contracts import timestamp

    fields(case, {"hostnames", "candidates", "destination_cidrs", "resolvers"})
    fields(
        execution, {"deadline", "timeout_seconds", "max_artifact_bytes", "allow_private_targets"}
    )
    require(
        tool_sha256 == HTTPX_SHA256 and dnsx_sha256 == DNSX_SHA256, "unsupported_recon_artifacts"
    )
    timestamp(execution["deadline"])
    integer(execution["timeout_seconds"], 1, 600)
    integer(execution["max_artifact_bytes"], 1, 1024**3)
    private = execution["allow_private_targets"]
    require(type(private) is bool, "invalid_private_option")
    hosts = [_hostname(h) for h in _sequence(case["hostnames"])]
    candidates = _sequence(case["candidates"])
    dispatches = []
    for item in candidates:
        fields(item, {"hostname", "scheme", "port", "path", "method"})
        require(_hostname(item["hostname"]) in hosts, "unapproved_recon_hostname")
        require(
            item["scheme"] == "https"
            and type(item["port"]) is int
            and item["port"] == 443
            and item["path"] == "/"
            and item["method"] == "GET",
            "unsupported_recon_candidate",
        )
        dispatches.append({"request": {"url": f"https://{item['hostname']}:443/", "method": "GET"}})
    for value in _sequence(case["destination_cidrs"], 100):
        _network(value, private)
    for resolver in _sequence(case["resolvers"], 10):
        fields(resolver, {"address", "port"})
        _network(str(resolver["address"]) + "/32", private)
        integer(resolver["port"], 1, 65535)
    n, m = len(hosts), len(candidates)
    return {
        "schema": "vardr.finite-recon-plan/1",
        "profile": PROFILE,
        "runtime": "unsupported",
        "platform_model": "linux-amd64-conditional/1",
        "case_hash": digest(encoded(case)),
        "input": copy.deepcopy(case),
        "tools": {"httpx_sha256": tool_sha256, "dnsx_sha256": dnsx_sha256},
        "execution": copy.deepcopy(execution),
        "dispatches": dispatches,
        "credential_references": [],
        "max_http_dispatches": 4 * m,
        "max_dns_queries": 2 * n + 50 * m,
        "reservation": {"unit": "whole_plan_execution_ordinal", "refund_after_handoff": False},
        "counting": {
            "dns": "application_questions",
            "http": "application_requests",
            "packets_bytes_connections": "not_bounded_by_this_projection",
        },
        "options": {
            "dnsx": {
                "query": "A",
                "retry": 1,
                "tcp_on_truncation": True,
                "timeout_seconds": 1,
                "threads": 1,
                "auth": False,
                "update": False,
                "enumeration_trace_wildcard_hosts_config_resume": False,
            },
            "httpx": {
                "protocol": "http11",
                "retries": 0,
                "timeout_seconds": 1,
                "threads": 1,
                "rate_limit": 10,
                "redirects": False,
                "scheme_fallback": False,
                "auth": False,
                "cdn": False,
                "random_agent": False,
                "update": False,
                "extra_probes_ports_paths_methods": False,
                "probe_all_ips": False,
            },
            "environment": "fresh_owned_home_empty_config_allowlist_no_proxy",
            "resolver_transport": ["udp", "tcp"],
            "http_destination_allowlist": "exact_signed_destination_cidrs",
        },
    }


def select_candidates(plan: dict, answers: list) -> list[dict]:
    """Pure handoff, never an execution permission or destination-enforcement proof.

    Caller still needs trusted signature/ledger validation. Missing hosts are not
    selected; empty, duplicate, ambiguous or out-of-scope answers fail closed.
    The original signed plan and full reservation remain unchanged.
    """
    require(isinstance(plan, dict), "invalid_recon_plan")
    try:
        expected = compile_recon_plan(
            plan["input"],
            plan["execution"],
            tool_sha256=plan["tools"]["httpx_sha256"],
            dnsx_sha256=plan["tools"]["dnsx_sha256"],
        )
    except (KeyError, TypeError) as exc:
        raise AuthorizationError("invalid_recon_plan") from exc
    require(encoded(plan) == encoded(expected), "execution_plan_changed")
    require(
        isinstance(answers, list) and len(answers) <= len(plan["input"]["hostnames"]),
        "invalid_recon_answers",
    )
    selected: set[str] = set()
    networks = [ipaddress.IPv4Network(n) for n in plan["input"]["destination_cidrs"]]
    for answer in answers:
        fields(answer, {"hostname", "addresses"})
        host = _hostname(answer["hostname"])
        require(
            host in plan["input"]["hostnames"] and host not in selected, "unapproved_recon_answer"
        )
        for raw in _sequence(answer["addresses"], 100):
            require(isinstance(raw, str), "invalid_recon_address")
            try:
                address = ipaddress.IPv4Address(raw)
            except (ValueError, TypeError) as exc:
                raise AuthorizationError("invalid_recon_address") from exc
            _network(str(address) + "/32", plan["execution"]["allow_private_targets"])
            require(
                str(address) == raw and any(address in n for n in networks),
                "recon_destination_denied",
            )
        selected.add(host)
    return copy.deepcopy([c for c in plan["input"]["candidates"] if c["hostname"] in selected])


def compile_recon_runtime_plan(
    case: dict, execution: dict, *, tool_sha256: str, dnsx_sha256: str | None
) -> dict:
    """Bind a finite managed-tool journey without changing the dormant projection."""
    for artifact in (tool_sha256, dnsx_sha256):
        require(
            isinstance(artifact, str) and re.fullmatch(r"[a-f0-9]{64}", artifact) is not None,
            "invalid_recon_artifact",
        )
    plan = compile_recon_plan(case, execution, tool_sha256=HTTPX_SHA256, dnsx_sha256=DNSX_SHA256)
    # DNSx file input otherwise expands ASN-shaped names through an external lookup.
    require(
        all(re.fullmatch(r"as-?[0-9]+", host) is None for host in case["hostnames"]),
        "recon_asn_expansion_denied",
    )
    plan.update(
        schema="vardr.finite-recon-plan/2",
        profile=RUNTIME_PROFILE,
        runtime="contained-tools/1",
        platform_model="verified-managed-tools/1",
        tool_sha256=tool_sha256,
        tools={"httpx_sha256": tool_sha256, "dnsx_sha256": dnsx_sha256},
        max_dns_queries=2 * len(case["hostnames"]),
    )
    plan["options"]["transport"] = {
        "http_destination": "validated_literal_ipv4",
        "address_selection": "lowest_numeric_ipv4_per_hostname",
        "http_host": "original_hostname:443",
        "tls_sni": "original_hostname",
        "http_stage_dns": False,
    }
    return plan


def select_runtime_candidates(plan: dict, answers: list) -> list[dict]:
    """Validate every answer and bind original candidates to one numeric address."""
    require(isinstance(plan, dict), "invalid_recon_plan")
    try:
        expected = compile_recon_runtime_plan(
            plan["input"],
            plan["execution"],
            tool_sha256=plan["tools"]["httpx_sha256"],
            dnsx_sha256=plan["tools"]["dnsx_sha256"],
        )
    except (KeyError, TypeError) as exc:
        raise AuthorizationError("invalid_recon_plan") from exc
    require(encoded(plan) == encoded(expected), "execution_plan_changed")
    projection = compile_recon_plan(
        plan["input"], plan["execution"], tool_sha256=HTTPX_SHA256, dnsx_sha256=DNSX_SHA256
    )
    candidates = select_candidates(projection, answers)
    addresses = {
        answer["hostname"]: str(min(ipaddress.IPv4Address(value) for value in answer["addresses"]))
        for answer in answers
    }
    return [{**candidate, "address": addresses[candidate["hostname"]]} for candidate in candidates]
