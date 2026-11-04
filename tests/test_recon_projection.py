"""Dormant projection only: synthetic documents, no DNS, HTTP or tool process."""

import copy
import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from tests.test_authorization_contract import SEED
from tests.test_authorization_contract import specimen as gate_specimen
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.contracts import approve, validate
from vardrrunner.authorization.recon_plan import (
    DNSX_SHA256,
    HTTPX_SHA256,
    PROFILE,
    compile_recon_plan,
    select_candidates,
)
from vardrrunner.authorization.runtime import execute_gate


@pytest.fixture
def specimen(tmp_path):
    return gate_specimen.__wrapped__(tmp_path)


@pytest.fixture
def projection():
    case = {
        "hostnames": ["one.example.test", "two.example.test"],
        "candidates": [
            {"hostname": h, "scheme": "https", "port": 443, "path": "/", "method": "GET"}
            for h in ("one.example.test", "two.example.test")
        ],
        "destination_cidrs": ["127.0.0.1/32"],
        "resolvers": [{"address": "127.0.0.53", "port": 53}],
    }
    execution = {
        "deadline": "2026-11-01T18:01:00Z",
        "timeout_seconds": 30,
        "max_artifact_bytes": 100000,
        "allow_private_targets": True,
    }
    return case, execution


def compile_projection(case, execution):
    return compile_recon_plan(case, execution, tool_sha256=HTTPX_SHA256, dnsx_sha256=DNSX_SHA256)


def authorize(s, case, execution, **changes):
    plan = compile_projection(case, execution)
    context = copy.deepcopy(s["context"])
    context.update(
        job_id="recon-job",
        credential_grants=[],
        plan_sha256=digest(encoded(plan)),
        scope=[
            {
                "origin": f"https://{h}:443",
                "path": "/",
                "method": "GET",
                "excluded": False,
                "reason": "",
            }
            for h in case["hostnames"]
        ],
    )
    context.update(changes)
    receipt = approve(
        context,
        s["issuer"],
        "standalone",
        "operator-1",
        "recon-approval",
        "2026-11-01T17:59:00Z",
        SEED,
    )
    runtime = replace(
        s["runtime"],
        job_id="recon-job",
        tool_sha256=HTTPX_SHA256,
        dnsx_sha256=DNSX_SHA256,
        capabilities=frozenset({PROFILE}),
    )
    contract = s["ledger"].issue(
        receipt,
        (s["anchor"],),
        s["issuer"],
        SEED,
        "recon-contract",
        "attempt-1",
        runtime,
        plan,
        case,
        execution,
    )
    return contract, receipt, plan, runtime


def test_compile_and_handoff_immutable(projection):
    case, execution = projection
    plan = compile_projection(case, execution)
    before = encoded(plan)
    assert plan["max_http_dispatches"] == 8
    assert plan["max_dns_queries"] == 104
    assert plan["runtime"] == "unsupported"
    assert (
        select_candidates(plan, [{"hostname": case["hostnames"][0], "addresses": ["127.0.0.1"]}])
        == case["candidates"][:1]
    )
    assert select_candidates(plan, []) == []
    assert encoded(plan) == before
    assert plan["reservation"]["refund_after_handoff"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("hostnames", ["ONE.example.test"]),
        ("hostnames", ["127.0.0.1"]),
        ("hostnames", ["one..test"]),
        ("hostnames", ["-a.test"]),
        ("hostnames", ["a.test."]),
        ("hostnames", ["a.test", "a.test"]),
        ("hostnames", []),
        ("destination_cidrs", ["127.0.0.1/24"]),
        ("destination_cidrs", ["169.254.169.254/32"]),
        ("destination_cidrs", ["0.0.0.0/0"]),
        ("destination_cidrs", ["100.100.100.200/32"]),
        ("destination_cidrs", ["::1/128"]),
        ("resolvers", [{"address": "resolver.test", "port": 53}]),
        ("resolvers", [{"address": "127.0.0.53", "port": True}]),
        ("resolvers", [{"address": "127.0.0.53", "port": 0}]),
    ],
)
def test_reject_ambiguous_inputs(projection, field, value):
    case, execution = projection
    case[field] = value
    with pytest.raises(AuthorizationError):
        compile_projection(case, execution)


@pytest.mark.parametrize(
    "field,value",
    [
        ("scheme", "http"),
        ("port", True),
        ("port", 8443),
        ("method", "POST"),
        ("path", "/other"),
        ("hostname", "unapproved.test"),
    ],
)
def test_only_fixed_candidates(projection, field, value):
    case, execution = projection
    case["candidates"][0][field] = value
    with pytest.raises(AuthorizationError):
        compile_projection(case, execution)


@pytest.mark.parametrize(
    "answers",
    [
        [{"hostname": "one.example.test", "addresses": []}],
        [{"hostname": "one.example.test", "addresses": ["127.0.0.1", "127.0.0.2"]}],
        [{"hostname": "other.test", "addresses": ["127.0.0.1"]}],
        [{"hostname": "one.example.test", "addresses": ["::1"]}],
        [{"hostname": "one.example.test", "addresses": ["127.0.0.1"]}] * 2,
    ],
)
def test_handoff_refuses_expansion(projection, answers):
    with pytest.raises(AuthorizationError):
        select_candidates(compile_projection(*projection), answers)


def test_changed_projection_not_recompiled(projection):
    plan = compile_projection(*projection)
    plan["options"]["httpx"]["redirects"] = True
    with pytest.raises(AuthorizationError, match="execution_plan_changed"):
        select_candidates(plan, [])


def test_artifact_identity_and_private_gate(projection):
    case, execution = projection
    for httpx, dnsx in [("a" * 64, DNSX_SHA256), (HTTPX_SHA256, None)]:
        with pytest.raises(AuthorizationError, match="unsupported_recon_artifacts"):
            compile_recon_plan(case, execution, tool_sha256=httpx, dnsx_sha256=dnsx)
    execution["allow_private_targets"] = False
    with pytest.raises(AuthorizationError, match="private_target_denied"):
        compile_projection(case, execution)


def test_signed_whole_unit_consume_once(specimen, projection):
    s = specimen
    case, execution = projection
    contract, receipt, plan, runtime = authorize(s, case, execution)
    args = (contract, receipt, plan, case, execution, (s["anchor"],), runtime)
    assert validate(*args)["execution_index"] == 1
    select_candidates(plan, [])  # No answers cannot refund or split the issued ordinal.
    claimed = s["ledger"].consume(*args)
    with pytest.raises(AuthorizationError):
        s["ledger"].consume(*args)
    s["ledger"].finish(claimed)
    with pytest.raises(AuthorizationError):
        s["ledger"].consume(*args)


@pytest.mark.parametrize("change", ["capability", "dnsx", "primary", "revoked", "stopped", "scope"])
def test_common_checks_preserved(specimen, projection, change):
    s = specimen
    case, execution = projection
    if change == "scope":
        with pytest.raises(AuthorizationError, match="scope_denied"):
            authorize(s, case, execution, scope=[])
        return
    contract, receipt, plan, runtime = authorize(s, case, execution)
    changes = {
        "capability": {"capabilities": frozenset()},
        "dnsx": {"dnsx_sha256": "a" * 64},
        "primary": {"tool_sha256": "a" * 64},
        "revoked": {"revoked": True},
        "stopped": {"stop_work": True},
    }[change]
    with pytest.raises(AuthorizationError):
        validate(
            contract, receipt, plan, case, execution, (s["anchor"],), replace(runtime, **changes)
        )


@pytest.mark.parametrize(
    "change",
    [
        {"max_http_dispatches": 7},
        {"max_artifact_bytes": 10},
        {"max_duration_seconds": 10},
        {"mode": "advisory"},
    ],
)
def test_whole_envelope_limits(specimen, projection, change):
    with pytest.raises(AuthorizationError):
        authorize(specimen, *projection, **change)


def test_expired_shared_deadline(specimen, projection):
    case, execution = projection
    execution["deadline"] = "2026-11-01T18:00:00Z"
    with pytest.raises(AuthorizationError, match="recon_deadline_denied"):
        authorize(specimen, case, execution)


def test_gate_runtime_refuses_before_side_effects(projection, tmp_path):
    class Forbidden:
        def __getattr__(self, name):
            raise AssertionError("runtime side effect")

    with pytest.raises(AuthorizationError, match="unsupported_enforcement"):
        execute_gate(
            Forbidden(),
            {},
            {},
            compile_projection(*projection),
            *projection,
            (),
            Forbidden(),
            tmp_path,
            expiring_grants=True,
        )


@pytest.mark.parametrize("cidr", ["198.0.0.0/8", "192.0.0.0/8", "203.0.0.0/8"])
def test_global_ended_network_cannot_include_private_holes(projection, cidr):
    case, execution = projection
    case["destination_cidrs"] = [cidr]
    case["resolvers"] = [{"address": "1.1.1.1", "port": 53}]
    execution["allow_private_targets"] = False
    with pytest.raises(AuthorizationError, match="private_target_denied"):
        compile_projection(case, execution)


@pytest.mark.parametrize("phase", ["issue", "consume"])
@pytest.mark.parametrize("seconds", [59.9, 60.0, 61.0])
def test_recon_deadline_rechecked_after_validation(
    specimen, projection, monkeypatch, phase, seconds
):
    from vardrrunner.authorization import ledger as ledger_module

    s = specimen
    case, execution = projection
    args = None
    if phase == "consume":
        contract, receipt, plan, runtime = authorize(s, case, execution)
        args = (contract, receipt, plan, case, execution, (s["anchor"],), runtime)
    ticks = [0.0]
    monkeypatch.setattr(s["ledger"], "_monotonic", lambda: ticks[0])
    original = ledger_module.validate

    def advance_after_validation(*args):
        result = original(*args)
        ticks[0] = seconds
        return result

    monkeypatch.setattr(ledger_module, "validate", advance_after_validation)

    def reservations():
        with s["ledger"].journal._connection() as con:
            return [
                list(map(tuple, con.execute("SELECT * FROM " + table + " ORDER BY rowid")))
                for table in (
                    "authorization_approvals",
                    "authorization_fences",
                    "authorization_contracts",
                )
            ]

    before = reservations()

    def attempt():
        if phase == "issue":
            return authorize(s, case, execution)
        return s["ledger"].consume(*args)

    if seconds < 60:
        attempt()
        assert reservations() != before
    else:
        with pytest.raises(AuthorizationError, match="recon_deadline_denied"):
            attempt()
        assert reservations() == before
        with s["ledger"].journal._connection() as con:
            observed = con.execute("SELECT observed FROM authorization_clock").fetchone()[0]
        from datetime import datetime

        assert datetime.fromisoformat(observed) >= s["runtime"].now + timedelta(seconds=seconds)


def test_gate_final_time_does_not_inherit_recon_deadline(specimen, monkeypatch):
    from vardrrunner.authorization import ledger as ledger_module

    s = specimen
    ticks = [0.0]
    monkeypatch.setattr(s["ledger"], "_monotonic", lambda: ticks[0])
    original = ledger_module.validate

    def advance_after_validation(*args):
        result = original(*args)
        ticks[0] = 61.0
        return result

    monkeypatch.setattr(ledger_module, "validate", advance_after_validation)
    s["ledger"].consume(
        s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
    )


def test_separate_recon_schema_preserves_gate_schema(specimen, projection):
    gate_schema = json.loads(
        (Path(__file__).parents[1] / "docs/contracts/plan-v1.schema.json").read_text()
    )
    plan = compile_projection(*projection)
    assert plan["schema"] == "vardr.finite-recon-plan/1"
    assert specimen["plan"]["schema"] == gate_schema["properties"]["schema"]["const"]
    assert specimen["plan"]["profile"] == gate_schema["properties"]["profile"]["const"]
    assert plan["schema"] != specimen["plan"]["schema"]
    plan["schema"] = specimen["plan"]["schema"]
    with pytest.raises(AuthorizationError, match="execution_plan_changed"):
        select_candidates(plan, [])
