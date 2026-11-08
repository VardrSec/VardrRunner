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
    RUNTIME_PROFILE,
    compile_recon_plan,
    compile_recon_runtime_plan,
    select_candidates,
    select_runtime_candidates,
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


def authorize(s, case, execution, runtime_profile=False, runtime_hashes=None, **changes):
    httpx_hash, dnsx_hash = runtime_hashes or ("a" * 64, "b" * 64)
    plan = (
        compile_recon_runtime_plan(case, execution, tool_sha256=httpx_hash, dnsx_sha256=dnsx_hash)
        if runtime_profile
        else compile_projection(case, execution)
    )
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
        tool_sha256=httpx_hash if runtime_profile else HTTPX_SHA256,
        dnsx_sha256=dnsx_hash if runtime_profile else DNSX_SHA256,
        capabilities=frozenset({RUNTIME_PROFILE if runtime_profile else PROFILE}),
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
    def reserved():
        raise AssertionError("Dormant recon must not enter the standalone journal callback")

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
            on_reserved=reserved,
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


def test_runtime_projection_preserves_v1_and_checks_all_answers(projection):
    case, execution = projection
    original = encoded(compile_projection(case, execution))
    case["destination_cidrs"] = ["127.0.0.0/24"]
    plan = compile_recon_runtime_plan(case, execution, tool_sha256="a" * 64, dnsx_sha256="b" * 64)
    assert (
        plan["schema"],
        plan["runtime"],
        plan["max_dns_queries"],
        plan["max_http_dispatches"],
    ) == ("vardr.finite-recon-plan/2", "contained-tools/1", 4, 8)
    assert plan["tool_sha256"] == "a" * 64 and plan["tools"]["dnsx_sha256"] == "b" * 64
    answer = {"hostname": case["hostnames"][0], "addresses": ["127.0.0.20", "127.0.0.3"]}
    assert select_runtime_candidates(plan, [answer]) == [
        {**case["candidates"][0], "address": "127.0.0.3"}
    ]
    answer["addresses"].append("127.0.1.1")
    with pytest.raises(AuthorizationError, match="recon_destination_denied"):
        select_runtime_candidates(plan, [answer])
    plan["options"]["transport"]["http_stage_dns"] = True
    with pytest.raises(AuthorizationError, match="execution_plan_changed"):
        select_runtime_candidates(plan, [])
    case["destination_cidrs"] = ["127.0.0.1/32"]
    assert encoded(compile_projection(case, execution)) == original


@pytest.mark.parametrize("hostname", ["as123", "as-123"])
def test_runtime_rejects_dnsx_asn_expansion(projection, hostname):
    case, execution = projection
    case["hostnames"] = [hostname]
    case["candidates"] = [{**case["candidates"][0], "hostname": hostname}]
    compile_projection(case, execution)  # Preserve the dormant v1 contract.
    with pytest.raises(AuthorizationError, match="recon_asn_expansion_denied"):
        compile_recon_runtime_plan(case, execution, tool_sha256="a" * 64, dnsx_sha256="b" * 64)


def test_runtime_signed_binding_requires_explicit_capability_and_both_hashes(specimen, projection):
    case, execution = projection
    contract, receipt, plan, runtime = authorize(specimen, case, execution, runtime_profile=True)
    args = (contract, receipt, plan, case, execution, (specimen["anchor"],))
    assert validate(*args, runtime)["execution_index"] == 1
    for changes in (
        {"capabilities": frozenset({PROFILE})},
        {"tool_sha256": "c" * 64},
        {"dnsx_sha256": None},
        {"dnsx_sha256": "c" * 64},
    ):
        with pytest.raises(AuthorizationError):
            validate(*args, replace(runtime, **changes))
    claimed = specimen["ledger"].consume(*args, runtime)
    with pytest.raises(AuthorizationError):
        specimen["ledger"].consume(*args, runtime)
    specimen["ledger"].finish(claimed)


@pytest.mark.parametrize("outcome", ["success", "outside", "tool_error", "timeout"])
def test_runtime_two_tool_handoff_and_fail_closed(
    specimen, projection, monkeypatch, tmp_path, outcome
):
    import time
    from datetime import datetime
    from types import SimpleNamespace
    from unittest.mock import Mock

    from vardrrunner import config, execution_control, launch_guard, toolchain, worker_lifecycle
    from vardrrunner.authorization import recon_runtime as runtime_module

    tools = tmp_path / "tools"
    tools.mkdir()
    paths = {name: tools / name for name in ("dnsx", "httpx")}
    for name, path in paths.items():
        path.write_bytes(name.encode("ascii"))
    hashes = {name: digest(path.read_bytes()) for name, path in paths.items()}
    monkeypatch.setattr(config, "TOOLS_DIR", tools)
    toolchain._write_lock({name: {"binary": name, "binary_sha256": hashes[name]} for name in paths})
    monkeypatch.setattr(runtime_module, "qualified_tools", lambda: (paths, hashes))
    monkeypatch.setenv("VARDRRUNNER_ALLOW_PRIVATE_TARGETS", "1")
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.invalid")
    case, execution = projection
    contract, receipt, plan, context = authorize(
        specimen,
        case,
        execution,
        runtime_profile=True,
        runtime_hashes=(hashes["httpx"], hashes["dnsx"]),
    )

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return context.now

    monkeypatch.setattr(runtime_module, "datetime", FixedDatetime)
    baseline = time.monotonic()
    ticks = [0.0]
    monkeypatch.setattr(
        runtime_module, "time", SimpleNamespace(monotonic=lambda: baseline + ticks[0])
    )
    owner = Mock(spec=worker_lifecycle.SequentialWorkerOwner)
    monkeypatch.setattr(worker_lifecycle, "current", lambda: owner)
    calls, ceilings = [], []
    output = tmp_path / "recon-output"
    output.mkdir()

    def tool(command, temporary, name, timeout):
        calls.append((name, command, timeout))
        ceilings.append(launch_guard._MONOTONIC.get())
        environment = config.tool_environment()
        assert environment["HOME"] == str(output / "tool-home")
        assert not any("proxy" in key.lower() for key in environment)
        assert (Path(environment["HOME"]) / "config").is_dir()
        destination = Path(command[command.index("-o") + 1])
        if name == "dnsx":
            assert command[command.index("-timeout") + 1] == "1s"
            address = "127.0.0.2" if outcome == "outside" else "127.0.0.1"
            destination.write_text(
                json.dumps({"host": case["hostnames"][0], "a": [address]}) + "\n"
            )
            ticks[0] = 31.0 if outcome == "timeout" else 5.0
        else:
            assert command[command.index("-u") + 1] == "https://127.0.0.1:443/"
            assert command[command.index("-sni-name") + 1] == case["hostnames"][0]
            assert command[command.index("-H") + 1] == "Host: one.example.test:443"
            assert "-no-fallback-scheme" in command and "-follow-redirects" not in command
            assert timeout <= 25
            if outcome == "tool_error":
                raise runtime_module.runner.ToolError("synthetic tool failure")
            destination.write_text(
                json.dumps({"url": "https://127.0.0.1:443/", "status_code": 200}) + "\n"
            )
            ticks[0] = 10.0

    monkeypatch.setattr(runtime_module.runner, "_run_tool", tool)
    finish = Mock(wraps=specimen["ledger"].finish)
    monkeypatch.setattr(specimen["ledger"], "finish", finish)
    args = (contract, receipt, plan, case, execution, (specimen["anchor"],), context)
    control = execution_control.Control(
        lambda: {"action": "continue", "lease_seconds": 10},
        {},
        10,
        started=baseline,
        local_stop=lambda: False,
    )
    with execution_control.controlled(control):
        if outcome == "success":
            artifact = runtime_module.execute_recon(specimen["ledger"], *args, output)
            document = json.loads(artifact.read_text())
            assert document["http"][0]["logical_url"] == "https://one.example.test:443/"
            assert document["handoff"]["execution_authority"] is False
            assert document["handoff"]["requires_new_review"] is True
            assert document["provenance"]["tools"]["httpx"]["sha256"] == hashes["httpx"]
            assert document["provenance"]["tools"]["dnsx"]["version"] == "1.3.1"
            assert document["provenance"]["case_hash"] == plan["case_hash"]
            assert document["provenance"]["case_snapshot"]["candidates"] == case["candidates"]
            assert finish.call_count == 1
        else:
            with pytest.raises((AuthorizationError, runtime_module.runner.ToolError)):
                runtime_module.execute_recon(specimen["ledger"], *args, output)
            finish.assert_not_called()
    assert [name for name, _, _ in calls] == (
        ["dnsx", "httpx"] if outcome in {"success", "tool_error"} else ["dnsx"]
    )
    assert ceilings == [baseline + execution["timeout_seconds"]] * len(calls)
    with pytest.raises(AuthorizationError):
        specimen["ledger"].consume(*args)
