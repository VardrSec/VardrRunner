"""Shared managed policy unit checks. Actual Gate/native evidence lives in Map's opt-in fixture."""

import copy
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from vardrrunner import credential_grants, execution_control, handlers, launch_guard, runner
from vardrrunner.authorization import managed
from vardrrunner.authorization.codec import (
    AuthorizationError,
    TrustAnchor,
    digest,
    encoded,
    sign,
    unb64,
)
from vardrrunner.authorization.contracts import ValidationContext
from vardrrunner.authorization.ledger import AuthorizationLedger
from vardrrunner.authorization.plan import compile_gate_plan
from vardrrunner.journal import Journal

NOW = datetime(2026, 11, 2, 18, tzinfo=timezone.utc)


@pytest.fixture
def specimen(tmp_path, monkeypatch):
    ticks = [0.0]
    from datetime import timedelta

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(seconds=ticks[0])

    fake_time = SimpleNamespace(
        monotonic=lambda: ticks[0], time=lambda: Clock.now().timestamp(), sleep=time.sleep
    )
    monkeypatch.setattr(managed, "datetime", Clock)
    monkeypatch.setattr(managed, "time", fake_time)
    monkeypatch.setattr(execution_control, "time", fake_time)
    monkeypatch.setattr(launch_guard, "time", fake_time)
    monkeypatch.setattr(credential_grants, "now", lambda: Clock.now())
    vector = json.loads(
        (Path(__file__).parent / "fixtures/authorization/managed-wire-v1.json").read_text()
    )
    binary = tmp_path / "unit-only-not-executable.exe"
    binary.write_bytes(b"synthetic unit fingerprint; never executed")
    monkeypatch.setattr(runner, "program", lambda _: str(binary))
    plan = compile_gate_plan(
        vector["case"], vector["execution"], tool_sha256=digest(binary.read_bytes())
    )
    permission = vector["context"]
    snapshot = {
        "origin": "https://map.example.test",
        "enrollment": {"runner_id": permission["runner_id"], "principal_sha256": "f" * 64},
    }
    permission.update(authority_sha256=digest(encoded(snapshot)), plan_sha256=digest(encoded(plan)))
    ap = json.loads(unb64(vector["approval"]["payload"]))
    ap.update(context=permission, approved_at="2026-11-02T18:00:00Z")
    approval = sign(ap, bytes(range(32)), "approval")
    payload = json.loads(unb64(vector["contract"]["payload"]))
    payload.update(
        approval_sha256=digest(encoded(approval)),
        plan_sha256=permission["plan_sha256"],
        issued_at="2026-11-02T18:00:00Z",
    )
    envelope = sign(payload, bytes(range(32, 64)), "contract")
    context = ValidationContext(
        permission["runner_id"],
        permission["engagement_id"],
        permission["job_id"],
        payload["attempt_id"],
        payload["fence"],
        "map",
        NOW,
        permission["authority_revision"],
        plan["tool_sha256"],
        permission["authority_sha256"],
    )
    binding = dict(origin=snapshot["origin"], runner_id=context.runner_id, job_id=context.job_id)
    reply = {
        **binding,
        **{k: payload[k] for k in ("contract_id", "attempt_id", "fence")},
        "authority_revision": context.authority_revision,
        "authority_sha256": context.authority_sha256,
        "action": "continue",
        "lease_seconds": 10,
        "lease_expires_at": "2026-11-02T18:00:10Z",
    }
    claim = {
        "execution_control": {
            **binding,
            "token": "x" * 40,
            "lease_seconds": 10,
            "capacity_reserved": True,
            "duration_budget": {
                "allocated_seconds": 30,
                "total_allocated_seconds": 30,
                "limit_seconds": 300,
            },
            "target_budget": {
                "binding": {
                    "profile": plan["profile"],
                    "case_sha256": plan["case_hash"],
                    "origins": ["https://api.example.test:443"],
                },
                "charged": 1,
                "spent": 1,
                "limit": 10,
            },
        },
        "managed_authorization": {
            "contract": envelope,
            "approval": approval,
            "plan": plan,
            "authority_snapshot": snapshot,
        },
    }
    anchors = tuple(
        TrustAnchor(
            a["issuer_id"],
            a["key_id"],
            unb64(a["public_key"]),
            frozenset(a["purposes"]),
            frozenset(a["origins"]),
        )
        for a in vector["trust"]
    )
    ledger = AuthorizationLedger(
        Journal(tmp_path / "ledger.db"), clock=lambda: Clock.now(), monotonic=lambda: ticks[0]
    )
    for _, source, name in handlers.credential_references(vector["case"]):
        for origin in handlers._case_origins(vector["case"]):
            credential_grants.Store().approve(
                snapshot["origin"], context.engagement_id, origin, source, name, 60
            )

    calls = []

    def current(request):
        calls.append(True)
        return copy.deepcopy(reply)

    def make(allocated_seconds=30):
        return managed.ManagedGate(
            claim,
            anchors,
            ledger,
            context,
            vector["case"],
            vector["execution"],
            map_origin=snapshot["origin"],
            principal_sha256="f" * 64,
            claim_started=0,
            allocated_seconds=allocated_seconds,
            current=current,
        )

    return SimpleNamespace(
        make=make,
        claim=claim,
        reply=reply,
        ticks=ticks,
        binary=binary,
        context=context,
        ledger=ledger,
        calls=calls,
        case=vector["case"],
        execution=vector["execution"],
        anchors=anchors,
    )


def test_shared_validation_consumption_and_local_only_artifact(specimen, tmp_path, monkeypatch):
    s = specimen
    monkeypatch.setattr(execution_control, "available", lambda: True)

    def inert_handler(self, targets, folder, config, **kwargs):
        with launch_guard.boundary():
            result = folder / "vardrgate_result.json"
            result.write_text("{}")
        return result

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", inert_handler)
    gate = s.make()
    assert gate.execute(tmp_path).exists()
    with pytest.raises(AuthorizationError, match="single_managed_attempt"):
        gate.execute(tmp_path)


@pytest.mark.parametrize("field", ["origin", "runner_id", "principal_sha256"])
def test_constructor_refuses_wrong_association(specimen, field):
    s = specimen
    snapshot = s.claim["managed_authorization"]["authority_snapshot"]
    (snapshot if field == "origin" else snapshot["enrollment"])[field] = "changed"
    with pytest.raises(AuthorizationError):
        s.make()


@pytest.mark.parametrize(
    "field", ["action", "fence", "authority_revision", "lease_seconds", "lease_expires_at"]
)
def test_current_denials_never_create_verified_permission(specimen, field):
    s = specimen
    gate = s.make()
    s.reply[field] = (
        2
        if field in {"fence", "authority_revision"}
        else 11
        if field == "lease_seconds"
        else "changed"
    )
    with pytest.raises(AuthorizationError):
        gate.refresh()
    assert not gate.context.managed_status_verified


def test_cached_reply_cap_and_launch_tool_recheck(specimen):
    s = specimen
    gate = s.make()
    gate.refresh()
    s.ticks[0] = 8
    gate.refresh()
    assert gate.lease_deadline() == 10
    s.ticks[0] = 11
    with pytest.raises(AuthorizationError):
        gate.refresh()
    s.ticks[0] = 0
    s.binary.write_bytes(b"changed")
    with pytest.raises(AuthorizationError, match="tool_changed"):
        gate._launch_check()


def test_unsupported_native_platform_never_consumes(specimen, tmp_path, monkeypatch):
    monkeypatch.setattr(execution_control, "available", lambda: False)
    with pytest.raises(AuthorizationError, match="unsupported"):
        specimen.make().execute(tmp_path)


def test_local_grant_denial_is_sticky(specimen):
    gate = specimen.make()
    with credential_grants.required(gate.binding["origin"]) as policy:
        handlers.check_gate_case(gate.case, gate.context.engagement_id)
        gate._policy = policy
        origin = handlers._case_origins(gate.case)[0]
        _, source, name = handlers.credential_references(gate.case)[0]
        policy.store.revoke(
            gate.binding["origin"], gate.context.engagement_id, origin, source, name
        )
        with pytest.raises(credential_grants.GrantError):
            gate.refresh()
        assert gate.stopped()


def test_transport_error_is_fixed_and_does_not_extend_cap(specimen):
    gate = specimen.make()
    before = gate.lease_deadline()

    def unavailable(request):
        raise OSError("synthetic transport diagnostic; never propagate")

    gate._current = unavailable
    with pytest.raises(AuthorizationError, match="^managed_control_unavailable$"):
        gate.refresh()
    assert gate.lease_deadline() == before


@pytest.mark.parametrize(
    "field",
    [
        "duration_missing",
        "duration_partial",
        "duration_bool",
        "target_missing",
        "target_origin",
        "target_charge",
        "target_spent",
        "target_limit",
        "target_bool",
    ],
)
def test_budget_receipts_refused_before_current_or_consumption(specimen, monkeypatch, field):
    s = specimen
    receipt = s.claim["execution_control"]
    if field == "duration_missing":
        receipt.pop("duration_budget")
    elif field == "duration_partial":
        receipt["duration_budget"].pop("total_allocated_seconds")
    elif field == "duration_bool":
        receipt["duration_budget"]["allocated_seconds"] = True
    elif field == "target_missing":
        receipt.pop("target_budget")
    elif field == "target_origin":
        receipt["target_budget"]["binding"]["origins"] = ["https://foreign.test:443"]
    else:
        receipt["target_budget"][
            {
                "target_charge": "charged",
                "target_spent": "spent",
                "target_limit": "limit",
                "target_bool": "charged",
            }[field]
        ] = True if field == "target_bool" else 0
    with pytest.raises(AuthorizationError):
        s.make(allocated_seconds=1 if field == "duration_bool" else 30)
    assert not s.calls
    with s.ledger.journal._connection() as con:
        assert con.execute("SELECT count(*) FROM authorization_contracts").fetchone()[0] == 0
