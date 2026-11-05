"""NM-1 synthetic conformance and failure paths; no HTTP or operator state."""

import copy
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vardrrunner.authorization.codec import (
    AuthorizationError,
    TrustAnchor,
    b64,
    decoded,
    digest,
    encoded,
    sign,
    unb64,
)
from vardrrunner.authorization.contracts import (
    ValidationContext,
    approve,
    validate,
    validate_context,
)
from vardrrunner.authorization.ledger import AuthorizationLedger
from vardrrunner.authorization.plan import compile_gate_plan, origin
from vardrrunner.journal import Journal

# Publicly documented fixture-only seed; never a trust anchor for real work.
SEED = bytes(range(32))
NOW = datetime(2026, 11, 1, 18, tzinfo=timezone.utc)
TOOL = "a" * 64


@pytest.fixture
def specimen(tmp_path):
    case = {
        "id": "case-1",
        "mutating": True,
        "identities": [
            {
                "id": "owner",
                "credential": {"type": "bearer", "value_env": "NM1_OWNER"},
                "preflight": {
                    "url": "https://api.example.test/me",
                    "expected_status": 200,
                    "json_fields": {"id": "owner"},
                },
            },
            {"id": "peer", "credential": {"type": "static_header"}},
            {"id": "skipped", "credential": {"type": "static_header"}},
        ],
        "setup": [
            {
                "name": "prepare",
                "request": {"method": "POST", "url": "https://api.example.test/prepare"},
            }
        ],
        "request": {
            "method": "PATCH",
            "url": "https://api.example.test/objects/17",
            "body": {"label": "reviewed"},
        },
        "expected_access": [
            {"identity_id": "owner", "decision": "allow"},
            {"identity_id": "peer", "decision": "deny"},
            {"identity_id": "skipped", "decision": "skip"},
        ],
        "write_verification": {
            "identity": {
                "id": "reader",
                "credential": {"type": "static_header"},
                "preflight": {
                    "url": "https://api.example.test/me",
                    "expected_status": 200,
                    "json_fields": {"id": "reader"},
                },
            },
            "request": {"method": "GET", "url": "https://api.example.test/objects/17"},
            "reset": {
                "as": "owner",
                "request": {"method": "POST", "url": "https://api.example.test/reset"},
            },
        },
    }
    execution = {}
    plan = compile_gate_plan(case, execution, tool_sha256=TOOL)
    scope = [
        dict(
            origin=origin(d["request"]["url"]),
            path=d["request"]["url"].split(".test", 1)[1],
            method=d["request"]["method"],
            excluded=False,
            reason="",
        )
        for d in plan["dispatches"]
    ]
    context = {
        "runner_id": "runner-1",
        "engagement_id": "eng-1",
        "job_id": "job-1",
        "authority_revision": 1,
        "authority_sha256": "b" * 64,
        "plan_sha256": digest(encoded(plan)),
        "mode": "strict",
        "scope": scope,
        "exceptions": [],
        "not_before": "2026-11-01T17:00:00Z",
        "expires_at": "2026-11-01T19:00:00Z",
        "testing_start": "2026-11-01T17:00:00Z",
        "testing_end": "2026-11-01T19:00:00Z",
        "max_executions": 2,
        "max_duration_seconds": 60,
        "max_http_dispatches": 100,
        "max_artifact_bytes": 1000000,
        "control": "local_offline",
        "credential_grants": [
            {
                "identity_id": "owner",
                "source": "value_env",
                "name": "NM1_OWNER",
                "revision": 1,
                "expires_at": "2026-11-01T19:00:00Z",
            }
        ],
    }
    issuer = {"id": "issuer-1", "key_id": "key-1"}
    anchor = TrustAnchor(
        "issuer-1",
        "key-1",
        Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes_raw(),
        frozenset({"approval", "contract"}),
        frozenset({"standalone", "map"}),
    )
    runtime = ValidationContext(
        "runner-1", "eng-1", "job-1", "attempt-1", 1, "standalone", NOW, 1, TOOL, "b" * 64
    )
    ledger = AuthorizationLedger(Journal(tmp_path / "journal.sqlite3"), monotonic=lambda: 0)
    ledger.set_state("issuer-1", "eng-1", 1, False, "b" * 64)
    receipt = approve(
        context, issuer, "standalone", "operator-1", "approval-1", "2026-11-01T17:59:00Z", SEED
    )
    contract = ledger.issue(
        receipt, (anchor,), issuer, SEED, "contract-1", "attempt-1", runtime, plan, case, execution
    )
    return dict(
        case=case,
        execution=execution,
        plan=plan,
        context=context,
        issuer=issuer,
        anchor=anchor,
        runtime=runtime,
        ledger=ledger,
        approval=receipt,
        contract=contract,
    )


def check(s, **changes):
    values = {
        "envelope": s["contract"],
        "approval": s["approval"],
        "plan": s["plan"],
        "case": s["case"],
        "execution": s["execution"],
        "anchors": (s["anchor"],),
        "context": s["runtime"],
    }
    values.update(changes)
    return validate(**values)


def test_positive_auxiliary_inventory_and_existing_case_digest(specimen):
    s = specimen
    assert check(s)["execution_index"] == 1
    assert s["plan"]["case_hash"] == digest(
        json.dumps(s["case"], sort_keys=True, separators=(",", ":")).encode()
    )
    assert s["plan"]["max_http_dispatches"] == 14
    assert {d["phase"] for d in s["plan"]["dispatches"]} == {
        "setup",
        "preflight",
        "resource",
        "verification",
        "reset",
    }
    assert any(
        d["identity_id"] == "skipped" and d["phase"] == "resource" for d in s["plan"]["dispatches"]
    )


def test_approval_reuse_with_bounded_count_and_single_use(specimen):
    s = specimen
    completed = s["ledger"].consume(
        s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
    )
    with pytest.raises(AuthorizationError, match="replayed"):
        s["ledger"].consume(
            s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
        )
    s["ledger"].finish(completed)
    next_context = replace(s["runtime"], attempt_id="attempt-2", fence=2)
    second = s["ledger"].issue(
        s["approval"],
        (s["anchor"],),
        s["issuer"],
        SEED,
        "contract-2",
        "attempt-2",
        next_context,
        s["plan"],
        s["case"],
        {},
    )
    assert decoded(unb64(second["payload"]))["execution_index"] == 2
    completed = s["ledger"].consume(
        second, s["approval"], s["plan"], s["case"], {}, (s["anchor"],), next_context
    )
    s["ledger"].finish(completed)
    with pytest.raises(AuthorizationError, match="exhausted"):
        s["ledger"].issue(
            s["approval"],
            (s["anchor"],),
            s["issuer"],
            SEED,
            "contract-3",
            "attempt-3",
            replace(next_context, attempt_id="attempt-3", fence=3),
            s["plan"],
            s["case"],
            {},
        )


def test_concurrent_consumption_has_one_winner(specimen):
    s = specimen

    def consume(_):
        try:
            s["ledger"].consume(
                s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
            )
            return True
        except AuthorizationError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(consume, range(4))) == 1


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("runner_id", "other"),
        ("engagement_id", "other"),
        ("job_id", "other"),
        ("attempt_id", "other"),
        ("fence", 2),
        ("origin", "map"),
        ("authority_revision", 2),
        ("authority_sha256", "c" * 64),
        ("revoked", True),
        ("stop_work", True),
        ("capabilities", frozenset()),
        ("tool_sha256", "c" * 64),
        ("now", NOW + timedelta(hours=2)),
        ("now", NOW - timedelta(hours=2)),
    ],
)
def test_trusted_runtime_mismatch_denies(specimen, name, value):
    with pytest.raises(AuthorizationError):
        check(specimen, context=replace(specimen["runtime"], **{name: value}))


@pytest.mark.parametrize(
    "path",
    [
        ("request", "url"),
        ("setup", 0, "request", "url"),
        ("identities", 0, "preflight", "url"),
        ("write_verification", "request", "url"),
        ("write_verification", "reset", "request", "url"),
    ],
)
def test_every_auxiliary_request_is_bound(specimen, path):
    case = copy.deepcopy(specimen["case"])
    cursor = case
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = "https://api.example.test/changed"
    with pytest.raises(AuthorizationError, match="execution_plan_changed"):
        check(specimen, case=case)


@pytest.mark.parametrize("mutation", ["payload", "signature", "purpose", "unknown_field"])
def test_envelope_tampering_denies(specimen, mutation):
    envelope = dict(specimen["contract"])
    if mutation == "payload":
        payload = decoded(unb64(envelope["payload"]))
        payload["fence"] = 9
        envelope["payload"] = b64(encoded(payload))
    elif mutation == "signature":
        envelope["signature"] = b64(b"x" * 64)
    elif mutation == "purpose":
        envelope["purpose"] = "approval"
    else:
        envelope["key_url"] = "https://untrusted.invalid"
    with pytest.raises(AuthorizationError):
        check(specimen, envelope=envelope)


@pytest.mark.parametrize(
    ("document", "schema", "reason"),
    [
        ("envelope", "vardr.authorization-envelope/2", "envelope_version_or_purpose"),
        ("contract", "vardr.authorization/2", "unsupported_schema"),
        ("approval", "vardr.execution-approval/2", "unsupported_schema"),
    ],
)
def test_unsupported_contract_versions_deny_before_consumption(specimen, document, schema, reason):
    s = specimen
    envelope, approval = copy.deepcopy(s["contract"]), copy.deepcopy(s["approval"])
    if document == "envelope":
        envelope["format"] = schema
    elif document == "contract":
        payload = decoded(unb64(envelope["payload"]))
        payload["schema"] = schema
        envelope = sign(payload, SEED, "contract")
    else:
        receipt = decoded(unb64(approval["payload"]))
        receipt["schema"] = schema
        approval = sign(receipt, SEED, "approval")
        payload = decoded(unb64(envelope["payload"]))
        payload["approval_sha256"] = digest(encoded(approval))
        envelope = sign(payload, SEED, "contract")
    with pytest.raises(AuthorizationError, match=reason):
        s["ledger"].consume(
            envelope,
            approval,
            s["plan"],
            s["case"],
            s["execution"],
            (s["anchor"],),
            s["runtime"],
        )
    with s["ledger"].journal._connection() as con:
        rows = con.execute("SELECT consumed FROM authorization_contracts").fetchall()
    assert len(rows) == 1 and rows[0]["consumed"] == 0
    assert check(s)["execution_index"] == 1


@pytest.mark.parametrize("anchor", [None, "revoked", "purpose", "origin", "bad_key"])
def test_only_enrolled_purpose_specific_trust(specimen, anchor):
    a = specimen["anchor"]
    anchors = (
        ()
        if anchor is None
        else (
            replace(
                a,
                **{"revoked": True}
                if anchor == "revoked"
                else {"purposes": frozenset()}
                if anchor == "purpose"
                else {"origins": frozenset()}
                if anchor == "origin"
                else {"public_key": b"x" * 32},
            ),
        )
    )
    with pytest.raises(AuthorizationError):
        check(specimen, anchors=anchors)


@pytest.mark.parametrize(
    "data",
    [
        b'{"x":1,"x":2}',
        b'{"nested":{"x":1,"x":2}}',
        b'{"x":NaN}',
        b"[] trailing",
        b"\xff",
        b"[" * 40 + b"]" * 40,
        b"",
    ],
)
def test_strict_wire_parser(data):
    with pytest.raises(AuthorizationError):
        decoded(data)


@pytest.mark.parametrize("value", ["=", "ab=", "a", "!", 1, "AB"])
def test_noncanonical_base64_denies(value):
    with pytest.raises(AuthorizationError):
        unb64(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_executions", True),
        ("max_duration_seconds", 0),
        ("mode", "disabled"),
        ("control", "fallback"),
        ("authority_sha256", "bad"),
        ("runner_id", "bad id"),
        ("not_before", "yesterday"),
        ("testing_end", "2026-11-01T16:00:00Z"),
        ("expires_at", "2026-11-01T16:00:00Z"),
        ("scope", None),
    ],
)
def test_malformed_approval_context(specimen, field, value):
    context = copy.deepcopy(specimen["context"])
    context[field] = value
    with pytest.raises(AuthorizationError):
        validate_context(context)


@pytest.mark.parametrize(
    "kind",
    [
        "scope",
        "grant_missing",
        "grant_expired",
        "count",
        "duration",
        "strict_exception",
        "origin_control",
    ],
)
def test_signed_but_prohibited_approval(specimen, kind):
    s = specimen
    context = copy.deepcopy(s["context"])
    if kind == "scope":
        context["scope"] = []
    elif kind == "grant_missing":
        context["credential_grants"] = []
    elif kind == "grant_expired":
        context["credential_grants"][0]["expires_at"] = "2026-11-01T17:00:00Z"
    elif kind == "count":
        context["max_http_dispatches"] = 1
    elif kind == "duration":
        context["max_duration_seconds"] = 1
    elif kind == "strict_exception":
        context["exceptions"] = [{**context["scope"][0], "reason": "operator exception"}]
    else:
        context["control"] = "managed_online"
    with pytest.raises(AuthorizationError):
        receipt = approve(
            context,
            s["issuer"],
            "standalone",
            "operator-1",
            "approval-2",
            "2026-11-01T17:59:00Z",
            SEED,
        )
        s["ledger"].issue(
            receipt,
            (s["anchor"],),
            s["issuer"],
            SEED,
            "other-contract",
            "attempt-2",
            replace(s["runtime"], attempt_id="attempt-2", fence=2),
            s["plan"],
            s["case"],
            {},
        )


def test_revocation_and_fence_persist(specimen):
    s = specimen
    next_context = replace(s["runtime"], attempt_id="attempt-2", fence=2)
    s["ledger"].issue(
        s["approval"],
        (s["anchor"],),
        s["issuer"],
        SEED,
        "contract-2",
        "attempt-2",
        next_context,
        s["plan"],
        s["case"],
        {},
    )
    with pytest.raises(AuthorizationError, match="stale_fence"):
        s["ledger"].consume(
            s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
        )
    s["ledger"].set_state("issuer-1", "eng-1", 2, True, "b" * 64)
    with pytest.raises(AuthorizationError):
        s["ledger"].consume(
            s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
        )
    with pytest.raises(AuthorizationError, match="state_rollback"):
        s["ledger"].set_state("issuer-1", "eng-1", 1, False, "b" * 64)


def test_managed_issuance_prototype_requires_verified_control(specimen):
    s = specimen
    context = {**s["context"], "control": "managed_online"}
    receipt = approve(
        context, s["issuer"], "map", "operator-1", "map-approval", "2026-11-01T17:59:00Z", SEED
    )
    runtime = replace(s["runtime"], origin="map", attempt_id="map-attempt", fence=2)
    with pytest.raises(AuthorizationError, match="managed_control_unsupported"):
        s["ledger"].issue(
            receipt,
            (s["anchor"],),
            s["issuer"],
            SEED,
            "map-contract",
            "map-attempt",
            runtime,
            s["plan"],
            s["case"],
            {},
        )
    runtime = replace(runtime, managed_status_verified=True)
    issued = s["ledger"].issue(
        receipt,
        (s["anchor"],),
        s["issuer"],
        SEED,
        "map-contract",
        "map-attempt",
        runtime,
        s["plan"],
        s["case"],
        {},
    )
    assert check(s, envelope=issued, approval=receipt, context=runtime)["origin"] == "map"


def test_advisory_exception_is_specific_signed_and_auditable(specimen):
    s = specimen
    context = copy.deepcopy(s["context"])
    context["mode"] = "advisory"
    removed = context["scope"].pop(0)
    context["exceptions"] = [{**removed, "reason": "Operator reviewed exact setup route"}]
    receipt = approve(
        context,
        s["issuer"],
        "standalone",
        "operator-1",
        "advisory-approval",
        "2026-11-01T17:59:00Z",
        SEED,
    )
    runtime = replace(s["runtime"], attempt_id="advisory-attempt", fence=2)
    contract = s["ledger"].issue(
        receipt,
        (s["anchor"],),
        s["issuer"],
        SEED,
        "advisory-contract",
        "advisory-attempt",
        runtime,
        s["plan"],
        s["case"],
        {},
    )
    assert check(s, envelope=contract, approval=receipt, context=runtime)


@pytest.mark.parametrize(
    "mutation",
    [
        "substitution",
        "capture",
        "literal_secret",
        "unknown_field",
        "private_bool",
        "unsafe",
        "cors",
        "headers",
        "query",
    ],
)
def test_unsupported_plan_inputs(specimen, mutation):
    case = copy.deepcopy(specimen["case"])
    execution = {}
    if mutation == "substitution":
        case["request"]["url"] += "/{{captured}}"
    elif mutation == "capture":
        case["setup"][0]["capture"] = {"value": "id"}
    elif mutation == "literal_secret":
        case["identities"][0]["credential"]["value"] = "fixture-secret"
    elif mutation == "unknown_field":
        case["automatic_scan"] = True
    elif mutation == "private_bool":
        execution["allow_private_targets"] = 1
    elif mutation == "unsafe":
        case["mutating"] = False
    elif mutation == "cors":
        case["cors"] = {}
    elif mutation == "headers":
        case["request"]["headers"] = {"Host": "elsewhere.invalid"}
    else:
        case["request"]["query_params"] = {"access_token": "fixture-secret"}
    with pytest.raises(AuthorizationError):
        compile_gate_plan(case, execution, tool_sha256=TOOL)


def test_active_attempt_blocks_reissuance_until_known_finished(specimen):
    s = specimen
    payload = s["ledger"].consume(
        s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
    )
    next_context = replace(s["runtime"], attempt_id="attempt-2", fence=2)
    with pytest.raises(AuthorizationError, match="attempt_in_flight"):
        s["ledger"].issue(
            s["approval"],
            (s["anchor"],),
            s["issuer"],
            SEED,
            "contract-2",
            "attempt-2",
            next_context,
            s["plan"],
            s["case"],
            {},
        )
    with pytest.raises(AuthorizationError, match="completion_owner_mismatch"):
        s["ledger"].finish({**payload, "attempt_id": "other-attempt"})
    s["ledger"].finish(payload)
    s["ledger"].finish(payload)  # idempotent finalization does not allocate another execution


def test_same_revision_cannot_hide_changed_authority_snapshot(specimen):
    s = specimen
    with pytest.raises(AuthorizationError, match="state_rollback"):
        s["ledger"].set_state("issuer-1", "eng-1", 1, False, "c" * 64)
    with pytest.raises(AuthorizationError, match="authority_snapshot_changed"):
        check(s, context=replace(s["runtime"], authority_sha256="c" * 64))


def test_remote_consumer_reserves_ordinal_and_rejects_duplicate_fence(specimen, tmp_path):
    s = specimen
    consumer = AuthorizationLedger(Journal(tmp_path / "consumer.sqlite3"), monotonic=lambda: 0)
    consumer.set_state("issuer-1", "eng-1", 1, False, "b" * 64)
    consumer.consume(
        s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
    )
    payload = decoded(unb64(s["contract"]["payload"]))
    duplicate = {
        **payload,
        "contract_id": "other-contract",
        "attempt_id": "attempt-2",
        "execution_index": 2,
    }
    with pytest.raises(AuthorizationError, match="attempt_in_flight"):
        consumer.consume(
            sign(duplicate, SEED, "contract"),
            s["approval"],
            s["plan"],
            s["case"],
            {},
            (s["anchor"],),
            replace(s["runtime"], attempt_id="attempt-2"),
        )
    consumer.finish(payload)
    with pytest.raises(AuthorizationError, match="consumption_state_failed"):
        consumer.consume(
            sign(duplicate, SEED, "contract"),
            s["approval"],
            s["plan"],
            s["case"],
            {},
            (s["anchor"],),
            replace(s["runtime"], attempt_id="attempt-2"),
        )


def test_remote_higher_fence_cannot_displace_active_attempt(specimen, tmp_path):
    s = specimen
    consumer = AuthorizationLedger(Journal(tmp_path / "consumer.sqlite3"), monotonic=lambda: 0)
    consumer.set_state("issuer-1", "eng-1", 1, False, "b" * 64)
    payload = consumer.consume(
        s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
    )
    second = {
        **payload,
        "contract_id": "contract-2",
        "attempt_id": "attempt-2",
        "execution_index": 2,
        "fence": 2,
    }
    runtime = replace(s["runtime"], attempt_id="attempt-2", fence=2)
    args = (
        sign(second, SEED, "contract"),
        s["approval"],
        s["plan"],
        s["case"],
        {},
        (s["anchor"],),
        runtime,
    )
    with pytest.raises(AuthorizationError, match="attempt_in_flight"):
        consumer.consume(*args)
    consumer.finish(payload)
    assert consumer.consume(*args)["fence"] == 2


def test_clock_rollback_and_unknown_prototype_schema_fail_closed(specimen, tmp_path):
    s = specimen
    with s["ledger"].journal._connection() as con:
        con.execute(
            "INSERT OR REPLACE INTO authorization_clock VALUES (1,?)",
            ((NOW + timedelta(minutes=1)).isoformat(),),
        )
    with pytest.raises(AuthorizationError, match="clock_rollback"):
        s["ledger"].consume(
            s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
        )
    journal = Journal(tmp_path / "old-prototype.sqlite3")
    with journal._connection() as con:
        con.execute("CREATE TABLE authorization_state (issuer TEXT)")
        con.execute("INSERT INTO authorization_state VALUES ('retained')")
    with pytest.raises(AuthorizationError, match="unsupported_prototype_ledger_schema"):
        AuthorizationLedger(journal)
    with journal._connection() as con:
        assert con.execute("SELECT issuer FROM authorization_state").fetchone()[0] == "retained"


@pytest.mark.parametrize("operation", ["consume", "issue"])
def test_expiry_denial_survives_ledger_reload_and_clock_rollback(specimen, operation):
    s = specimen
    later = replace(s["runtime"], now=NOW + timedelta(hours=2))
    if operation == "consume":
        with pytest.raises(AuthorizationError, match="expired_or_not_yet_valid"):
            s["ledger"].consume(
                s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), later
            )
    else:
        with pytest.raises(AuthorizationError, match="expired_or_not_yet_valid"):
            s["ledger"].issue(
                s["approval"],
                (s["anchor"],),
                s["issuer"],
                SEED,
                "expired-issue",
                "attempt-2",
                replace(later, attempt_id="attempt-2", fence=2),
                s["plan"],
                s["case"],
                {},
            )
    reloaded = AuthorizationLedger(s["ledger"].journal, monotonic=lambda: 0)
    with pytest.raises(AuthorizationError, match="clock_rollback"):
        reloaded.consume(
            s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
        )
    with reloaded.journal._connection() as con:
        assert con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0] == 0
        assert con.execute("SELECT issued FROM authorization_approvals").fetchone()[0] == 1


def test_clock_observation_uses_runtime_not_signed_payload_time(specimen):
    s = specimen
    forged = decoded(unb64(s["contract"]["payload"]))
    forged["issued_at"] = "2099-01-01T00:00:00Z"
    with pytest.raises(AuthorizationError, match="invalid_issuance_time"):
        s["ledger"].consume(
            sign(forged, SEED, "contract"),
            s["approval"],
            s["plan"],
            s["case"],
            {},
            (s["anchor"],),
            s["runtime"],
        )
    with s["ledger"].journal._connection() as con:
        assert (
            con.execute("SELECT observed FROM authorization_clock").fetchone()[0] == NOW.isoformat()
        )
    assert (
        s["ledger"].consume(
            s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
        )["execution_index"]
        == 1
    )


def test_clock_storage_failure_denies_before_permission_or_consumption(specimen):
    s = specimen
    with patch.object(s["ledger"].journal, "_connection", side_effect=sqlite3.OperationalError):
        with pytest.raises(AuthorizationError, match="clock_state_failed"):
            s["ledger"].consume(
                s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
            )
    with s["ledger"].journal._connection() as con:
        assert con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0] == 0


@pytest.mark.parametrize("operation", ["consume", "issue"])
@pytest.mark.parametrize("delay", ["writer_lock", "validation"])
def test_expiry_after_entry_cannot_reserve_and_survives_denial(
    specimen, tmp_path, operation, delay
):
    s = specimen
    ticks = [0.0]
    entered = threading.Event()

    def monotonic():
        entered.set()
        return ticks[0]

    ledger = AuthorizationLedger(Journal(tmp_path / "delayed.sqlite3"), monotonic=monotonic)
    ledger.set_state("issuer-1", "eng-1", 1, False, "b" * 64)
    permission = {**s["context"], "expires_at": "2026-11-01T18:00:01Z"}
    approval = approve(
        permission, s["issuer"], "standalone", "operator-1", "short", "2026-11-01T17:59:00Z", SEED
    )
    payload = decoded(unb64(s["contract"]["payload"]))
    contract = sign(
        {
            **payload,
            "approval_id": "short",
            "approval_sha256": digest(encoded(approval)),
            "expires_at": permission["expires_at"],
        },
        SEED,
        "contract",
    )

    def attempt():
        if operation == "consume":
            return ledger.consume(
                contract, approval, s["plan"], s["case"], {}, (s["anchor"],), s["runtime"]
            )
        return ledger.issue(
            approval,
            (s["anchor"],),
            s["issuer"],
            SEED,
            "short",
            "attempt-1",
            s["runtime"],
            s["plan"],
            s["case"],
            {},
        )

    if delay == "writer_lock":
        with ledger.journal._connection() as writer, ThreadPoolExecutor(max_workers=1) as pool:
            writer.execute("BEGIN IMMEDIATE")
            future = pool.submit(attempt)
            assert entered.wait(2) and not future.done()
            ticks[0] = 2.0  # Explicit trusted fixture clock, while writer lock remains held.
            writer.commit()
            with pytest.raises(AuthorizationError, match="expired_or_not_yet_valid"):
                future.result(timeout=5)
    else:
        from vardrrunner.authorization import ledger as module

        original = module.validate

        def delayed(*args):
            result = original(*args)
            ticks[0] = 2.0
            return result

        with patch.object(module, "validate", delayed):
            with pytest.raises(AuthorizationError, match="expired_or_not_yet_valid"):
                attempt()
    with ledger.journal._connection() as con:
        assert con.execute("SELECT count(*) FROM authorization_contracts").fetchone()[0] == 0
        assert con.execute("SELECT count(*) FROM authorization_approvals").fetchone()[0] == 0
        assert con.execute("SELECT count(*) FROM authorization_fences").fetchone()[0] == 0
        assert (
            con.execute("SELECT observed FROM authorization_clock").fetchone()[0]
            >= (NOW + timedelta(seconds=2)).isoformat()
        )
    # Subsequent rollback cannot restore the unused short contract's permission.
    ticks[0] = 0.0
    with pytest.raises(AuthorizationError, match="clock_rollback"):
        attempt()


def test_trusted_runtime_clock_and_corrupt_observation_fail_closed(specimen):
    s = specimen
    wall = [NOW + timedelta(hours=2)]
    ledger = AuthorizationLedger(s["ledger"].journal, clock=lambda: wall[0], monotonic=lambda: 0)
    args = (s["contract"], s["approval"], s["plan"], s["case"], {}, (s["anchor"],), s["runtime"])
    with pytest.raises(AuthorizationError, match="expired_or_not_yet_valid"):
        ledger.consume(*args)
    wall[0] = NOW
    with pytest.raises(AuthorizationError, match="clock_rollback"):
        ledger.consume(*args)
    with ledger.journal._connection() as con:
        con.execute("UPDATE authorization_clock SET observed='corrupt'")
    with pytest.raises(AuthorizationError, match="clock_state_failed"):
        ledger.consume(*args)
    wall[0] = NOW.replace(tzinfo=None)
    with pytest.raises(AuthorizationError, match="invalid_clock"):
        ledger.consume(*args)
