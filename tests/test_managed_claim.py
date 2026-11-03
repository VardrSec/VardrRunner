"""Pre-claim/local fencing tests: real policy and independent SQLite connections."""

import copy
import importlib.util
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from vardrrunner import config, credential_grants, handlers
from vardrrunner.authorization.claim import PROFILE, ClaimError, ClaimStore, ManagedEntry
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.journal import Journal, JournalError, Phase
from vardrrunner.recovery import reconcile

_spec = importlib.util.spec_from_file_location(
    "claim_fixture_only", Path(__file__).with_name("test_managed_gate.py")
)
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
NOW = _fixture.NOW
specimen = _fixture.specimen


@pytest.fixture
def entry_fixture(specimen, tmp_path, monkeypatch):
    from vardrrunner import execution_control

    # Exercise policy/journal decisions through an inert handler on every host.
    # Native Windows containment remains a separate, real OS acceptance gate.
    monkeypatch.setattr(execution_control, "available", lambda: True)
    s = specimen
    journal = Journal(config.journal_file())
    rpc, current_calls, consume_calls = [], [], []
    directory = tmp_path / "entry-result"
    directory.mkdir()

    def claim(body):
        rpc.append(copy.deepcopy(body))
        return {**copy.deepcopy(s.claim), "config": {"test_case": copy.deepcopy(s.case)}}

    def current(body):
        current_calls.append(True)
        return copy.deepcopy(s.reply)

    def consume(body):
        consume_calls.append(copy.deepcopy(body))
        return {
            **{
                k: v
                for k, v in s.reply.items()
                if k not in {"action", "lease_seconds", "lease_expires_at"}
            },
            "schema": "vardr.managed-consumption/1",
            "contract_sha256": body["contract_sha256"],
            "consumed": True,
        }

    def make(**kwargs):
        args = dict(
            journal=journal,
            map_origin="https://map.example.test",
            runner_id=s.context.runner_id,
            engagement_id=s.context.engagement_id,
            job_id=s.context.job_id,
            principal_sha256="f" * 64,
            case=s.case,
            execution=s.execution,
            allocated_seconds=30,
            anchors=s.anchors,
            claim=claim,
            current=current,
            consume=consume,
            clock=lambda: NOW + timedelta(seconds=s.ticks[0]),
            monotonic=lambda: s.ticks[0],
        )
        args.update(kwargs)
        return ManagedEntry(**args)

    return type(
        "Fixture",
        (),
        {
            "make": staticmethod(make),
            "rpc": rpc,
            "current_calls": current_calls,
            "consume_calls": consume_calls,
            "journal": journal,
            "directory": directory,
            "s": s,
        },
    )()


def state(f):
    with f.journal._connection() as con:
        return con.execute("SELECT state FROM managed_claim_intents").fetchone()[0]


def test_valid_reply_bound_before_consumption_and_no_sensitive_journal(entry_fixture):
    f = entry_fixture
    result = f.make().acquire(f.directory)
    assert len(f.rpc) == 1 and f.current_calls
    assert f.journal.get(result.run_id).phase == Phase.CLAIMED
    assert state(f) == "bound"
    with f.journal._connection() as con:
        table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE name='authorization_contracts'"
        ).fetchone()
        assert (
            not table
            or con.execute("SELECT count(*) FROM authorization_contracts").fetchone()[0] == 0
        )
        dump = "\n".join(con.iterdump())
    assert "x" * 40 not in dump
    assert "api.example.test" not in dump
    assert "vardr.authorization-envelope" not in dump
    assert f.s.claim["managed_authorization"]["approval"]["signature"] not in dump


@pytest.mark.parametrize("reason", ["missing", "revoked", "replaced", "expired"])
def test_preclaim_grant_denial_has_zero_rpc(entry_fixture, reason):
    f = entry_fixture
    _, source, name = handlers.credential_references(f.s.case)[0]
    origin = handlers._case_origins(f.s.case)[0]
    store = credential_grants.Store()
    if reason == "missing":
        config.CONFIG_FILE.write_text("{}")
    elif reason == "revoked":
        assert store.revoke(
            "https://map.example.test", f.s.context.engagement_id, origin, source, name
        )
    elif reason == "replaced":
        # Change after the first real check, while reserving the local intent.
        original = ClaimStore.prepare_send

        def replace_after_reservation(self, *args):
            original(self, *args)
            store.approve(
                "https://map.example.test", f.s.context.engagement_id, origin, source, name, 60
            )

        from unittest.mock import patch

        with (
            patch.object(ClaimStore, "prepare_send", replace_after_reservation),
            pytest.raises(ClaimError),
        ):
            f.make().acquire(f.directory)
        assert state(f) == "denied_before_rpc" and not f.rpc
        return
    else:
        f.s.ticks[0] = 61
    with pytest.raises(credential_grants.GrantError):
        f.make().acquire(f.directory)
    assert not f.rpc


@pytest.mark.parametrize("point", ["reserve", "prepare_send", "bind"])
def test_write_failures_never_retry_or_launch(entry_fixture, monkeypatch, point):
    f = entry_fixture

    def fail(*args):
        raise sqlite3.OperationalError("synthetic boundary write failure")

    original = getattr(ClaimStore, point)
    monkeypatch.setattr(ClaimStore, point, fail)
    with pytest.raises((sqlite3.Error, ClaimError)):
        f.make().acquire(f.directory)
    assert len(f.rpc) == (1 if point == "bind" else 0)
    monkeypatch.setattr(ClaimStore, point, original)
    with pytest.raises(AuthorizationError, match="existing_invocation"):
        f.make().acquire(f.directory)
    client = Mock()
    assert reconcile(f.journal, client, "https://map.example.test").deferred == 1
    assert not client.mock_calls


def test_lost_response_is_held_and_restart_never_calls_transport(entry_fixture):
    f = entry_fixture

    def lost(body):
        f.rpc.append(body)
        raise OSError("synthetic lost response")

    first = f.make(claim=lost)
    with pytest.raises(ClaimError, match="claim_outcome_unknown"):
        first.acquire(f.directory)
    assert len(f.rpc) == 1 and state(f) == "claim_unknown"
    with pytest.raises(AuthorizationError):
        first.acquire(f.directory)
    with pytest.raises(AuthorizationError):
        f.make().acquire(f.directory)
    assert len(f.rpc) == 1 and not f.current_calls


@pytest.mark.parametrize("change", ["case", "plan", "principal", "budget"])
def test_changed_reply_is_held_before_consumption(entry_fixture, change):
    f = entry_fixture

    def altered(body):
        f.rpc.append(body)
        reply = {**copy.deepcopy(f.s.claim), "config": {"test_case": copy.deepcopy(f.s.case)}}
        if change == "case":
            reply["config"]["test_case"]["request"]["url"] += "/changed"
        elif change == "plan":
            reply["managed_authorization"]["plan"]["tool_sha256"] = "0" * 64
        elif change == "principal":
            reply["managed_authorization"]["authority_snapshot"]["enrollment"][
                "principal_sha256"
            ] = "0" * 64
        else:
            reply["execution_control"]["duration_budget"]["allocated_seconds"] = True
        return reply

    with pytest.raises(ClaimError, match="handoff_held"):
        f.make(claim=altered).acquire(f.directory)
    assert state(f) == "reply_or_binding_unknown"
    with f.journal._connection() as con:
        table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE name='authorization_contracts'"
        ).fetchone()
        assert (
            not table
            or con.execute("SELECT count(*) FROM authorization_contracts").fetchone()[0] == 0
        )


def test_delayed_reply_keeps_presend_clock_pair(entry_fixture):
    f = entry_fixture

    def delayed(body):
        f.rpc.append(body)
        f.s.ticks[0] = 6
        return {**copy.deepcopy(f.s.claim), "config": {"test_case": copy.deepcopy(f.s.case)}}

    handle = f.make(claim=delayed).acquire(f.directory)
    assert handle.gate._anchor == NOW and handle.gate._entered == 0
    assert handle.gate.lease_deadline() == 10
    assert handle.gate.now() == NOW + timedelta(seconds=6)


def test_independent_connection_cas_has_one_winner(tmp_path):
    path = tmp_path / "cas.db"
    journal = Journal(path)
    fingerprint = {
        "plan_sha256": "a" * 64,
        "case_sha256": "b" * 64,
        "tool_sha256": "c" * 64,
        "association_sha256": "d" * 64,
    }
    record = journal.begin(
        job_id="one",
        backend_url="https://map.example.test",
        engagement_id="one",
        job_type="vardrgate_api_test",
        tool="vardrgate_api_test",
        target_source="case",
        command_profile={"managed_profile": PROFILE, **fingerprint},
    )
    stores = [ClaimStore(Journal(path)), ClaimStore(Journal(path))]
    barrier = threading.Barrier(2)

    def compete(store):
        barrier.wait()
        try:
            return store.reserve(
                record.run_id,
                fingerprint,
                {
                    "backend_url": "https://map.example.test",
                    "job_id": "one",
                    "engagement_id": "one",
                    "job_type": "vardrgate_api_test",
                    "tool": "vardrgate_api_test",
                    "target_source": "case",
                },
            )
        except ClaimError:
            return None

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(compete, stores))
    assert sum(value is not None for value in results) == 1
    with journal._connection() as con:
        assert con.execute("SELECT count(*) FROM managed_claim_intents").fetchone()[0] == 1


@pytest.mark.parametrize("phase", list(Phase))
def test_managed_recovery_deferred_in_every_phase(entry_fixture, phase):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    # Simulate interrupted on-disk phase/profile damage without promoting it.
    with f.journal._connection() as con:
        con.execute(
            "UPDATE runs SET phase=?,command_profile='{}' WHERE run_id=?",
            (phase.value, handle.run_id),
        )
    client = Mock()
    result = reconcile(f.journal, client, "https://map.example.test")
    assert not client.mock_calls
    if phase not in {Phase.DONE, Phase.FAILED, Phase.INTERRUPTED, Phase.STOP_WORK, Phase.SKIPPED}:
        assert result.deferred == 1


@pytest.mark.parametrize(
    "field", ["backend_url", "job_id", "engagement_id", "job_type", "tool", "target_source"]
)
def test_reserve_refuses_foreign_identity_without_mutating_run(tmp_path, field):
    journal = Journal(tmp_path / "foreign.db")
    fingerprint = {
        "plan_sha256": "a" * 64,
        "case_sha256": "b" * 64,
        "tool_sha256": "c" * 64,
        "association_sha256": "d" * 64,
    }
    identity = {
        "backend_url": "https://map.example.test",
        "job_id": "one",
        "engagement_id": "eng",
        "job_type": "vardrgate_api_test",
        "tool": "vardrgate_api_test",
        "target_source": "case",
    }
    record = journal.begin(**identity, command_profile={"managed_profile": PROFILE, **fingerprint})
    store = ClaimStore(journal)
    with journal._connection() as con:
        before = dict(con.execute("SELECT * FROM runs").fetchone())
    wrong = {**identity, field: "different"}
    with pytest.raises(AuthorizationError, match="managed_run_identity"):
        store.reserve(record.run_id, fingerprint, wrong)
    with journal._connection() as con:
        assert dict(con.execute("SELECT * FROM runs").fetchone()) == before
        assert con.execute("SELECT count(*) FROM managed_claim_intents").fetchone()[0] == 0


@pytest.mark.parametrize("change", ["expired", "replaced"])
def test_grants_changed_during_last_journal_read_prevent_rpc(entry_fixture, monkeypatch, change):
    f = entry_fixture
    original = f.journal.stop_requested
    calls = []

    def late(run_id):
        if not calls:
            calls.append(True)
            if change == "expired":
                f.s.ticks[0] = 61
            else:
                _, source, name = handlers.credential_references(f.s.case)[0]
                credential_grants.Store().approve(
                    "https://map.example.test",
                    f.s.context.engagement_id,
                    handlers._case_origins(f.s.case)[0],
                    source,
                    name,
                    60,
                )
        return original(run_id)

    monkeypatch.setattr(f.journal, "stop_requested", late)
    with pytest.raises(ClaimError, match="denied_before_rpc"):
        f.make().acquire(f.directory)
    assert calls and not f.rpc and state(f) == "denied_before_rpc"


def test_monotonic_sample_precedes_utc_and_pause_cannot_extend(entry_fixture):
    f = entry_fixture
    order = []

    def mono():
        order.append("mono")
        return f.s.ticks[0]

    def utc():
        order.append("utc")
        f.s.ticks[0] += 2
        return NOW + timedelta(seconds=f.s.ticks[0])

    handle = f.make(clock=utc, monotonic=mono).acquire(f.directory)
    assert order[:2] == ["mono", "utc"]
    assert handle.gate._entered == 0
    assert handle.gate.now() >= NOW + timedelta(seconds=4)
    assert handle.gate.lease_deadline() <= 8


def test_wall_rollback_during_rpc_preserves_trusted_anchor(entry_fixture, monkeypatch):
    from datetime import datetime

    from vardrrunner.authorization import managed

    f = entry_fixture
    wall = [NOW]

    class Rolled(datetime):
        @classmethod
        def now(cls, tz=None):
            return wall[0]

    def delayed(body):
        f.rpc.append(body)
        f.s.ticks[0] = 6
        wall[0] = NOW - timedelta(hours=1)
        return {**copy.deepcopy(f.s.claim), "config": {"test_case": copy.deepcopy(f.s.case)}}

    monkeypatch.setattr(managed, "datetime", Rolled)
    handle = f.make(claim=delayed, clock=lambda: wall[0]).acquire(f.directory)
    assert handle.gate.now() == NOW + timedelta(seconds=6)
    assert handle.gate.lease_deadline() == 10


def test_grant_revoked_during_remote_commit_is_held(entry_fixture):
    f = entry_fixture

    def commit_then_revoke(body):
        f.rpc.append(body)
        _, source, name = handlers.credential_references(f.s.case)[0]
        assert credential_grants.Store().revoke(
            "https://map.example.test",
            f.s.context.engagement_id,
            handlers._case_origins(f.s.case)[0],
            source,
            name,
        )
        return {**copy.deepcopy(f.s.claim), "config": {"test_case": copy.deepcopy(f.s.case)}}

    with pytest.raises(ClaimError, match="handoff_held"):
        f.make(claim=commit_then_revoke).acquire(f.directory)
    assert len(f.rpc) == 1 and state(f) == "reply_or_binding_unknown"


@pytest.mark.parametrize("point", ["prepare_send", "bind"])
def test_failure_after_local_commit_stays_fenced(entry_fixture, monkeypatch, point):
    f = entry_fixture
    original = getattr(ClaimStore, point)

    def after_commit(self, *args):
        original(self, *args)
        raise JournalError("synthetic postcommit interruption")

    monkeypatch.setattr(ClaimStore, point, after_commit)
    with pytest.raises(ClaimError):
        f.make().acquire(f.directory)
    assert len(f.rpc) == (0 if point == "prepare_send" else 1)
    with pytest.raises(AuthorizationError):
        f.make().acquire(f.directory)


def test_local_artifact_ceiling_is_stricter_than_signed(entry_fixture, monkeypatch):
    from vardrrunner import launch_guard, resources
    from vardrrunner.authorization.codec import sign, unb64

    f = entry_fixture
    monkeypatch.setenv("VARDRRUNNER_MAX_ARTIFACT_MB", "1")
    wire = f.s.claim["managed_authorization"]
    approval = json.loads(unb64(wire["approval"]["payload"]))
    approval["context"]["max_artifact_bytes"] = 3 * 1024**2
    wire["approval"] = sign(approval, bytes(range(32)), "approval")
    contract = json.loads(unb64(wire["contract"]["payload"]))
    contract["approval_sha256"] = digest(encoded(wire["approval"]))
    wire["contract"] = sign(contract, bytes(range(32, 64)), "contract")
    handle = f.make().acquire(f.directory)

    def local_artifact(self, targets, directory, config, **kwargs):
        with launch_guard.boundary():
            path = directory / "vardrgate_result.json"
            path.write_bytes(b" " * (2 * 1024**2))
        return path

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", local_artifact)
    with pytest.raises(resources.ResourceLimitError):
        handle.execute(f.directory)
    assert (f.directory / "vardrgate_result.json").stat().st_size == 2 * 1024**2
    record = f.journal.get(handle.run_id)
    assert record.phase == Phase.EXECUTING and record.artifact_sha256 is None
    assert state(f) == "held_after_claim"
    client = Mock()
    assert reconcile(f.journal, client, "https://map.example.test").deferred == 1
    assert not client.mock_calls


def test_execute_write_failure_cannot_reuse_handle(entry_fixture, monkeypatch):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    original = f.journal.transition

    def fail(run_id, phase, **kwargs):
        if phase == Phase.EXECUTING:
            raise JournalError("synthetic execution write failure")
        return original(run_id, phase, **kwargs)

    monkeypatch.setattr(f.journal, "transition", fail)
    with pytest.raises(JournalError):
        handle.execute(f.directory)
    with pytest.raises(AuthorizationError, match="single_managed_execution"):
        handle.execute(f.directory)


def test_acquired_grant_replacement_cannot_renew_attempt(entry_fixture, monkeypatch):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    before = handle.gate.until
    _, source, name = handlers.credential_references(f.s.case)[0]
    credential_grants.Store().approve(
        "https://map.example.test",
        f.s.context.engagement_id,
        handlers._case_origins(f.s.case)[0],
        source,
        name,
        600,
    )
    executed = Mock(side_effect=AssertionError("native handler must not execute"))
    monkeypatch.setattr(handlers.VardrGateHandler, "execute", executed)
    with pytest.raises(credential_grants.GrantError, match="replaced"):
        handle.execute(f.directory)
    assert handle.gate.until == before
    executed.assert_not_called()
    assert state(f) == "held_after_claim" and len(f.rpc) == 1
    with f.journal._connection() as con:
        assert con.execute("SELECT count(*) FROM authorization_contracts").fetchone()[0] == 0


def test_local_stop_before_rpc_is_durably_denied(entry_fixture, monkeypatch):
    f = entry_fixture
    original = ClaimStore.prepare_send

    def stop(self, run_id, *args):
        original(self, run_id, *args)
        self.journal.request_stop(run_id)

    monkeypatch.setattr(ClaimStore, "prepare_send", stop)
    with pytest.raises(ClaimError, match="denied_before_rpc"):
        f.make().acquire(f.directory)
    assert not f.rpc and state(f) == "denied_before_rpc"


def inert_artifact(monkeypatch):
    from vardrrunner import launch_guard

    def inert(self, targets, directory, config, **kwargs):
        with launch_guard.boundary():
            output = directory / "vardrgate_result.json"
            output.write_text("{}")
        return output

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", inert)


def test_consumption_ack_is_durable_before_inert_launch(entry_fixture, monkeypatch):
    f = entry_fixture
    inert_artifact(monkeypatch)
    handle = f.make().acquire(f.directory)
    assert handle.execute(f.directory).is_file()
    assert state(f) == "consume_acknowledged" and len(f.consume_calls) == 1
    client = Mock()
    assert reconcile(f.journal, client, f.s.claim["execution_control"]["origin"]).deferred == 1
    assert not client.mock_calls


@pytest.mark.parametrize("failure", ["missing", "lost", "binding", "bool_fence", "late"])
def test_unacknowledged_consumption_never_dispatches_or_retries(
    entry_fixture, monkeypatch, failure
):
    f = entry_fixture
    native = Mock(side_effect=AssertionError("must not dispatch"))
    monkeypatch.setattr(handlers.VardrGateHandler, "execute", native)
    calls = []

    def callback(body):
        calls.append(body)
        if failure == "lost":
            raise OSError("synthetic lost post-commit acknowledgement")
        reply = {
            **{
                k: v
                for k, v in f.s.reply.items()
                if k not in {"action", "lease_seconds", "lease_expires_at"}
            },
            "schema": "vardr.managed-consumption/1",
            "consumed": True,
            "contract_sha256": body["contract_sha256"],
        }
        if failure == "binding":
            reply["contract_sha256"] = "0" * 64
        elif failure == "bool_fence":
            reply["fence"] = True
        elif failure == "late":
            f.s.ticks[0] = 11
        return reply

    handle = f.make(consume=None if failure == "missing" else callback).acquire(f.directory)
    with pytest.raises(AuthorizationError):
        handle.execute(f.directory)
    assert state(f) == "held_after_claim"
    with pytest.raises(AuthorizationError, match="single_managed_execution"):
        handle.execute(f.directory)
    with pytest.raises(AuthorizationError, match="existing_invocation"):
        f.make().acquire(f.directory)
    assert len(calls) == (0 if failure == "missing" else 1)
    native.assert_not_called()
    with f.journal._connection() as con:
        assert con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0] == 1


@pytest.mark.parametrize("point", ["before_send", "after_reply"])
def test_consumption_journal_failure_holds_without_dispatch(entry_fixture, monkeypatch, point):
    f = entry_fixture
    native = Mock(side_effect=AssertionError("must not dispatch"))
    monkeypatch.setattr(handlers.VardrGateHandler, "execute", native)
    original = ClaimStore.consumption

    def failure(self, run_id, owner, *, acknowledged):
        if acknowledged == (point == "after_reply"):
            raise JournalError("synthetic consumption journal failure")
        original(self, run_id, owner, acknowledged=acknowledged)

    monkeypatch.setattr(ClaimStore, "consumption", failure)
    handle = f.make().acquire(f.directory)
    with pytest.raises(JournalError):
        handle.execute(f.directory)
    assert len(f.consume_calls) == (1 if point == "after_reply" else 0)
    assert state(f) == "held_after_claim"
    native.assert_not_called()


def test_portable_fixture_does_not_bypass_real_platform_denial(entry_fixture, monkeypatch):
    from vardrrunner import execution_control

    f = entry_fixture
    monkeypatch.setattr(execution_control, "available", lambda: False)
    with pytest.raises(AuthorizationError, match="controlled_process_tree_unsupported"):
        f.make().acquire(f.directory)
    assert not f.rpc and not f.consume_calls


def test_acknowledgement_marker_survives_later_hold(entry_fixture, monkeypatch):
    f = entry_fixture
    inert_artifact(monkeypatch)
    handle = f.make().acquire(f.directory)
    handle.execute(f.directory)
    f.make().store.hold(handle.run_id, handle._owner, "held_after_claim")
    with f.journal._connection() as con:
        row = con.execute("SELECT * FROM managed_claim_intents").fetchone()
        assert row["state"] == "held_after_claim"
        assert row["consumption_sent"] == row["consumption_acknowledged"] == 1


def test_existing_claim_schema_gets_additive_audit_markers(entry_fixture):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    with f.journal._connection() as con:
        con.execute("ALTER TABLE managed_claim_intents DROP COLUMN consumption_sent")
        con.execute("ALTER TABLE managed_claim_intents DROP COLUMN consumption_acknowledged")
    store = ClaimStore(f.journal)
    with store.journal._connection() as con:
        row = con.execute("SELECT * FROM managed_claim_intents").fetchone()
        assert row["run_id"] == handle.run_id and row["state"] == "bound"
        assert row["consumption_sent"] == row["consumption_acknowledged"] == 0
