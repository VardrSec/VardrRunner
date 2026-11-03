"""Known native-stop proof decisions; no native process is dispatched here."""

import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vardrrunner import execution_control, handlers, launch_guard
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.stops import CANCEL_CAUSES, CAUSES, StopStore, reconcile, stop_hash
from vardrrunner.journal import JournalError, Phase

_spec = importlib.util.spec_from_file_location(
    "stop_claim_fixture", Path(__file__).with_name("test_managed_claim.py")
)
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
entry_fixture = _fixture.entry_fixture
specimen = _fixture.specimen


@pytest.fixture
def stopped(entry_fixture, monkeypatch):
    f = entry_fixture
    proof = {"confirmed": True, "cause": "local_emergency_stop"}

    def inert(self, targets, directory, config, **kwargs):
        with launch_guard.boundary():
            pass
        # Native observer writes happen after the grant writer boundary ends.
        # This public fixture PID is journal metadata only, never signaled.
        f.journal.transition(handle.run_id, Phase.EXECUTING, pid=600001)
        (directory / "partial.json").write_text('{"partial":true}')
        raise execution_control.ExecutionStopped(proof["cause"], proof["confirmed"], pid=600001)

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", inert)
    handle = f.make().acquire(f.directory)
    binding = {
        k: handle.gate.binding[k]
        for k in ("origin", "job_id", "runner_id", "contract_id", "attempt_id", "fence")
    }
    binding["contract_sha256"] = digest(encoded(handle.gate.envelope))
    calls, state = [], {"stop": None}

    def send(body):
        calls.append("send")
        state["stop"] = {
            "schema": "vardr.managed-stop-receipt/1",
            **binding,
            "outcome": body["outcome"],
            "cause": body["cause"],
            "receipt_sha256": stop_hash(binding, body["outcome"], body["cause"]),
            "capacity_reserved": False,
        }
        return copy.deepcopy(state["stop"])

    def inspect(body):
        calls.append("inspect")
        assert "token" not in body
        return {
            "schema": "vardr.managed-stop-observation/1",
            **binding,
            "consumed": True,
            "capacity_reserved": state["stop"] is None,
            "execution_state": state["stop"]["outcome"] if state["stop"] else "uncertain",
            "stop": copy.deepcopy(state["stop"]),
        }

    def execute():
        with pytest.raises(execution_control.ExecutionStopped):
            handle.execute(f.directory)

    return SimpleNamespace(
        f=f,
        handle=handle,
        proof=proof,
        calls=calls,
        state=state,
        send=send,
        inspect=inspect,
        execute=execute,
    )


def consumed(f):
    with f.journal._connection() as con:
        return con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0]


@pytest.mark.parametrize("cause", sorted(CAUSES))
def test_only_known_confirmed_stop_can_report_and_close(stopped, cause):
    t = stopped
    t.proof["cause"] = cause
    t.execute()
    assert t.f.journal.get(t.handle.run_id).pid == 600001
    assert (t.f.directory / "partial.json").read_text() == '{"partial":true}'
    t.handle.report_stop(t.send)
    record = t.f.journal.get(t.handle.run_id)
    assert record.phase == (Phase.STOP_WORK if cause in CANCEL_CAUSES else Phase.FAILED)
    assert record.failure_reason == cause and consumed(t.f) == 2
    assert t.calls == ["send"]
    with pytest.raises(AuthorizationError):
        t.handle.report_stop(t.send)
    assert t.calls == ["send"]
    assert reconcile(t.f.journal, t.handle.run_id, t.inspect) == "terminal_stop_receipt_observed"


@pytest.mark.parametrize(
    "confirmed,cause",
    [
        (False, "tool_timeout"),
        (1, "tool_timeout"),
        (True, "execution_state_uncertain"),
        (True, "untrusted raw error"),
    ],
)
def test_uncertain_or_untyped_proof_retains_pid_and_cannot_report(stopped, confirmed, cause):
    t = stopped
    t.proof.update(confirmed=confirmed, cause=cause)
    t.execute()
    assert t.f.journal.get(t.handle.run_id).pid == 600001
    with pytest.raises(AuthorizationError, match="known_native_stop_required"):
        t.handle.report_stop(t.send)
    assert not t.calls and consumed(t.f) == 1


def test_no_execution_or_missing_consumption_ack_is_not_stop_permission(stopped):
    t = stopped
    with pytest.raises(AuthorizationError, match="known_native_stop_required"):
        t.handle.report_stop(t.send)
    t.execute()
    with t.f.journal._connection() as con:
        con.execute("UPDATE managed_claim_intents SET consumption_acknowledged=0")
    with pytest.raises(AuthorizationError, match="not_owned"):
        t.handle.report_stop(t.send)
    assert not t.calls


@pytest.mark.parametrize("committed", [False, True])
def test_lost_stop_response_never_retries_or_infers_termination(stopped, committed):
    t = stopped
    t.execute()

    def lost(body):
        if committed:
            t.send(body)
        raise OSError("synthetic uncertain transport")

    with pytest.raises(AuthorizationError, match="outcome_unknown"):
        t.handle.report_stop(lost)
    with pytest.raises(AuthorizationError):
        t.handle.report_stop(t.send)
    before = list(t.calls)
    result = reconcile(t.f.journal, t.handle.run_id, t.inspect)
    assert t.calls == before + ["inspect"]
    assert result == ("terminal_stop_receipt_observed" if committed else "held_no_stop_receipt")
    assert consumed(t.f) == (2 if committed else 1)


@pytest.mark.parametrize(
    "field,value",
    [
        ("contract_id", "foreign"),
        ("cause", "tool_timeout"),
        ("fence", True),
        ("capacity_reserved", 0),
        ("extra", "value"),
    ],
)
def test_malformed_stop_receipt_does_not_close(stopped, field, value):
    t = stopped
    t.execute()

    def changed(body):
        result = t.send(body)
        result[field] = value
        return result

    with pytest.raises(AuthorizationError):
        t.handle.report_stop(changed)
    assert consumed(t.f) == 1
    assert t.f.journal.get(t.handle.run_id).phase == Phase.FINALIZING


@pytest.mark.parametrize("point", ["reserve", "close"])
def test_local_stop_write_failure_never_duplicates_remote_send(stopped, monkeypatch, point):
    t = stopped
    t.execute()

    def fail(*args, **kwargs):
        raise JournalError("synthetic local stop write failure")

    monkeypatch.setattr(StopStore, point, fail)
    with pytest.raises(JournalError):
        t.handle.report_stop(t.send)
    assert t.calls == ([] if point == "reserve" else ["send"])
    assert consumed(t.f) == 1


def test_failed_pid_clear_does_not_establish_report_right(stopped, monkeypatch):
    t = stopped
    original = t.f.journal.transition

    def fail(run_id, phase, **kwargs):
        if kwargs.get("last_event") == "managed_native_stop_confirmed":
            raise JournalError("synthetic stop proof write failure")
        return original(run_id, phase, **kwargs)

    monkeypatch.setattr(t.f.journal, "transition", fail)
    t.execute()
    with pytest.raises(AuthorizationError):
        t.handle.report_stop(t.send)
    assert not t.calls and t.f.journal.get(t.handle.run_id).pid == 600001


@pytest.mark.parametrize("change", ["binding", "capacity", "state", "missing", "unavailable"])
def test_stop_observation_cannot_close_on_inconsistent_state(stopped, change):
    t = stopped
    t.execute()

    def lost(body):
        t.send(body)
        raise OSError("lost")

    with pytest.raises(AuthorizationError):
        t.handle.report_stop(lost)

    def wrong(body):
        if change == "unavailable":
            raise OSError("offline")
        result = t.inspect(body)
        if change == "binding":
            result["contract_id"] = "foreign"
        elif change == "capacity":
            result["capacity_reserved"] = True
        elif change == "state":
            result["execution_state"] = "active"
        else:
            result["stop"]["receipt_sha256"] = "0" * 64
        return result

    with pytest.raises(AuthorizationError):
        reconcile(t.f.journal, t.handle.run_id, wrong)
    assert consumed(t.f) == 1


def test_missing_or_corrupt_stop_intent_never_contacts_server(stopped):
    t = stopped
    callback = Mock()
    with pytest.raises(AuthorizationError, match="intent_missing"):
        reconcile(t.f.journal, t.handle.run_id, callback)
    callback.assert_not_called()
    t.execute()

    def lost(body):
        raise OSError("lost")

    with pytest.raises(AuthorizationError):
        t.handle.report_stop(lost)
    with t.f.journal._connection() as con:
        con.execute("UPDATE managed_stop_intents SET receipt_sha256=?", ("0" * 64,))
    with pytest.raises(AuthorizationError, match="intent_binding"):
        reconcile(t.f.journal, t.handle.run_id, callback)
    callback.assert_not_called()


def test_stop_receipt_disappearance_never_reopens_a_terminal_attempt(stopped):
    t = stopped
    t.execute()
    t.handle.report_stop(t.send)
    t.state["stop"] = None
    with pytest.raises(AuthorizationError, match="terminal_stop_receipt_missing"):
        reconcile(t.f.journal, t.handle.run_id, t.inspect)
    assert consumed(t.f) == 2
