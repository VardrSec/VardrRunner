"""Explicit finalization/observation; native dispatch is an inert fixture only."""

import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vardrrunner import execution_control, handlers, launch_guard
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.results import ResultStore, receipt, reconcile
from vardrrunner.journal import JournalError, Phase

_spec = importlib.util.spec_from_file_location(
    "result_claim_fixture", Path(__file__).with_name("test_managed_claim.py")
)
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
entry_fixture = _fixture.entry_fixture
specimen = _fixture.specimen


@pytest.fixture
def result_fixture(entry_fixture, monkeypatch):
    f = entry_fixture
    case_hash = f.s.claim["execution_control"]["target_budget"]["binding"]["case_sha256"]
    raw = {
        "test_case_id": f.s.case["id"],
        "case_hash": case_hash,
        "executions": [],
        "findings": [],
        "preflight": [],
    }

    def inert(self, targets, directory, config, **kwargs):
        with launch_guard.boundary():
            output = directory / "vardrgate_result.json"
            output.write_text(json.dumps(raw))
        return output

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", inert)
    handle = f.make().acquire(f.directory)
    state = {"result": None, "completion": None}
    calls = []
    binding = {
        k: handle.gate.binding[k]
        for k in ("origin", "job_id", "runner_id", "contract_id", "attempt_id", "fence")
    }
    binding["contract_sha256"] = digest(encoded(handle.gate.envelope))

    def submit(body):
        calls.append("submit")
        state["result"] = {
            "schema": "vardr.managed-result-receipt/1",
            **binding,
            "artifact_sha256": body["artifact_sha256"],
            "case_sha256": case_hash,
            "receipt_sha256": receipt(binding, body["artifact_sha256"], case_hash),
            "evidence_created": 0,
            "scan_items_created": 0,
        }
        return copy.deepcopy(state["result"])

    def finish(body):
        calls.append("finish")
        assert body["termination_confirmed"] is True
        state["completion"] = {
            "schema": "vardr.managed-completion/1",
            **binding,
            "receipt_sha256": body["receipt_sha256"],
            "outcome": body["outcome"],
            "capacity_reserved": False,
        }
        return copy.deepcopy(state["completion"])

    def inspect(body):
        calls.append("inspect")
        assert "token" not in body
        return {
            "schema": "vardr.managed-reconciliation/1",
            **binding,
            "consumed": True,
            "capacity_reserved": state["completion"] is None,
            "execution_state": state["completion"]["outcome"] if state["completion"] else "active",
            **copy.deepcopy(state),
        }

    return SimpleNamespace(
        f=f,
        handle=handle,
        raw=raw,
        submit=submit,
        finish=finish,
        inspect=inspect,
        calls=calls,
        state=state,
    )


def consumed(f):
    with f.journal._connection() as con:
        return con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0]


def test_known_return_then_receipts_close_without_refund(result_fixture):
    t = result_fixture
    t.handle.execute(t.f.directory)
    t.handle.finalize(t.submit, t.finish)
    assert t.calls == ["submit", "finish"]
    assert t.f.journal.get(t.handle.run_id).phase == Phase.DONE
    assert consumed(t.f) == 2
    with pytest.raises(AuthorizationError):
        t.handle.finalize(t.submit, t.finish)
    assert t.calls == ["submit", "finish"]
    assert reconcile(t.f.journal, t.handle.run_id, t.inspect) == "terminal_receipt_observed"
    with t.f.journal._connection() as con:
        dump = "\n".join(con.iterdump())
    assert "x" * 40 not in dump and "vardr.authorization-envelope" not in dump


def test_failed_preflight_never_finalizes_as_success(result_fixture):
    t = result_fixture
    t.raw["preflight"] = [{"status": "failed"}]
    t.handle.execute(t.f.directory)
    t.handle.finalize(t.submit, t.finish)
    assert t.state["completion"]["outcome"] == "failed"
    assert t.f.journal.get(t.handle.run_id).phase == Phase.FAILED


@pytest.mark.parametrize(
    "failure", ["no_execution", "uncertain_native", "changed", "missing", "symlink"]
)
def test_no_known_valid_artifact_never_sends(result_fixture, monkeypatch, failure):
    t = result_fixture
    if failure == "uncertain_native":

        def uncertain(*args, **kwargs):
            raise execution_control.ExecutionStopped("synthetic_uncertainty", False)

        monkeypatch.setattr(handlers.VardrGateHandler, "execute", uncertain)
        with pytest.raises(execution_control.ExecutionStopped):
            t.handle.execute(t.f.directory)
    elif failure != "no_execution":
        path = t.handle.execute(t.f.directory)
        if failure == "changed":
            path.write_text("changed")
        elif failure == "missing":
            path.unlink()
        else:
            renamed = path.with_suffix(".retained")
            path.rename(renamed)
            path.symlink_to(renamed)
    with pytest.raises(AuthorizationError):
        t.handle.finalize(t.submit, t.finish)
    assert not t.calls


@pytest.mark.parametrize("lost", ["submit_before", "submit_after", "finish_after"])
def test_lost_reply_only_allows_explicit_observation(result_fixture, lost):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def submit(body):
        if lost == "submit_before":
            raise OSError("synthetic no commit")
        reply = t.submit(body)
        if lost == "submit_after":
            raise OSError("synthetic post-commit loss")
        return reply

    def finish(body):
        t.finish(body)
        raise OSError("synthetic terminal commit with lost reply")

    with pytest.raises(AuthorizationError, match="outcome_unknown"):
        t.handle.finalize(submit, finish if lost == "finish_after" else t.finish)
    with pytest.raises(AuthorizationError):
        t.handle.finalize(t.submit, t.finish)
    before = list(t.calls)
    observed = reconcile(t.f.journal, t.handle.run_id, t.inspect)
    assert t.calls == before + ["inspect"]
    if lost == "finish_after":
        assert observed == "terminal_receipt_observed" and consumed(t.f) == 2
        assert t.f.journal.get(t.handle.run_id).phase == Phase.DONE
    else:
        assert observed == (
            "held_no_receipt" if lost == "submit_before" else "held_result_observed"
        )
        assert consumed(t.f) == 1
        assert t.f.journal.get(t.handle.run_id).phase != Phase.DONE


@pytest.mark.parametrize(
    "phase,field,value",
    [
        ("submit", "contract_id", "other"),
        ("submit", "receipt_sha256", "0" * 64),
        ("submit", "fence", True),
        ("submit", "evidence_created", True),
        ("submit", "extra", "unknown"),
        ("finish", "outcome", "failed"),
        ("finish", "capacity_reserved", 0),
        ("finish", "fence", True),
    ],
)
def test_changed_receipts_never_close_local_attempt(result_fixture, phase, field, value):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def mutate(callback):
        def invoke(body):
            reply = callback(body)
            reply[field] = value
            return reply

        return invoke

    with pytest.raises(AuthorizationError):
        t.handle.finalize(
            mutate(t.submit) if phase == "submit" else t.submit,
            mutate(t.finish) if phase == "finish" else t.finish,
        )
    assert consumed(t.f) == 1 and t.f.journal.get(t.handle.run_id).phase != Phase.DONE
    if phase == "submit":
        assert t.calls == ["submit"]


@pytest.mark.parametrize("point", ["reserve", "result_ack", "finish_send", "close"])
def test_journal_failures_never_replay_remote_writes(result_fixture, monkeypatch, point):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def fail(*args, **kwargs):
        raise JournalError("synthetic receipt journal failure")

    monkeypatch.setattr(ResultStore, point, fail)
    with pytest.raises(JournalError):
        t.handle.finalize(t.submit, t.finish)
    assert len(t.calls) == {"reserve": 0, "result_ack": 1, "finish_send": 1, "close": 2}[point]
    assert t.f.journal.get(t.handle.run_id).phase != Phase.DONE


@pytest.mark.parametrize(
    "change", ["binding", "outcome", "missing_result", "capacity", "unavailable"]
)
def test_reconciliation_never_infers_terminal_from_inconsistent_state(result_fixture, change):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def lost(body):
        t.finish(body)
        raise OSError("lost")

    with pytest.raises(AuthorizationError):
        t.handle.finalize(t.submit, lost)

    def wrong(body):
        if change == "unavailable":
            raise OSError("offline")
        reply = t.inspect(body)
        if change == "binding":
            reply["contract_id"] = "foreign"
        elif change == "outcome":
            reply["completion"]["outcome"] = "failed"
        elif change == "missing_result":
            reply["result"] = None
        else:
            reply["capacity_reserved"] = True
        return reply

    with pytest.raises(AuthorizationError):
        reconcile(t.f.journal, t.handle.run_id, wrong)
    assert consumed(t.f) == 1


def test_missing_intent_is_not_remote_recovery_permission(result_fixture):
    t = result_fixture
    callback = Mock()
    with pytest.raises(AuthorizationError, match="intent_missing"):
        reconcile(t.f.journal, t.handle.run_id, callback)
    callback.assert_not_called()


@pytest.mark.parametrize("corrupt", ["binding", "claim"])
def test_corrupt_local_binding_is_refused_before_observation(result_fixture, corrupt):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def lost(body):
        t.submit(body)
        raise OSError("lost")

    with pytest.raises(AuthorizationError):
        t.handle.finalize(lost, t.finish)
    with t.f.journal._connection() as con:
        if corrupt == "binding":
            binding = json.loads(ResultStore(t.f.journal).get(t.handle.run_id)["binding"])
            binding["origin"] = "https://foreign.example.test"
            con.execute("UPDATE managed_result_intents SET binding=?", (json.dumps(binding),))
        else:
            con.execute("UPDATE managed_claim_intents SET fence=fence+1")
    callback = Mock()
    with pytest.raises(AuthorizationError, match="intent_binding"):
        reconcile(t.f.journal, t.handle.run_id, callback)
    callback.assert_not_called()


def test_terminal_receipt_disappearance_is_not_reopened(result_fixture):
    t = result_fixture
    t.handle.execute(t.f.directory)
    t.handle.finalize(t.submit, t.finish)
    t.state["completion"] = None
    with pytest.raises(AuthorizationError, match="terminal_receipt_missing"):
        reconcile(t.f.journal, t.handle.run_id, t.inspect)
    assert consumed(t.f) == 2 and t.f.journal.get(t.handle.run_id).phase == Phase.DONE
