"""Authenticated terminal metadata closes exact holds, never execution rights."""

import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import typer

from tests.test_managed_observations import entry_fixture as entry_fixture
from tests.test_managed_observations import lost_claim, public_reply
from tests.test_managed_observations import result_fixture as result_fixture
from tests.test_managed_observations import specimen as specimen
from tests.test_managed_observations import stopped as stopped
from vardrrunner import api, config, identity
from vardrrunner.authorization import observations, reconciliation, results, stops
from vardrrunner.authorization.claim import ClaimError, ClaimStore
from vardrrunner.authorization.codec import AuthorizationError
from vardrrunner.authorization.reconciliation import local_holds, reconcile_managed, retire_preclaim
from vardrrunner.commands import managed_recovery
from vardrrunner.journal import Phase


def host_reply(f, run_id, gate=None, *, consumed=False):
    reply = public_reply(f, run_id, gate)
    reply["claim"]["consumed"] = consumed
    binding = observations.binding(reply)
    reply.update(
        execution_state="failed",
        capacity_reserved=False,
        stop={
            "schema": "vardr.managed-stop-receipt/1",
            **binding,
            "outcome": "failed",
            "cause": "observed_exit",
            "receipt_sha256": stops.stop_hash(binding, "failed", "observed_exit"),
            "capacity_reserved": False,
        },
    )
    return reply


def test_lost_claim_retirement_preserves_unconsumed_unknown_tombstone(entry_fixture):
    f = entry_fixture
    facade = lost_claim(f)
    reply = host_reply(f, facade.run_id)
    assert local_holds(f.journal) > 0
    assert (
        reconcile_managed(f.journal, facade.run_id, f.s.context.runner_id, lambda _: reply)
        == "terminal_host_exit_observed"
    )
    assert local_holds(f.journal) == 0 and not f.journal.unfinished()
    with f.journal._connection() as con:
        claim = con.execute("SELECT * FROM managed_claim_intents").fetchone()
    assert claim["state"] == "host_exit_observed" and claim["contract"] is None
    assert claim["consumption_sent"] == claim["consumption_acknowledged"] == 0
    assert f.journal.get(facade.run_id).phase == Phase.FAILED
    with pytest.raises(AuthorizationError, match="already_reserved"):
        f.make().acquire(f.directory)
    assert len(f.rpc) == 1
    assert not f.journal.unfinished() and local_holds(f.journal) == 0
    assert (
        reconcile_managed(f.journal, facade.run_id, f.s.context.runner_id, lambda _: reply)
        == "terminal_host_exit_observed"
    )


def test_host_retirement_closes_exact_ledger_without_reconstructing_native_proof(stopped):
    t = stopped
    t.proof["confirmed"] = False
    t.execute()
    before = t.f.journal.get(t.handle.run_id)
    partial = (t.f.directory / "partial.json").read_bytes()
    reply = host_reply(t.f, t.handle.run_id, t.handle.gate, consumed=True)
    assert (
        reconcile_managed(t.f.journal, t.handle.run_id, t.f.s.context.runner_id, lambda _: reply)
        == "terminal_host_exit_observed"
    )
    after = t.f.journal.get(t.handle.run_id)
    assert after.pid is None and after.phase == Phase.FAILED
    assert (
        after.run_dir == before.run_dir and (t.f.directory / "partial.json").read_bytes() == partial
    )
    assert after.warnings[-1]["previous_pid"] == before.pid
    with t.f.journal._connection() as con:
        claim = con.execute("SELECT * FROM managed_claim_intents").fetchone()
        assert con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0] == 2
        assert con.execute("SELECT issued FROM authorization_approvals").fetchone()[0] == 1
        assert con.execute("SELECT fence FROM authorization_fences").fetchone()[0] == 1
    assert claim["consumption_acknowledged"] == 1
    assert t.handle._confirmed_stop is None and local_holds(t.f.journal) == 0
    sender = Mock()
    with pytest.raises(AuthorizationError, match="known_native_stop_required"):
        t.handle.report_stop(sender)
    sender.assert_not_called()


def test_upload_not_received_can_be_retired_without_replaying_artifact(result_fixture):
    t = result_fixture
    t.handle.execute(t.f.directory)
    artifact = t.f.journal.get(t.handle.run_id).artifact_sha256

    def lost(_):
        raise OSError("synthetic upload outcome unknown")

    with pytest.raises(AuthorizationError):
        t.handle.finalize(lost, t.finish)
    reply = host_reply(t.f, t.handle.run_id, t.handle.gate, consumed=True)
    reconcile_managed(t.f.journal, t.handle.run_id, t.f.s.context.runner_id, lambda _: reply)
    assert t.f.journal.get(t.handle.run_id).artifact_sha256 == artifact
    with t.f.journal._connection() as con:
        intent = con.execute("SELECT * FROM managed_result_intents").fetchone()
    assert intent["state"] == "host_retired" and t.calls == []
    assert local_holds(t.f.journal) == 0


def test_retained_unfinished_result_remains_held_and_never_creates_stop(result_fixture):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def lost(_):
        raise OSError("synthetic finish not received")

    with pytest.raises(AuthorizationError):
        t.handle.finalize(t.submit, lost)
    reply = public_reply(t.f, t.handle.run_id, t.handle.gate)
    reply["claim"]["consumed"] = True
    reply["result"] = t.state["result"]
    assert (
        reconcile_managed(t.f.journal, t.handle.run_id, t.f.s.context.runner_id, lambda _: reply)
        == "held_result_observed"
    )
    assert local_holds(t.f.journal) > 0 and t.f.journal.unfinished()
    assert t.calls == ["submit"]


def test_existing_native_terminal_receipts_use_original_reconciliation(result_fixture):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def lost(body):
        t.finish(body)
        raise OSError("synthetic lost finish acknowledgement")

    with pytest.raises(AuthorizationError):
        t.handle.finalize(t.submit, lost)
    reply = public_reply(t.f, t.handle.run_id, t.handle.gate)
    reply["claim"]["consumed"] = True
    reply.update(
        result=t.state["result"],
        completion=t.state["completion"],
        execution_state="completed",
        capacity_reserved=False,
    )
    assert (
        reconcile_managed(t.f.journal, t.handle.run_id, t.f.s.context.runner_id, lambda _: reply)
        == "terminal_receipt_observed"
    )
    assert t.f.journal.get(t.handle.run_id).phase == Phase.DONE
    assert local_holds(t.f.journal) == 0


def failed_completion_reply(t):
    reply = public_reply(t.f, t.handle.run_id, t.handle.gate)
    reply["claim"]["consumed"] = True
    reply.update(
        execution_state="failed",
        capacity_reserved=False,
        result=t.state["result"],
        completion={
            "schema": "vardr.managed-completion/1",
            **observations.binding(reply),
            "receipt_sha256": t.state["result"]["receipt_sha256"],
            "outcome": "failed",
            "capacity_reserved": False,
        },
    )
    return reply


@pytest.mark.parametrize("window", ["result_ack_lost", "finish_not_received"])
def test_server_failed_completion_preserves_original_intent_and_uncertain_flags(
    result_fixture, window
):
    t = result_fixture
    output = t.handle.execute(t.f.directory)
    original_artifact = output.read_bytes()

    def lost_result(body):
        t.submit(body)
        raise OSError("synthetic result acknowledgement lost")

    def lost_finish(body):
        raise OSError("synthetic finish not received")

    with pytest.raises(AuthorizationError):
        t.handle.finalize(lost_result if window == "result_ack_lost" else t.submit, lost_finish)
    before = t.f.journal.get(t.handle.run_id)
    with t.f.journal._connection() as con:
        intent_before = dict(con.execute("SELECT * FROM managed_result_intents").fetchone())
        claim_before = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
    assert intent_before["outcome"] == "completed"
    assert intent_before["finish_sent"] == (window == "finish_not_received")
    reply = failed_completion_reply(t)
    for _ in range(2):
        assert (
            reconcile_managed(
                t.f.journal, t.handle.run_id, t.f.s.context.runner_id, lambda _: reply
            )
            == "terminal_failed_completion_observed"
        )
        assert local_holds(t.f.journal) == 0 and not t.f.journal.unfinished()
    after = t.f.journal.get(t.handle.run_id)
    assert after.phase == Phase.FAILED and after.failure_reason == "observed_failed_completion"
    assert (
        after.artifact_sha256 == before.artifact_sha256 and output.read_bytes() == original_artifact
    )
    assert after.upload_state == before.upload_state
    assert len(after.warnings) == len(before.warnings) + 1
    assert after.warnings[-1]["code"] == "server_failed_completion"
    with t.f.journal._connection() as con:
        intent = dict(con.execute("SELECT * FROM managed_result_intents").fetchone())
        claim = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
        assert con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0] == 2
        assert con.execute("SELECT issued FROM authorization_approvals").fetchone()[0] == 1
        assert con.execute("SELECT fence FROM authorization_fences").fetchone()[0] == 1
    assert intent == {**intent_before, "state": "server_retired"}
    assert claim == {**claim_before, "state": "failed_completion_observed"}
    assert t.calls == ["submit"]
    with pytest.raises(AuthorizationError):
        t.f.make().acquire(t.f.directory)
    assert local_holds(t.f.journal) == 0


@pytest.mark.parametrize(
    "change",
    [
        "artifact",
        "case",
        "contract",
        "fence",
        "unconsumed",
        "capacity",
        "local_intent",
        "missing_intent",
    ],
)
def test_failed_completion_cannot_retire_a_different_or_unproven_artifact(result_fixture, change):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def lost(body):
        raise OSError("synthetic finish not received")

    with pytest.raises(AuthorizationError):
        t.handle.finalize(t.submit, lost)
    reply = failed_completion_reply(t)
    if change in {"artifact", "case"}:
        key = "artifact_sha256" if change == "artifact" else "case_sha256"
        reply["result"][key] = "f" * 64
        reply["result"]["receipt_sha256"] = results.receipt(
            observations.binding(reply),
            reply["result"]["artifact_sha256"],
            reply["result"]["case_sha256"],
        )
        reply["completion"]["receipt_sha256"] = reply["result"]["receipt_sha256"]
    elif change in {"contract", "fence"}:
        reply["claim"]["contract_id" if change == "contract" else "fence"] = (
            "other-contract" if change == "contract" else 2
        )
    elif change == "unconsumed":
        reply["claim"]["consumed"] = False
    elif change == "capacity":
        reply["capacity_reserved"] = True
    else:
        with t.f.journal._connection() as con:
            if change == "local_intent":
                con.execute("UPDATE managed_result_intents SET artifact_size=artifact_size+1")
            else:
                con.execute("DELETE FROM managed_result_intents")
    before = t.f.journal.get(t.handle.run_id)
    with pytest.raises(AuthorizationError):
        reconcile_managed(t.f.journal, t.handle.run_id, t.f.s.context.runner_id, lambda _: reply)
    assert t.f.journal.get(t.handle.run_id) == before and local_holds(t.f.journal) > 0
    with t.f.journal._connection() as con:
        assert con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0] == 1


def test_failed_completion_retirement_write_failure_is_atomic(result_fixture):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def lost(body):
        raise OSError("synthetic finish not received")

    with pytest.raises(AuthorizationError):
        t.handle.finalize(t.submit, lost)
    before = t.f.journal.get(t.handle.run_id)
    with t.f.journal._connection() as con:
        con.execute("""CREATE TRIGGER reject_failed_completion BEFORE UPDATE OF phase ON runs
            WHEN NEW.last_event='managed_failed_completion_receipt'
            BEGIN SELECT RAISE(ABORT, 'synthetic completion retirement failure'); END""")
    with pytest.raises(Exception, match="synthetic completion retirement failure"):
        reconcile_managed(
            t.f.journal,
            t.handle.run_id,
            t.f.s.context.runner_id,
            lambda _: failed_completion_reply(t),
        )
    assert t.f.journal.get(t.handle.run_id) == before and local_holds(t.f.journal) > 0
    with t.f.journal._connection() as con:
        assert con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0] == 1
        assert (
            con.execute("SELECT state FROM managed_result_intents").fetchone()[0]
            == "finish_in_flight"
        )


def test_retirement_transaction_failure_preserves_all_active_holds(stopped):
    t = stopped
    t.execute()
    before = t.f.journal.get(t.handle.run_id)
    with t.f.journal._connection() as con:
        con.execute("""CREATE TRIGGER reject_host_retirement BEFORE UPDATE OF phase ON runs
            WHEN NEW.last_event='managed_host_exit_receipt'
            BEGIN SELECT RAISE(ABORT, 'synthetic retirement write failure'); END""")
    reply = host_reply(t.f, t.handle.run_id, t.handle.gate, consumed=True)
    with pytest.raises(Exception, match="synthetic retirement write failure"):
        reconcile_managed(t.f.journal, t.handle.run_id, t.f.s.context.runner_id, lambda _: reply)
    assert t.f.journal.get(t.handle.run_id) == before
    with t.f.journal._connection() as con:
        assert con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0] == 1
        assert (
            con.execute("SELECT state FROM managed_claim_intents").fetchone()[0]
            != "host_exit_observed"
        )
    assert local_holds(t.f.journal) > 0


@pytest.mark.parametrize("change", ["origin", "receipt", "consumed_active", "source"])
def test_wrong_or_concurrent_observation_never_closes_local_holds(
    entry_fixture, monkeypatch, change
):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    reply = host_reply(f, handle.run_id, handle.gate)
    if change == "origin":
        reply["origin"] = "https://other.test"
    elif change == "receipt":
        reply["stop"]["receipt_sha256"] = "0" * 64
    elif change == "consumed_active":
        reply.update(stop=None, execution_state="active", capacity_reserved=True)
    else:
        observe = observations.observe

        def changed(*args):
            result = observe(*args)
            f.journal.transition(handle.run_id, Phase.CLAIMED, pid=800001)
            return result

        monkeypatch.setattr(observations, "observe", changed)
    if change == "consumed_active":
        assert (
            reconcile_managed(f.journal, handle.run_id, f.s.context.runner_id, lambda _: reply)
            == "held_no_terminal_receipt"
        )
    else:
        with pytest.raises(AuthorizationError):
            reconcile_managed(f.journal, handle.run_id, f.s.context.runner_id, lambda _: reply)
    assert local_holds(f.journal) > 0


def test_unknown_claim_cannot_be_reclassified_as_zero_rpc(entry_fixture):
    f = entry_fixture
    facade = lost_claim(f)
    with pytest.raises(AuthorizationError, match="preclaim_retirement_not_proven"):
        retire_preclaim(f.journal, facade.run_id)
    assert f.journal.get(facade.run_id).phase == Phase.CLAIMING


def test_dangling_active_ledger_is_a_hold_after_terminal_metadata(result_fixture):
    t = result_fixture
    t.handle.execute(t.f.directory)
    t.handle.finalize(t.submit, t.finish)
    assert local_holds(t.f.journal) == 0
    with t.f.journal._connection() as con:
        con.execute("UPDATE authorization_contracts SET consumed=1")
    assert not t.f.journal.unfinished() and local_holds(t.f.journal) > 0


@pytest.mark.parametrize("marker_write_fails", [False, True])
def test_only_durable_no_rpc_marker_allows_local_preclaim_retirement(
    entry_fixture, monkeypatch, marker_write_fails
):
    f = entry_fixture
    prepare = ClaimStore.prepare_send

    def stop_after_prepare(store, run_id, *args):
        prepare(store, run_id, *args)
        f.journal.request_stop(run_id)

    monkeypatch.setattr(ClaimStore, "prepare_send", stop_after_prepare)
    if marker_write_fails:
        monkeypatch.setattr(
            ClaimStore,
            "hold",
            Mock(side_effect=sqlite3.OperationalError("synthetic marker failure")),
        )
    entry = f.make()
    with pytest.raises(ClaimError, match="denied_before_rpc"):
        entry.acquire(f.directory)
    assert not f.rpc
    with f.journal._connection() as con:
        claim = con.execute("SELECT * FROM managed_claim_intents").fetchone()
    assert (
        claim["contract"] is None
        and claim["consumption_sent"] == claim["consumption_acknowledged"] == 0
    )
    if marker_write_fails:
        with pytest.raises(AuthorizationError, match="not_proven"):
            retire_preclaim(f.journal, entry.run_id)
        assert local_holds(f.journal) > 0
    else:
        assert claim["state"] == "preclaim_retired" and local_holds(f.journal) == 0
        inspect = Mock()
        assert (
            reconcile_managed(f.journal, entry.run_id, f.s.context.runner_id, inspect)
            == "local_preclaim_retired"
        )
        inspect.assert_not_called()


def test_reserve_conflict_write_uncertainty_cannot_close_new_run(entry_fixture, monkeypatch):
    f = entry_fixture
    facade = lost_claim(f)
    reply = host_reply(f, facade.run_id)
    reconcile_managed(f.journal, facade.run_id, f.s.context.runner_id, lambda _: reply)
    original = f.journal.get(facade.run_id)
    monkeypatch.setattr(
        reconciliation,
        "retire_reserve_conflict",
        Mock(side_effect=sqlite3.OperationalError("synthetic conflict retirement failure")),
    )
    with pytest.raises(ClaimError, match="already_reserved"):
        f.make().acquire(f.directory)
    assert f.journal.get(facade.run_id) == original
    assert len(f.rpc) == 1 and local_holds(f.journal) > 0


@pytest.mark.parametrize("foreign_backend", [False, True])
def test_metadata_command_uses_original_read_only_observation_only(
    entry_fixture, monkeypatch, tmp_path, capsys, foreign_backend
):
    f = entry_fixture
    facade = lost_claim(f)
    reply = host_reply(f, facade.run_id)
    path = tmp_path / "existing-identity.json"
    path.write_text("{}")
    monkeypatch.setattr(identity, "identity_file", lambda: path)
    monkeypatch.setattr(
        identity, "load_or_create", lambda: SimpleNamespace(runner_id=f.s.context.runner_id)
    )
    monkeypatch.setattr(
        config, "require_auth", lambda: (reply["origin"], "vmap_synthetic_private_fixture")
    )
    client = SimpleNamespace(
        base="https://foreign.test" if foreign_backend else reply["origin"],
        managed_post=Mock(return_value=reply),
    )
    monkeypatch.setattr(api, "VardrMapClient", lambda *args: client)
    if foreign_backend:
        with pytest.raises(typer.Exit):
            managed_recovery.reconcile_managed_run(run_id=facade.run_id)
        assert capsys.readouterr().out == "managed_reconciliation_held\n"
        client.managed_post.assert_not_called()
        assert local_holds(f.journal) > 0
        return
    managed_recovery.reconcile_managed_run(run_id=facade.run_id)
    output = capsys.readouterr().out
    assert json.loads(output) == {
        "state": "terminal_host_exit_observed",
        "remaining_local_holds": 0,
    }
    args = client.managed_post.call_args.args
    assert args[0] == f"/jobs/{reply['job_id']}/managed/observation"
    assert set(args[1]) == observations.ROOT - {"job_id"}
    assert "token" not in args[1] and "private_fixture" not in output


def test_existing_native_stop_receipt_uses_original_intent(stopped):
    t = stopped
    t.execute()

    def lost(body):
        t.send(body)
        raise OSError("synthetic lost native stop acknowledgement")

    with pytest.raises(AuthorizationError):
        t.handle.report_stop(lost)
    reply = public_reply(t.f, t.handle.run_id, t.handle.gate)
    reply["claim"]["consumed"] = True
    reply.update(stop=t.state["stop"], execution_state="cancelled", capacity_reserved=False)
    assert (
        reconcile_managed(t.f.journal, t.handle.run_id, t.f.s.context.runner_id, lambda _: reply)
        == "terminal_stop_receipt_observed"
    )
    assert local_holds(t.f.journal) == 0
    assert t.f.journal.get(t.handle.run_id).pid == 600001  # Retained metadata, never signalled.
