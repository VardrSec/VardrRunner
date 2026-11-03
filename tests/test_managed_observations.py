"""Explicit no-capability observations never resume claims or native work."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from vardrrunner.authorization import observations, results, stops
from vardrrunner.authorization.claim import ClaimError
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.journal import Journal, JournalError, Phase
from vardrrunner.recovery import reconcile as legacy_reconcile


def fixture_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_claim = fixture_module("observation_claim_fixture", "test_managed_claim.py")
_result = fixture_module("observation_result_fixture", "test_managed_results.py")
_stop = fixture_module("observation_stop_fixture", "test_managed_stops.py")
entry_fixture = _claim.entry_fixture
specimen = _claim.specimen
result_fixture = _result.result_fixture
stopped = _stop.stopped


def public_reply(f, run_id, gate=None):
    gate = gate or f.s.make()
    root, _ = observations.original(f.journal, run_id, f.s.context.runner_id)
    return {
        "schema": "vardr.managed-claim-observation/1",
        **root,
        "claim": {
            "contract_id": gate.payload["contract_id"],
            "attempt_id": gate.payload["attempt_id"],
            "fence": gate.payload["fence"],
            "contract_sha256": digest(encoded(gate.envelope)),
            "consumed": False,
            "authority_revision": gate.context.authority_revision,
            "authority_sha256": gate.context.authority_sha256,
        },
        "execution_state": "active",
        "capacity_reserved": True,
        "result": None,
        "completion": None,
        "stop": None,
    }


def lost_claim(f):
    def lost(body):
        f.rpc.append(body)
        raise OSError("synthetic lost claim reply")

    facade = f.make(claim=lost)
    with pytest.raises(ClaimError, match="outcome_unknown"):
        facade.acquire(f.directory)
    return facade


def test_observed_absence_and_later_claim_never_retry_original_invocation(entry_fixture):
    f = entry_fixture
    facade = lost_claim(f)
    full = public_reply(f, facade.run_id)
    absent = {**full, "claim": None, "execution_state": None, "capacity_reserved": False}
    before = f.journal.get(facade.run_id)
    assert (
        observations.observe(f.journal, facade.run_id, f.s.context.runner_id, lambda _: absent)
        == absent
    )
    assert (
        observations.observe(f.journal, facade.run_id, f.s.context.runner_id, lambda _: full)
        == full
    )
    assert f.journal.get(facade.run_id) == before
    with pytest.raises(AuthorizationError, match="existing_invocation"):
        f.make().acquire(f.directory)
    assert len(f.rpc) == 1
    with f.journal._connection() as con:
        claim = con.execute("SELECT * FROM managed_claim_intents").fetchone()
        assert claim["state"] == "claim_unknown" and claim["contract"] is None
        dump = "\n".join(con.iterdump())
    assert "x" * 40 not in dump and "vardr.authorization-envelope" not in dump


def test_terminal_metadata_without_local_native_proof_only_records_observation(entry_fixture):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    reply = public_reply(f, handle.run_id, handle.gate)
    reply["claim"]["consumed"] = True
    association = observations.binding(reply)
    sha = "a" * 64
    reply["result"] = {
        "schema": "vardr.managed-result-receipt/1",
        **association,
        "artifact_sha256": sha,
        "case_sha256": reply["case_sha256"],
        "receipt_sha256": results.receipt(association, sha, reply["case_sha256"]),
        "evidence_created": 0,
        "scan_items_created": 0,
    }
    reply["completion"] = {
        "schema": "vardr.managed-completion/1",
        **association,
        "receipt_sha256": reply["result"]["receipt_sha256"],
        "outcome": "completed",
        "capacity_reserved": False,
    }
    reply.update(execution_state="completed", capacity_reserved=False)
    observations.observe(f.journal, handle.run_id, f.s.context.runner_id, lambda _: reply)
    assert f.journal.get(handle.run_id).phase == Phase.CLAIMED
    client = Mock()
    assert legacy_reconcile(f.journal, client, reply["origin"]).deferred == 1
    assert not client.mock_calls
    callback = Mock()
    with pytest.raises(AuthorizationError, match="intent_missing"):
        observations.reconcile_result(f.journal, handle.run_id, f.s.context.runner_id, callback)
    callback.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("origin", "https://other.test"),
        ("association_sha256", "0" * 64),
        ("token", "must-not-persist"),
        ("lease_seconds", 10),
    ],
)
def test_wrong_or_capability_bearing_root_is_rejected_before_persistence(
    entry_fixture, field, value
):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    reply = public_reply(f, handle.run_id, handle.gate)
    reply[field] = value
    with pytest.raises(AuthorizationError):
        observations.observe(f.journal, handle.run_id, f.s.context.runner_id, lambda _: reply)
    with f.journal._connection() as con:
        assert (
            con.execute(
                "SELECT 1 FROM sqlite_master WHERE name='managed_claim_observations'"
            ).fetchone()
            is None
        )


@pytest.mark.parametrize("change", ["fence", "consumed", "hash", "extra", "absence"])
def test_invalid_or_foreign_claim_metadata_is_not_actionable(entry_fixture, change):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    reply = public_reply(f, handle.run_id, handle.gate)
    if change == "fence":
        reply["claim"]["fence"] = True
    elif change == "consumed":
        reply["claim"]["consumed"] = 1
    elif change == "hash":
        reply["claim"]["contract_sha256"] = "not-a-hash"
    elif change == "extra":
        reply["claim"]["token"] = "must-not-persist"
    else:
        reply.update(claim=None, execution_state=None, capacity_reserved=False)
    with pytest.raises(AuthorizationError):
        observations.observe(f.journal, handle.run_id, f.s.context.runner_id, lambda _: reply)
    assert f.journal.get(handle.run_id).phase == Phase.CLAIMED


@pytest.mark.parametrize("kind", ["claim", "consumption", "receipt"])
def test_older_snapshots_cannot_replace_retained_observations(entry_fixture, kind):
    f = entry_fixture
    facade = lost_claim(f)
    first = public_reply(f, facade.run_id)
    if kind != "claim":
        first["claim"]["consumed"] = True
    if kind == "receipt":
        association = observations.binding(first)
        first["stop"] = {
            "schema": "vardr.managed-stop-receipt/1",
            **association,
            "outcome": "cancelled",
            "cause": "local_emergency_stop",
            "receipt_sha256": stops.stop_hash(association, "cancelled", "local_emergency_stop"),
            "capacity_reserved": False,
        }
        first.update(execution_state="cancelled", capacity_reserved=False)
    observations.observe(f.journal, facade.run_id, f.s.context.runner_id, lambda _: first)
    old = copy.deepcopy(first)
    if kind == "claim":
        old.update(claim=None, execution_state=None, capacity_reserved=False)
    elif kind == "consumption":
        old["claim"]["consumed"] = False
    else:
        old.update(stop=None, execution_state="active", capacity_reserved=True)
    with pytest.raises(AuthorizationError, match="regressed"):
        observations.observe(f.journal, facade.run_id, f.s.context.runner_id, lambda _: old)
    with f.journal._connection() as con:
        assert (
            json.loads(con.execute("SELECT snapshot FROM managed_claim_observations").fetchone()[0])
            == first
        )


def test_unavailable_transport_or_changed_local_source_never_changes_claim(entry_fixture):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    reply = public_reply(f, handle.run_id, handle.gate)
    before = f.journal.get(handle.run_id)

    def offline(_):
        raise OSError("offline")

    with pytest.raises(AuthorizationError, match="unavailable"):
        observations.observe(f.journal, handle.run_id, f.s.context.runner_id, offline)

    def changed(_):
        with f.journal._connection() as con:
            con.execute("UPDATE managed_claim_intents SET plan_sha256=?", ("0" * 64,))
        return reply

    with pytest.raises(AuthorizationError, match="source_changed"):
        observations.observe(f.journal, handle.run_id, f.s.context.runner_id, changed)
    assert f.journal.get(handle.run_id) == before


def test_snapshot_write_failure_never_becomes_native_or_terminal_permission(
    entry_fixture, monkeypatch
):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    reply = public_reply(f, handle.run_id, handle.gate)

    def fail(*args):
        raise JournalError("synthetic snapshot write failure")

    monkeypatch.setattr(observations.ObservationStore, "record", fail)
    with pytest.raises(JournalError):
        observations.observe(f.journal, handle.run_id, f.s.context.runner_id, lambda _: reply)
    assert f.journal.get(handle.run_id).phase == Phase.CLAIMED


def test_restart_result_reconciliation_requires_prior_local_proof_and_exact_receipt(result_fixture):
    t = result_fixture
    t.handle.execute(t.f.directory)

    def lost(body):
        t.finish(body)
        raise OSError("lost terminal reply")

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
    requests = []

    def inspect(body):
        requests.append(body)
        assert set(body) == observations.ROOT - {"job_id"}
        return reply

    fresh = Journal(t.f.journal.path)
    assert (
        observations.reconcile_result(fresh, t.handle.run_id, t.f.s.context.runner_id, inspect)
        == "terminal_receipt_observed"
    )
    assert fresh.get(t.handle.run_id).phase == Phase.DONE
    assert t.calls == ["submit", "finish"] and len(requests) == 1


def test_restart_stop_reconciliation_never_signals_a_retained_pid(stopped):
    t = stopped
    t.execute()

    def lost(body):
        t.send(body)
        raise OSError("lost stop reply")

    with pytest.raises(AuthorizationError):
        t.handle.report_stop(lost)
    reply = public_reply(t.f, t.handle.run_id, t.handle.gate)
    reply["claim"]["consumed"] = True
    reply.update(stop=t.state["stop"], execution_state="cancelled", capacity_reserved=False)
    fresh = Journal(t.f.journal.path)
    assert (
        observations.reconcile_stop(
            fresh, t.handle.run_id, t.f.s.context.runner_id, lambda _: reply
        )
        == "terminal_stop_receipt_observed"
    )
    assert fresh.get(t.handle.run_id).phase == Phase.STOP_WORK
    assert fresh.get(t.handle.run_id).pid == 600001
    assert t.calls == ["send"]


def test_missing_claim_journal_or_original_runner_prevents_transport(entry_fixture, tmp_path):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    callback = Mock()
    for value in ("invalid runner id", None):
        with pytest.raises(AuthorizationError, match="original_runner_required"):
            observations.observe(f.journal, handle.run_id, value, callback)
    with pytest.raises(AuthorizationError, match="state_unavailable"):
        observations.observe(
            Journal(tmp_path / "empty.db"), "absent", f.s.context.runner_id, callback
        )
    callback.assert_not_called()


RECOVERY_CHILD = r"""
import json, os, sys
from pathlib import Path
from unittest.mock import Mock, patch
import vardrrunner
from vardrrunner.authorization import observations
from vardrrunner.journal import Journal
from vardrrunner.recovery import reconcile

args = json.load(sys.stdin)
assert Path(vardrrunner.__file__).resolve().parent.parent == Path(args['source'])
assert Path.home().resolve() == Path.cwd().resolve()
assert not any(k.startswith('VARDRMAP_') for k in os.environ)
journal = Journal(Path(args['journal']))
client = Mock()
assert reconcile(journal, client, args['reply']['origin']).deferred == 1
assert not client.mock_calls
calls = []
def forbidden(*args, **kwargs):
    raise AssertionError('Recovery attempted network, process creation or PID signaling')
def observe(body):
    calls.append(body)
    assert set(body) == observations.ROOT - {'job_id'}
    if args['interrupt']:
        os._exit(7)
    return args['reply']
with patch('socket.socket', forbidden), patch('subprocess.Popen', forbidden), patch('os.kill', forbidden):
    operation = observations.reconcile_result if args['kind'] == 'result' else observations.reconcile_stop
    outcome = operation(journal, args['run_id'], args['runner_id'], observe)
assert len(calls) == 1
run = journal.get(args['run_id'])
print(json.dumps({'outcome':outcome, 'phase':run.phase.value, 'pid':run.pid}))
"""


def fresh_process(t, reply, kind, tmp_path, *, interrupt=False):
    home = tmp_path / "recovery-child-home"
    home.mkdir(exist_ok=True)
    environment = {"PATH": os.defpath, "HOME": str(home)}
    if os.name == "nt":
        environment["USERPROFILE"] = str(home)
    for name in ("SYSTEMROOT", "WINDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    payload = {
        "source": str(Path(__file__).resolve().parents[1]),
        "journal": str(t.f.journal.path),
        "run_id": t.handle.run_id,
        "runner_id": t.f.s.context.runner_id,
        "reply": reply,
        "kind": kind,
        "interrupt": interrupt,
    }
    serialized = json.dumps(payload)
    assert all(value not in serialized for value in ('"token"', '"envelope"', '"lease_seconds"'))
    child = subprocess.run(
        [sys.executable, "-I", "-c", RECOVERY_CHILD],
        input=serialized,
        text=True,
        capture_output=True,
        env=environment,
        cwd=home,
        timeout=15,
    )
    assert child.returncode == (7 if interrupt else 0), child.stdout + child.stderr
    return None if interrupt else json.loads(child.stdout)


@pytest.mark.parametrize("kind", ["result", "stop"])
@pytest.mark.parametrize("scenario", ["terminal", "missing_receipt", "interrupted_observation"])
def test_process_restart_observes_receipts_without_capability_or_live_handle(
    request, tmp_path, kind, scenario
):
    """Portable RECOVER evidence; native owner-crash containment remains Windows-only."""
    t = request.getfixturevalue("result_fixture" if kind == "result" else "stopped")
    if kind == "result":
        t.handle.execute(t.f.directory)

        def lost(body):
            t.finish(body)
            raise OSError("synthetic terminal response loss")

        with pytest.raises(AuthorizationError):
            t.handle.finalize(t.submit, lost)
    else:
        t.execute()

        def lost(body):
            t.send(body)
            raise OSError("synthetic stop response loss")

        with pytest.raises(AuthorizationError):
            t.handle.report_stop(lost)
    reply = public_reply(t.f, t.handle.run_id, t.handle.gate)
    reply["claim"]["consumed"] = True
    reply.update(**t.state, execution_state="completed" if kind == "result" else "cancelled")
    reply["capacity_reserved"] = False
    before = t.f.journal.get(t.handle.run_id)
    files = {p: p.read_bytes() for p in t.f.directory.iterdir() if p.is_file()}
    calls = t.calls.copy()
    if scenario == "missing_receipt":
        reply.update(result=None, completion=None, stop=None)
        reply.update(execution_state="uncertain", capacity_reserved=True)
    elif scenario == "interrupted_observation":
        fresh_process(t, reply, kind, tmp_path, interrupt=True)
        assert t.f.journal.get(t.handle.run_id) == before
    outcome = fresh_process(t, reply, kind, tmp_path)
    assert t.calls == calls
    assert {p: p.read_bytes() for p in files} == files
    assert outcome["pid"] == before.pid
    with t.f.journal._connection() as con:
        consumed = con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0]
    if scenario == "missing_receipt":
        assert outcome["outcome"] == (
            "held_no_receipt" if kind == "result" else "held_no_stop_receipt"
        )
        assert t.f.journal.get(t.handle.run_id) == before and consumed == 1
    else:
        expected = (
            "terminal_receipt_observed" if kind == "result" else "terminal_stop_receipt_observed"
        )
        assert outcome["outcome"] == expected
        assert outcome["phase"] == (Phase.DONE.value if kind == "result" else Phase.STOP_WORK.value)
        assert consumed == 2
