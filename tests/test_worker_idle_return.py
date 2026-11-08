"""Pure scheduling models; no native owner, channel or process is executed."""

import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_worker_idle_stop import ModeledNativeIdleExit, handshake
from tests.test_worker_idle_stop import admission_document as admission_document
from tests.test_worker_idle_stop import entry_fixture as entry_fixture
from tests.test_worker_idle_stop import persistent_worker as persistent_worker
from tests.test_worker_idle_stop import specimen as specimen
from tests.test_worker_idle_stop import worker_fixture as worker_fixture
from vardrrunner import worker_lifecycle as life
from vardrrunner.authorization.codec import AuthorizationError, sign, unb64
from vardrrunner.journal import Phase


@pytest.fixture
def idle_return_model(persistent_worker, monkeypatch):
    p = persistent_worker

    def create(*, jobs=0, maximum=None, rounding=False):
        p.settings.update(jobs=jobs, limits={"max_attempts": maximum, "idle_timeout_seconds": 2})
        worker = p.configure()
        ticks, base = p.t.f.s.ticks, 100 * life._SECOND
        state = SimpleNamespace(
            offset=0,
            rounded=False,
            preboundary_sleeps=[],
            boundary_calls=None,
            boundary_bounds=None,
            native_end=0,
            acknowledgement=[],
            released_snapshot=None,
        )
        monkeypatch.setattr(life, "_process_readback", lambda: None)
        monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
        monkeypatch.setattr(life.time, "monotonic", lambda: ticks[0])

        def boot(_=None):
            return base + round(ticks[0] * life._SECOND) + state.offset

        monkeypatch.setattr(life.time, "clock_gettime_ns", boot, raising=False)
        channel = Mock()
        channel.get_inheritable.return_value = False
        owner = life.PersistentWorkerOwner(channel, worker.admission, (0, 0.0), (1 << 64) - 1)
        owner._ready = True
        monkeypatch.setattr(owner, "_empty_children", lambda: True)
        rtt = 0.0 if rounding else 0.00001

        def acknowledge(kind, *_):
            if kind in {life._HELLO, life._DONE}:
                state.native_end = boot() + round(rtt * life._SECOND / 2) + 2 * life._SECOND
                ticks[0] += rtt
            state.acknowledgement.append(kind)
            return "ef" * 32

        handshake(owner, monkeypatch, acknowledge)
        original_ready = owner.require_ready

        def ready(admission):
            if boot() >= owner._idle_end and state.boundary_calls is None:
                state.boundary_calls = list(p.t.calls)
                state.boundary_bounds = (owner._idle_end, owner._idle_wait_end, owner._hard)
            original_ready(admission)

        monkeypatch.setattr(owner, "require_ready", ready)
        original_begin = owner.begin_attempt

        def begin(number):
            # Existing ManagedEntry/journal fixture drives one original job. Its
            # inert dispatch is joined to the real owner epoch with mocked ACKs.
            native = original_begin(number)
            epoch = p.t.owner.begin_attempt(number)
            verified, seal, finished = epoch.verified_lease, epoch.seal, epoch.finished

            def lease(binding, lease_end, hard_end):
                native.verified_lease(binding, lease_end, hard_end)
                verified(binding, lease_end, hard_end)

            def sealed():
                native.seal()
                seal()

            def done():
                owner._launched = owner._drained = owner._normal_return = True
                native._control = SimpleNamespace(
                    worker_quiescent=lambda: True,
                    stop_reason=lambda: "",
                    worker_reuse_safe=lambda: True,
                )
                proof = native.finished()
                finished()
                return proof

            epoch.verified_lease, epoch.seal, epoch.finished = lease, sealed, done
            return epoch

        monkeypatch.setattr(owner, "begin_attempt", begin)
        worker.owner = owner
        original_rpc = worker.client.managed_post

        def rpc(path, body):
            operation = path.rsplit("/", 1)[-1]
            if operation == "pending" and p.state["released"]:
                with worker.journal._connection() as con:
                    snapshot = dict(
                        con.execute("SELECT * FROM managed_persistent_attempts").fetchone()
                    )
                if state.released_snapshot is None:
                    state.released_snapshot = snapshot
                assert snapshot == state.released_snapshot
            value = original_rpc(path, body)
            if operation == "pending" and value["jobs"]:
                # The older shared signed fixture uses contract-1/attempt-1.
                # Keep this one original job, but give its public contract IDs
                # the UUID shape that the actual native epoch validates.
                specimen = p.t.f.s
                wire = specimen.claim["managed_authorization"]
                contract = json.loads(unb64(wire["contract"]["payload"]))
                suffix = f"{p.state['prepared']:012x}"
                contract.update(
                    contract_id="20000000-0000-4000-8000-" + suffix,
                    attempt_id="30000000-0000-4000-8000-" + suffix,
                )
                wire["contract"] = sign(contract, bytes(range(32, 64)), "contract")
                specimen.context = replace(specimen.context, attempt_id=contract["attempt_id"])
                specimen.reply.update(
                    contract_id=contract["contract_id"], attempt_id=contract["attempt_id"]
                )
            if operation == "pending" and p.state["released"] >= jobs:
                value["availability"]["state"] = "idle-ready"
            return value

        worker.client.managed_post = rpc

        def advance(seconds):
            ticks[0] += seconds
            if rounding and not state.rounded and ticks[0] >= 2:
                # Model a one-nanosecond boundary ordering discrepancy, with no
                # change to the actual owner's immutable cutoff or wait bound.
                state.offset = owner._idle_end - 1 - (base + round(ticks[0] * life._SECOND))
                state.rounded = True
            elif state.rounded and not owner._idle_closing:
                state.preboundary_sleeps.append(seconds)
            if owner._idle_closing and boot() >= state.native_end + 20_000_000:
                # Exact scalar124 branch: unarmed, live child, open mocked
                # channel, no stop/EOF/pending event; no real PID1 is started.
                raise ModeledNativeIdleExit()

        worker.sleep = advance
        monkeypatch.setattr(life.time, "sleep", advance)
        return SimpleNamespace(worker=worker, owner=owner, channel=channel, state=state, p=p)

    return create


def assert_native_wait(model):
    owner, state, p = model.owner, model.state, model.p
    assert owner._idle_closing
    assert state.boundary_calls == p.t.calls
    assert state.boundary_bounds == (owner._idle_end, owner._idle_wait_end, owner._hard)
    model.channel.close.assert_not_called()


def test_direct_python_idle_boundary_keeps_native_channel_open(idle_return_model):
    model = idle_return_model()
    with pytest.raises(ModeledNativeIdleExit):
        model.worker.run(wait_seconds=10, poll_seconds=2)
    assert_native_wait(model)
    assert model.p.t.calls == ["pending"]
    assert not model.p.epochs and not model.worker.journal.list()


def test_one_original_done_release_survives_native_idle_wait(idle_return_model):
    model = idle_return_model(jobs=1)
    with pytest.raises(ModeledNativeIdleExit):
        model.worker.run(wait_seconds=10, poll_seconds=2)
    assert_native_wait(model)
    p, worker = model.p, model.worker
    assert p.state["released"] == len(p.epochs) == 1
    for operation in (
        "claim",
        "consume",
        "runtime-bind",
        "native",
        "result",
        "finish",
        "done",
        "runtime-idle-release",
    ):
        assert p.t.calls.count(operation) == 1
    with worker.journal._connection() as con:
        retained = dict(con.execute("SELECT * FROM managed_persistent_attempts").fetchone())
    assert retained == model.state.released_snapshot
    assert retained["state"] == "released" and retained["native_done_sha256"] == "ef" * 32
    assert worker.journal.get(retained["run_id"]).phase == Phase.DONE
    assert model.state.acknowledgement.count(life._DONE) == 1


def test_advisory_cutoff_one_ns_early_sleeps_without_more_discovery(idle_return_model):
    model = idle_return_model(rounding=True)
    with pytest.raises(ModeledNativeIdleExit):
        model.worker.run(wait_seconds=10, poll_seconds=2)
    assert_native_wait(model)
    assert model.state.preboundary_sleeps == [0.05]
    assert model.p.t.calls == ["pending"] and not model.p.epochs


def test_advisory_cutoff_full_hold_refusal_never_waits(idle_return_model, monkeypatch):
    model = idle_return_model(rounding=True)
    original = model.worker._no_holds

    def no_holds(*, full=False):
        if full and model.state.rounded:
            raise AuthorizationError("worker_unresolved_local_attempt")
        original(full=full)

    monkeypatch.setattr(model.worker, "_no_holds", no_holds)
    with pytest.raises(AuthorizationError, match="^worker_unresolved_local_attempt$"):
        model.worker.run(wait_seconds=10, poll_seconds=2)
    assert not model.owner._idle_closing and not model.state.preboundary_sleeps
    assert model.p.t.calls == ["pending"]
    model.channel.close.assert_not_called()


def test_completed_count_one_with_idle_keeps_original_clean_return(idle_return_model):
    model = idle_return_model(jobs=2, maximum="1")
    record = model.worker.run(wait_seconds=10, poll_seconds=2)
    assert record is not None and record.phase == Phase.DONE
    assert model.p.state["released"] == len(model.p.epochs) == 1
    assert model.p.t.calls.count("claim") == model.p.t.calls.count("done") == 1
    assert model.p.t.calls.count("pending") == 1
    assert not model.owner._idle_closing and model.state.boundary_calls is None
    model.channel.close.assert_not_called()
