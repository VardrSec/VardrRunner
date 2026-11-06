"""Private candidate: pure clock/metadata composition, no owner/channel execution."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_managed_claim import entry_fixture as entry_fixture
from tests.test_managed_claim import specimen as specimen
from tests.test_managed_worker import worker_fixture as worker_fixture
from tests.test_worker_admission import admission_document as admission_document
from tests.test_worker_lifecycle_persistent import binding, complete
from tests.test_worker_lifecycle_persistent import context as context
from tests.test_worker_persistent import persistent_worker as persistent_worker
from tests.test_worker_persistent_admission import persistent_document as persistent_document
from vardrrunner import worker_lifecycle as life
from vardrrunner.authorization.codec import AuthorizationError


class ModeledNativeIdleExit(BaseException):
    """Model an independent owner selecting124; never exits an actual process."""


def handshake(owner, monkeypatch, acknowledged):
    nonce = bytes.fromhex(owner._admission.identity["owner_nonce"])
    monkeypatch.setattr(owner, "_receive_v2", lambda: (life._READY, 0, 0, 0, nonce))
    monkeypatch.setattr(owner, "_exchange_v2", Mock(side_effect=acknowledged))
    owner._handshake(nonce)


def test_finite_ack_window_never_changes_claim_cutoff_and_closing_is_sticky(context, monkeypatch):
    owner = context.create({"max_attempts": None, "idle_timeout_seconds": 15})

    def ack(*_):
        context.clock["boot"] += 200_000_000
        return "ef" * 32

    handshake(owner, monkeypatch, ack)
    assert owner._idle_end == 16 * life._SECOND
    assert owner._idle_wait_end == 21 * life._SECOND + 200_000_000
    context.clock["boot"] = owner._idle_end
    with pytest.raises(life.IdleBoundaryReached):
        owner.require_ready(owner._admission)
    context.clock["boot"] -= life._SECOND
    with pytest.raises(life.IdleBoundaryReached):
        owner.begin_attempt(1)
    assert owner._exchange_v2.call_count == 1
    assert owner._idle_end == 16 * life._SECOND


def test_readback_fault_is_never_typed_as_an_idle_stop(context, monkeypatch):
    owner = context.create({"max_attempts": None, "idle_timeout_seconds": 2})
    handshake(owner, monkeypatch, lambda *_: "ef" * 32)
    context.clock["boot"] = owner._idle_end

    def broken():
        raise life.LifecycleUnavailable("readback_failed")

    monkeypatch.setattr(life, "_process_readback", broken)
    with pytest.raises(life.LifecycleUnavailable, match="^readback_failed$") as error:
        owner.require_ready(owner._admission)
    assert not isinstance(error.value, life.IdleBoundaryReached)
    assert not owner._idle_closing


def test_terminal_wait_keeps_channel_open_and_refuses_if_owner_exit_unconfirmed(
    context, monkeypatch
):
    owner = context.create({"max_attempts": None, "idle_timeout_seconds": 2})

    def ack(*_):
        context.clock["boot"] += 200_000_000
        return "ef" * 32

    handshake(owner, monkeypatch, ack)
    context.clock["boot"] = owner._idle_end
    with pytest.raises(life.IdleBoundaryReached):
        owner.require_ready(owner._admission)
    before = owner._idle_wait_end
    monkeypatch.setattr(
        life.time,
        "sleep",
        lambda seconds: context.clock.__setitem__(
            "boot", context.clock["boot"] + max(1, int(seconds * life._SECOND))
        ),
    )
    with pytest.raises(life.LifecycleUnavailable) as error:
        owner.wait_idle_stop()
    assert not isinstance(error.value, life.IdleBoundaryReached)
    assert context.clock["boot"] == owner._idle_wait_end == before
    assert owner._exchange_v2.call_count == 1
    owner._channel.close.assert_not_called()


@pytest.mark.parametrize("hold", ["not_latched", "epoch", "children"])
def test_terminal_wait_needs_real_latch_no_active_epoch_and_empty_lineage(
    context, hold, monkeypatch
):
    owner = context.create({"max_attempts": None, "idle_timeout_seconds": 2})
    owner._idle_closing = hold != "not_latched"
    if hold == "epoch":
        owner._epoch = SimpleNamespace(_finished=False)
    if hold == "children":
        monkeypatch.setattr(owner, "_empty_children", lambda: False)
    sleep = Mock()
    monkeypatch.setattr(life.time, "sleep", sleep)
    with pytest.raises(life.LifecycleUnavailable):
        owner.wait_idle_stop()
    sleep.assert_not_called()
    owner._exchange_v2.assert_not_called()


def test_done_captures_only_wait_upper_bound_and_preserves_active_permission(context, monkeypatch):
    owner = context.create({"max_attempts": None, "idle_timeout_seconds": 2})

    def ack(kind, *_):
        if kind in {life._HELLO, life._DONE}:
            context.clock["boot"] += 200_000_000
        return "ef" * 32

    handshake(owner, monkeypatch, ack)
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(binding(owner, 1), 105.0, 120.0)
    old_lease, old_hard = owner._lease, owner._hard
    before = context.clock["boot"]
    complete(owner, epoch)
    assert owner._idle_end == before + 2 * life._SECOND
    assert owner._idle_wait_end == before + 200_000_000 + 7 * life._SECOND
    assert (owner._lease, owner._hard) == (old_lease, old_hard)


@pytest.mark.parametrize("ack_rtt, observation_delay", [(0.2, 0.0), (0.00001, 0.02)])
def test_real_worker_adapter_clock_skew_enters_nonspawning_wait_with_zero_claims(
    persistent_worker, monkeypatch, ack_rtt, observation_delay
):
    p = persistent_worker
    p.settings.update(jobs=0, limits={"max_attempts": None, "idle_timeout_seconds": 2})
    worker = p.configure()
    ticks = p.t.f.s.ticks
    base = 100 * life._SECOND
    monkeypatch.setattr(life, "_process_readback", lambda: None)
    monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(
        life.time, "clock_gettime_ns", lambda _: base + int(ticks[0] * life._SECOND), raising=False
    )
    channel = Mock()
    channel.get_inheritable.return_value = False
    owner = life.PersistentWorkerOwner(channel, worker.admission, (0, 0.0), (1 << 64) - 1)
    owner._ready = True
    monkeypatch.setattr(owner, "_empty_children", lambda: True)

    def ack(*_):
        ticks[0] += ack_rtt  # Before/after ACK window; no actual socket call.
        return "ef" * 32

    handshake(owner, monkeypatch, ack)
    ticks[0] += 0.5  # Startup audit/reservation happens after the owner anchor.
    worker.owner = owner
    after_boundary = []

    def native_wait(seconds):
        if not after_boundary:
            after_boundary.extend(p.t.calls)
        ticks[0] += seconds
        if ticks[0] >= 2 + ack_rtt / 2 + observation_delay:
            raise ModeledNativeIdleExit()

    monkeypatch.setattr(life.time, "sleep", native_wait)
    with pytest.raises(ModeledNativeIdleExit):
        worker.run(wait_seconds=10, poll_seconds=0.1)
    assert owner._idle_closing and p.t.calls == after_boundary
    assert p.t.calls and set(p.t.calls) == {"pending"}
    assert not p.epochs and not p.t.f.journal.list()
    with p.t.f.journal._connection() as con:
        assert con.execute("SELECT count(*) FROM managed_persistent_attempts").fetchone()[0] == 0
        assert con.execute("SELECT count(*) FROM managed_persistent_selections").fetchone()[0] == 0
    channel.close.assert_not_called()


def test_typed_boundary_cannot_skip_worker_hold_audit(persistent_worker, monkeypatch):
    p = persistent_worker
    p.settings.update(jobs=0, limits={"max_attempts": None, "idle_timeout_seconds": 2})
    worker = p.configure()
    owner = life.PersistentWorkerOwner(Mock(), worker.admission, (0, 0.0), (1 << 64) - 1)
    owner._idle_closing = True
    worker.owner = owner
    monkeypatch.setattr(
        worker, "_run", Mock(side_effect=life.IdleBoundaryReached("worker_idle_boundary_reached"))
    )
    audit = Mock(side_effect=AuthorizationError("worker_unresolved_local_attempt"))
    monkeypatch.setattr(worker, "_no_holds", audit)
    wait = Mock()
    monkeypatch.setattr(owner, "wait_idle_stop", wait)
    with pytest.raises(AuthorizationError, match="worker_unresolved_local_attempt"):
        worker.run()
    audit.assert_called_once_with(full=True)
    wait.assert_not_called()


@pytest.mark.parametrize("phase", ["hello", "done"])
@pytest.mark.parametrize("overflow", [False, True])
def test_shutdown_wait_bound_checks_uint64_without_extending_permission(
    context, monkeypatch, phase, overflow
):
    owner = context.create({"max_attempts": None, "idle_timeout_seconds": 2})
    maximum = (1 << 64) - 1
    acknowledged = maximum - 7 * life._SECOND + int(overflow)

    def ack(*_):
        context.clock["boot"] = acknowledged
        return "ef" * 32

    if phase == "hello":
        before = context.clock["boot"]

        def operation():
            handshake(owner, monkeypatch, ack)
    else:
        handshake(owner, monkeypatch, lambda *_: "ef" * 32)
        epoch = owner.begin_attempt(1)
        epoch.verified_lease(binding(owner, 1), 105.0, 120.0)
        before = context.clock["boot"]
        monkeypatch.setattr(owner, "_exchange_v2", Mock(side_effect=ack))

        def operation():
            complete(owner, epoch)

    if overflow:
        with pytest.raises(life.LifecycleUnavailable):
            operation()
        if phase == "done":
            assert not epoch._finished
    else:
        operation()
        assert owner._idle_wait_end == maximum
    assert owner._idle_end == before + 2 * life._SECOND
    assert not owner._idle_closing
    owner._channel.close.assert_not_called()


def test_shutdown_reserve_still_requires_readback_and_never_sends_rpc(context, monkeypatch):
    owner = context.create({"max_attempts": None, "idle_timeout_seconds": 2})
    handshake(owner, monkeypatch, lambda *_: "ef" * 32)
    context.clock["boot"] = owner._idle_end
    with pytest.raises(life.IdleBoundaryReached):
        owner.require_ready(owner._admission)
    assert owner._idle_wait_end == owner._idle_end + 5 * life._SECOND

    def broken():
        raise life.LifecycleUnavailable("readback_failed")

    monkeypatch.setattr(life, "_process_readback", broken)
    sleep = Mock()
    monkeypatch.setattr(life.time, "sleep", sleep)
    with pytest.raises(life.LifecycleUnavailable, match="^readback_failed$"):
        owner.wait_idle_stop()
    assert owner._idle_closing
    assert owner._exchange_v2.call_count == 1
    sleep.assert_not_called()
    owner._channel.close.assert_not_called()
