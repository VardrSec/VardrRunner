"""V2 IPC/state tests; they do not establish native containment acceptance."""

import hashlib
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vardrrunner import worker_lifecycle as life
from vardrrunner.authorization.codec import encoded

RUNNER = "11111111-1111-4111-8111-111111111111"
BINDING = {
    "origin": "https://map.example/backend",
    "job_id": "job-1",
    "runner_id": RUNNER,
    "contract_id": "22222222-2222-4222-8222-222222222222",
    "attempt_id": "33333333-3333-4333-8333-333333333333",
    "fence": 1,
    "contract_sha256": "ab" * 32,
}


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setattr(life, "_process_readback", lambda: None)
    monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(life.time, "clock_gettime_ns", lambda clock: 1_000_000_000, raising=False)
    monkeypatch.setattr(life.time, "monotonic", lambda: 100.0)
    admission = SimpleNamespace(
        origin=BINDING["origin"],
        runner_id=RUNNER,
        max_attempts=2,
        runtime_id="44444444-4444-4444-8444-444444444444",
        runtime_sha256="cd" * 32,
    )
    channel = Mock()
    channel.get_inheritable.return_value = False
    result = life.SequentialWorkerOwner(channel, admission, (1_000_000_000, 100.0), 901_000_000_000)
    result._ready = True
    monkeypatch.setattr(result, "_empty_children", lambda: True)
    monkeypatch.setattr(result, "_exchange_v2", Mock(return_value="ef" * 32))
    return result


def complete(owner, epoch):
    owner._launched = owner._drained = True
    epoch._control = SimpleNamespace(worker_quiescent=lambda: True)
    epoch.seal()
    assert epoch.finished() == "ef" * 32


def test_epoch_freezes_binding_and_old_callback_cannot_touch_next_attempt(owner):
    old = owner.begin_attempt(1)
    old.verified_lease(BINDING, 105.0, 120.0)
    expected = hashlib.sha256(
        encoded(
            {
                "runtime_id": owner._admission.runtime_id,
                "runtime_sha256": owner._admission.runtime_sha256,
                "runtime_sequence": 1,
                "binding": BINDING,
            }
        )
    ).digest()
    assert owner._exchange_v2.call_args.args == (
        life._LEASE,
        1,
        6_000_000_000,
        21_000_000_000,
        expected,
    )
    complete(owner, old)
    new = owner.begin_attempt(2)
    before = owner._exchange_v2.call_count
    for action in (
        old.require_active,
        lambda: old.verified_lease(BINDING, 105.0, 120.0),
        old.finished,
    ):
        with pytest.raises(life.LifecycleUnavailable):
            action()
    assert owner._exchange_v2.call_count == before
    new.verified_lease({**BINDING, "job_id": "job-2"}, 105.0, 130.0)
    assert owner._exchange_v2.call_args.args[1] == 2
    assert owner._hard == 31_000_000_000


@pytest.mark.parametrize("sequence", [0, True, 2, -1, 33])
def test_begin_requires_exact_fresh_sequence(owner, sequence):
    with pytest.raises(life.LifecycleUnavailable):
        owner.begin_attempt(sequence)


def test_finish_requires_seal_drain_and_exact_control_quiescence(owner):
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(BINDING, 105.0, 120.0)
    with pytest.raises(life.LifecycleUnavailable):
        epoch.finished()
    epoch.seal()
    owner._launched = owner._drained = True
    epoch._control = SimpleNamespace(worker_quiescent=lambda: False)
    with pytest.raises(life.LifecycleUnavailable):
        epoch.finished()
    epoch._control = SimpleNamespace(worker_quiescent=lambda: True)
    assert epoch.finished() == "ef" * 32
    assert owner._idle_end == 61_000_000_000


def test_sealed_epoch_refuses_late_lease_without_ipc(owner):
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(BINDING, 105.0, 120.0)
    epoch.seal()
    before = owner._exchange_v2.call_count
    with pytest.raises(life.LifecycleUnavailable):
        epoch.verified_lease(BINDING, 106.0, 130.0)
    assert owner._exchange_v2.call_count == before


def test_idle_deadline_never_renews_and_runway_stays_fixed(monkeypatch, owner):
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(BINDING, 105.0, 120.0)
    complete(owner, epoch)
    work, grant = owner._work_end, owner._grant_end
    monkeypatch.setattr(life.time, "clock_gettime_ns", lambda clock: owner._idle_end)
    with pytest.raises(life.LifecycleUnavailable):
        owner.begin_attempt(2)
    assert (owner._work_end, owner._grant_end) == (work, grant)


def test_attempt_limit_32_is_explicit_and_never_wraps(owner):
    owner._admission.max_attempts = 32
    for sequence in range(1, 33):
        epoch = owner.begin_attempt(sequence)
        epoch.verified_lease(BINDING, 105.0, 120.0)
        complete(owner, epoch)
    with pytest.raises(life.LifecycleUnavailable):
        owner.begin_attempt(33)


def test_control_object_and_shared_binding_are_pinned(monkeypatch, owner):
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(BINDING, 105.0, 120.0)
    binding = {k: v for k, v in BINDING.items() if k != "contract_sha256"}
    binding.update(authority_revision=1, authority_sha256="12" * 32)
    control = SimpleNamespace(binding=binding)
    monkeypatch.setattr(life.WorkerOwner, "run", Mock(return_value=0))
    assert owner.run(["reviewed-tool"], 1, None, control) == 0
    with pytest.raises(life.LifecycleUnavailable):
        owner.run(["reviewed-tool"], 1, None, SimpleNamespace(binding=binding))


def test_quiescence_inverse_clock_conversion_is_conservative(monkeypatch, owner):
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(BINDING, 105.0, 120.0)
    calls = []
    monkeypatch.setattr(life.time, "monotonic", lambda: calls.append("mono") or 101.0)
    monkeypatch.setattr(
        life.time, "clock_gettime_ns", lambda clock: calls.append("boot") or 3_000_000_000
    )
    assert epoch.quiescence_deadline() == 104.0
    assert calls[-2:] == ["mono", "boot"]


@pytest.mark.parametrize("fault", [None, "sequence", "magic", "size", "credentials"])
def test_v2_ack_is_exact_and_old_protocol_never_downgrades(monkeypatch, owner, fault):
    monkeypatch.setattr(socket, "SCM_CREDENTIALS", 2, raising=False)
    monkeypatch.setattr(socket, "CMSG_SPACE", lambda size: size + 16, raising=False)
    data = life._PACKET_V2.pack(
        life._MAGIC if fault == "magic" else life._MAGIC_V2,
        life._ACK,
        2 if fault == "sequence" else 1,
        4,
        5,
        b"a" * 32,
    )
    ancillary = [
        (
            socket.SOL_SOCKET,
            socket.SCM_CREDENTIALS,
            life._CREDENTIALS.pack(2 if fault == "credentials" else 1, 10000, 10000),
        )
    ]
    owner._channel.recvmsg.return_value = (
        data[:-1] if fault == "size" else data,
        ancillary,
        0,
        None,
    )
    owner._channel.send.return_value = life._PACKET_V2.size
    # Restore the real exchange rather than the fixture's IPC mock.
    exchange = life.SequentialWorkerOwner._exchange_v2.__get__(owner)
    if fault is None:
        assert exchange(life._LEASE, 1, 4, 5, b"a" * 32) == hashlib.sha256(data).hexdigest()
    else:
        with pytest.raises(life.LifecycleUnavailable):
            exchange(life._LEASE, 1, 4, 5, b"a" * 32)


def tool_handoff(owner):
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(BINDING, 105.0, 120.0)
    binding = {k: v for k, v in BINDING.items() if k != "contract_sha256"}
    binding.update(authority_revision=1, authority_sha256="12" * 32)
    control = SimpleNamespace(binding=binding, stop_reason=lambda: "")
    epoch._control = control
    owner._launched = owner._drained = owner._normal_return = True
    return epoch, control


def test_next_tool_preserves_epoch_binding_and_deadlines_and_cannot_repeat(owner):
    epoch, control = tool_handoff(owner)
    before = (
        owner._binding,
        owner._lease,
        owner._hard,
        owner._work_end,
        owner._sequence,
        owner._exchange_v2.call_count,
    )
    owner.prepare_next_tool(control)
    assert owner._epoch is epoch
    assert not owner._launched and not owner._drained and not owner._normal_return
    assert (
        owner._binding,
        owner._lease,
        owner._hard,
        owner._work_end,
        owner._sequence,
        owner._exchange_v2.call_count,
    ) == before
    with pytest.raises(life.LifecycleUnavailable):
        owner.prepare_next_tool(control)


@pytest.mark.parametrize(
    "condition", ["stale", "uncertain", "expired", "stopped", "sealed", "abnormal"]
)
def test_next_tool_refuses_unproven_or_expired_handoff(monkeypatch, owner, condition):
    epoch, control = tool_handoff(owner)
    if condition == "stale":
        control = SimpleNamespace(binding=control.binding, stop_reason=lambda: "")
    elif condition == "uncertain":
        monkeypatch.setattr(owner, "_empty_children", lambda: False)
    elif condition == "expired":
        monkeypatch.setattr(life.time, "clock_gettime_ns", lambda clock: owner._lease)
    elif condition == "stopped":
        control.stop_reason = lambda: "local_emergency_stop"
    elif condition == "sealed":
        epoch.seal()
    else:
        owner._normal_return = False
    before = (owner._binding, owner._lease, owner._hard, owner._launched, owner._drained)
    with pytest.raises(life.LifecycleUnavailable):
        owner.prepare_next_tool(control)
    assert (owner._binding, owner._lease, owner._hard, owner._launched, owner._drained) == before
