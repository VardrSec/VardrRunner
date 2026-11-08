"""Pure v3 channel/epoch tests; not platform or containment acceptance."""

import copy
import hashlib
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_worker_admission import NOW
from tests.test_worker_admission import admission_document as admission_document
from tests.test_worker_persistent_admission import persistent_document as persistent_document
from vardrrunner import worker_lifecycle as life
from vardrrunner.authorization.codec import digest, encoded
from vardrrunner.authorization.worker_admission import Admission


@pytest.fixture
def context(monkeypatch, persistent_document):
    clock = {"boot": 1_000_000_000, "mono": 100.0}
    monkeypatch.setattr(life, "_process_readback", lambda: None)
    monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(life.time, "clock_gettime_ns", lambda _: clock["boot"], raising=False)
    monkeypatch.setattr(life.time, "monotonic", lambda: clock["mono"])

    def create(limits=None):
        document = copy.deepcopy(persistent_document)
        if limits is not None:
            del document["admission_sha256"]
            document["limits"] = limits
            document["admission_sha256"] = digest(encoded(document))
        admission = Admission.parse(document, now=NOW)
        channel = Mock()
        channel.get_inheritable.return_value = False
        owner = life.PersistentWorkerOwner(channel, admission, (0, 0.0), (1 << 64) - 1)
        owner._ready = True
        monkeypatch.setattr(owner, "_empty_children", lambda: True)
        monkeypatch.setattr(owner, "_exchange_v2", Mock(return_value="ef" * 32))
        return owner

    return SimpleNamespace(create=create, clock=clock)


def binding(owner, sequence):
    return {
        "origin": owner._admission.origin,
        "runner_id": owner._admission.runner_id,
        "job_id": "job-" + str(sequence),
        "contract_id": "22222222-2222-4222-8222-222222222222",
        "attempt_id": "33333333-3333-4333-8333-333333333333",
        "fence": 1,
        "contract_sha256": "ab" * 32,
    }


def complete(owner, epoch):
    owner._launched = owner._drained = owner._normal_return = True
    epoch._control = SimpleNamespace(
        worker_quiescent=lambda: True, stop_reason=lambda: "", worker_reuse_safe=lambda: True
    )
    epoch.seal()
    assert epoch.finished() == "ef" * 32


def test_default_hello_carries_no_job_deadline_and_no_implicit_finite_limits(context, monkeypatch):
    owner = context.create()
    nonce = bytes.fromhex(owner._admission.identity["owner_nonce"])
    monkeypatch.setattr(owner, "_receive_v2", lambda: (life._READY, 0, 0, 0, nonce))
    owner._handshake(nonce)
    owner._exchange_v2.assert_called_once_with(life._HELLO, 0, 0, 0, nonce)
    assert owner._binding is None and owner._lease == owner._hard == 0
    assert not owner._launched and owner._idle_end == (1 << 64) - 1


def test_more_than_32_epochs_and_hours_of_idle_need_fresh_finite_job_permission(context):
    owner = context.create()
    previous = None
    for number in range(1, 41):
        context.clock.update(boot=number * 3600 * life._SECOND, mono=number * 3600.0)
        owner.require_ready(owner._admission)
        epoch = owner.begin_attempt(number)
        assert owner._binding is None and owner._lease == owner._hard == 0
        if previous is not None:
            before = owner._exchange_v2.call_count
            with pytest.raises(life.LifecycleUnavailable):
                previous.verified_lease(
                    binding(owner, number), context.clock["mono"] + 5, context.clock["mono"] + 20
                )
            assert owner._exchange_v2.call_count == before
        epoch.verified_lease(
            binding(owner, number), context.clock["mono"] + 5, context.clock["mono"] + 20
        )
        assert owner._hard == context.clock["boot"] + 20 * life._SECOND
        complete(owner, epoch)
        previous = epoch


def test_binding_digest_includes_admission_and_exact_decimal_sequence(context):
    owner = context.create()
    number = 9007199254740993
    owner._sequence = number - 1
    epoch = owner.begin_attempt(number)
    current = binding(owner, number)
    epoch.verified_lease(current, 105.0, 120.0)
    expected = hashlib.sha256(
        encoded(
            {
                "runtime_id": owner._admission.runtime_id,
                "runtime_sha256": owner._admission.runtime_sha256,
                "admission_sha256": owner._admission.admission_sha256,
                "runtime_sequence": str(number),
                "binding": current,
            }
        )
    ).digest()
    assert owner._exchange_v2.call_args.args == (
        life._LEASE,
        number,
        6 * life._SECOND,
        21 * life._SECOND,
        expected,
    )


def test_optional_idle_and_attempt_limits_are_fixed_policy(context, monkeypatch):
    owner = context.create({"max_attempts": "1", "idle_timeout_seconds": 2})
    nonce = bytes.fromhex(owner._admission.identity["owner_nonce"])
    monkeypatch.setattr(owner, "_receive_v2", lambda: (life._READY, 0, 0, 0, nonce))
    owner._handshake(nonce)
    owner._exchange_v2.assert_called_with(life._HELLO, 0, 2, 1, nonce)
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(binding(owner, 1), 105.0, 120.0)
    complete(owner, epoch)
    with pytest.raises(life.LifecycleUnavailable):
        owner.begin_attempt(2)
    context.clock["boot"] = owner._idle_end
    with pytest.raises(life.LifecycleUnavailable):
        owner.require_ready(owner._admission)


@pytest.mark.parametrize("failure", ["stop", "abnormal", "not_quiescent", "refresh"])
def test_drained_or_failed_alone_never_permits_done(context, failure):
    owner = context.create()
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(binding(owner, 1), 105.0, 120.0)
    owner._launched = owner._drained = True
    owner._normal_return = failure != "abnormal"
    epoch._control = SimpleNamespace(
        worker_quiescent=lambda: failure != "not_quiescent",
        stop_reason=lambda: "control_lease_expired" if failure == "stop" else "",
        worker_reuse_safe=lambda: failure != "refresh",
    )
    epoch.seal()
    before = owner._exchange_v2.call_count
    with pytest.raises(life.LifecycleUnavailable):
        epoch.finished()
    assert owner._exchange_v2.call_count == before


def test_active_clock_anchor_never_rebases_but_next_fresh_attempt_can_follow_pause(context):
    owner = context.create()
    epoch = owner.begin_attempt(1)
    context.clock["boot"] += 500 * life._SECOND
    with pytest.raises(life.LifecycleUnavailable):
        epoch.verified_lease(binding(owner, 1), 105.0, 120.0)
    assert not owner._exchange_v2.called
    # A separate idle incarnation's new attempt samples its own BOOT/MONO pair.
    other = context.create()
    fresh = other.begin_attempt(1)
    fresh.verified_lease(binding(other, 1), 105.0, 120.0)
    assert other._hard == 521 * life._SECOND


def test_persistent_private_channel_rejects_finite_magic(context, monkeypatch):
    owner = context.create()
    monkeypatch.setattr(socket, "SCM_CREDENTIALS", 2, raising=False)
    monkeypatch.setattr(socket, "CMSG_SPACE", lambda size: size, raising=False)
    owner._channel.recvmsg.return_value = (
        life._PACKET_V2.pack(life._MAGIC_V2, life._READY, 0, 0, 0, b"0" * 32),
        [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, life._CREDENTIALS.pack(1, 10000, 10000))],
        0,
        None,
    )
    with pytest.raises(life.LifecycleUnavailable):
        owner._receive_v2()


def test_fresh_attempt_after_modeled_idle_pause_does_not_rebase_old_epoch(context):
    owner = context.create()
    first = owner.begin_attempt(1)
    first.verified_lease(binding(owner, 1), 105.0, 120.0)
    complete(owner, first)
    context.clock["boot"] += 500 * life._SECOND
    second = owner.begin_attempt(2)
    second.verified_lease(binding(owner, 2), 105.0, 120.0)
    assert owner._hard == 521 * life._SECOND
    with pytest.raises(life.LifecycleUnavailable):
        first.verified_lease(binding(owner, 1), 105.0, 120.0)


def test_expired_active_permission_cannot_become_idle_even_with_mock_done_ack(context):
    owner = context.create()
    epoch = owner.begin_attempt(1)
    epoch.verified_lease(binding(owner, 1), 105.0, 120.0)
    owner._launched = owner._drained = owner._normal_return = True
    epoch._control = SimpleNamespace(
        worker_quiescent=lambda: True, stop_reason=lambda: "", worker_reuse_safe=lambda: True
    )
    epoch.seal()
    before = owner._exchange_v2.call_count
    context.clock["boot"] = owner._lease
    with pytest.raises(life.LifecycleUnavailable):
        epoch.finished()
    assert owner._exchange_v2.call_count == before


def test_explicit_v3_connect_never_uses_legacy_admission_expiry(context, monkeypatch):
    owner = context.create()
    monkeypatch.setattr(life.sys, "platform", "linux")
    monkeypatch.setattr(life, "_ACTIVE", None)
    monkeypatch.setattr(life, "_HOOK_INSTALLED", False)
    monkeypatch.setattr(life.threading, "active_count", lambda: 1)
    monkeypatch.setattr(life, "_prctl", lambda *args: 0)
    monkeypatch.setattr(
        life,
        "_incarnation_clock",
        Mock(side_effect=AssertionError("availability has no legacy expiry")),
    )
    monkeypatch.setattr(socket, "SO_PASSCRED", 16, raising=False)
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(socket, "SOCK_SEQPACKET", 5, raising=False)
    channel = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
    channel.getsockopt.return_value = 1
    channel.get_inheritable.return_value = False
    monkeypatch.setattr(socket, "socket", lambda **kwargs: channel)
    monkeypatch.setattr(
        life.PersistentWorkerOwner,
        "_receive_v2",
        lambda self: (
            life._READY,
            0,
            0,
            0,
            bytes.fromhex(owner._admission.identity["owner_nonce"]),
        ),
    )
    monkeypatch.setattr(life.PersistentWorkerOwner, "_exchange_v2", Mock(return_value="ab" * 32))
    monkeypatch.setattr(life.sys, "addaudithook", Mock())
    with life.connect(owner._admission) as connected:
        assert isinstance(connected, life.PersistentWorkerOwner)
        assert connected._binding is None and connected._lease == connected._hard == 0
    channel.close.assert_called_once()


def test_idle_never_authorizes_native_launch_and_int64_never_wraps(context):
    owner = context.create()
    with pytest.raises(life.LifecycleUnavailable):
        owner.run(["never-spawn"], 1, None, Mock())
    owner._sequence = (1 << 63) - 1
    with pytest.raises(life.LifecycleUnavailable):
        owner.begin_attempt(1 << 63)
