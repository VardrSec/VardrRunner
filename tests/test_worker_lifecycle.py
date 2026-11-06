"""Protocol/state-machine tests; actual Linux credentials need native acceptance."""

import ctypes
import errno
import signal
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vardrrunner import execution_control
from vardrrunner import worker_lifecycle as life


@pytest.fixture
def admission():
    return SimpleNamespace(identity={"owner_nonce": "ab" * 32})


@pytest.fixture
def owner(monkeypatch, admission):
    monkeypatch.setattr(life, "_process_readback", lambda: None)
    monkeypatch.setattr(life.os, "WNOHANG", 1, raising=False)
    channel = Mock()
    channel.get_inheritable.return_value = False
    result = life.WorkerOwner(channel, admission, (1_000_000_000, 100.0))
    result._ready = True
    return result


def test_ordinary_linux_does_not_enable_control(monkeypatch):
    monkeypatch.setattr(execution_control.os, "name", "posix")
    monkeypatch.setattr(life, "_ACTIVE", None)
    assert not execution_control.available()
    assert life.current() is None


def test_current_requires_verified_live_context(monkeypatch, owner):
    monkeypatch.setattr(life, "_ACTIVE", owner)
    assert life.current() is owner
    owner._closed = True
    assert life.current() is None


@pytest.mark.parametrize("mutation", ["admission", "closed", "finished", "inherited", "pid"])
def test_readiness_refuses_incomplete_binding(monkeypatch, owner, mutation):
    arg = owner._admission
    if mutation == "admission":
        arg = object()
    elif mutation == "inherited":
        owner._channel.get_inheritable.return_value = True
    elif mutation == "pid":
        owner._pid += 1
    else:
        setattr(owner, "_" + mutation, True)
    with pytest.raises(life.LifecycleUnavailable):
        owner.require_ready(arg)


def test_prctl_propagates_failed_kernel_readback(monkeypatch):
    libc = SimpleNamespace(prctl=Mock(return_value=-1))
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: libc)
    with pytest.raises(life.LifecycleUnavailable):
        life._prctl(3)
    libc.prctl.return_value = 1
    assert life._prctl(3) == 1


@pytest.mark.parametrize(
    "fault", [None, "uid", "session", "signal", "blocked", "caps", "nnp", "subreaper"]
)
def test_actual_process_readback_checks_all_required_state(monkeypatch, tmp_path, fault):
    monkeypatch.setattr(signal, "SIGCHLD", 17, raising=False)
    monkeypatch.setattr(signal, "SIG_BLOCK", 0, raising=False)
    monkeypatch.setattr(life.sys, "platform", "linux")
    monkeypatch.setattr(life.sys, "byteorder", "little")
    monkeypatch.setattr(
        life.os, "getresuid", lambda: (0,) * 3 if fault == "uid" else (10001,) * 3, raising=False
    )
    monkeypatch.setattr(life.os, "getresgid", lambda: (10001,) * 3, raising=False)
    monkeypatch.setattr(life.os, "getgroups", lambda: [], raising=False)
    monkeypatch.setattr(life.os, "getppid", lambda: 1)
    monkeypatch.setattr(
        life.os,
        "getsid",
        lambda pid: 1 if fault == "session" or pid == 1 else life.os.getpid(),
        raising=False,
    )
    monkeypatch.setattr(
        signal, "getsignal", lambda sig: signal.SIG_IGN if fault == "signal" else signal.SIG_DFL
    )
    monkeypatch.setattr(
        signal,
        "pthread_sigmask",
        lambda *a: {signal.SIGCHLD} if fault == "blocked" else set(),
        raising=False,
    )
    status = tmp_path / "status"
    status.write_text(
        "\n".join(
            f"{k}: {1 if fault == 'caps' and k == 'CapBnd' else 0}"
            for k in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")
        )
        + f"\nNoNewPrivs: {0 if fault == 'nnp' else 1}\n",
        encoding="ascii",
    )
    real_open = open
    monkeypatch.setattr(life, "open", lambda *a, **k: real_open(status, **k), raising=False)

    def prctl(option, value=0):
        if option == 37:
            value._obj.value = 0 if fault == "subreaper" else 1
        return 1 if option == 39 else 0

    monkeypatch.setattr(life, "_prctl", prctl)
    if fault is None:
        life._process_readback()
    else:
        with pytest.raises(life.LifecycleUnavailable):
            life._process_readback()


@pytest.mark.parametrize("fault", [None, "flags", "size", "credential", "magic", "ancillary"])
def test_packets_require_exact_size_and_dynamic_owner_credentials(monkeypatch, owner, fault):
    monkeypatch.setattr(socket, "SCM_CREDENTIALS", 2, raising=False)
    monkeypatch.setattr(socket, "CMSG_SPACE", lambda n: n + 16, raising=False)
    data = life._PACKET.pack(0 if fault == "magic" else life._MAGIC, life._ACK, 1, 2, b"x" * 32)
    credential = life._CREDENTIALS.pack(2 if fault == "credential" else 1, 10000, 10000)
    ancillary = (
        [] if fault == "ancillary" else [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credential)]
    )
    owner._channel.recvmsg.return_value = (
        data[:-1] if fault == "size" else data,
        ancillary,
        1 if fault == "flags" else 0,
        None,
    )
    if fault is None:
        assert owner._receive() == (life._ACK, 1, 2, b"x" * 32)
    else:
        with pytest.raises(life.LifecycleUnavailable):
            owner._receive()


def test_exchange_requires_exact_matching_ack(monkeypatch, owner):
    owner._channel.send.return_value = life._PACKET.size
    monkeypatch.setattr(owner, "_receive", lambda: (life._ACK, 1, 2, b"x" * 32))
    owner._exchange(life._LEASE, 1, 2, b"x" * 32)
    with pytest.raises(life.LifecycleUnavailable):
        owner._exchange(life._LEASE, 1, 3, b"x" * 32)
    owner._channel.send.return_value = 0
    with pytest.raises(life.LifecycleUnavailable):
        owner._exchange(life._LEASE, 1, 2, b"x" * 32)


def test_lease_conversion_caps_hard_and_binds_single_attempt(monkeypatch, owner):
    monkeypatch.setattr(life.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(life.time, "clock_gettime_ns", lambda clock: 1_000_000_000, raising=False)
    exchange = Mock()
    monkeypatch.setattr(owner, "_exchange", exchange)
    owner.verified_lease({"attempt_id": "a"}, 105.0, 120.0)
    assert exchange.call_args.args[1:3] == (6_000_000_000, 21_000_000_000)
    owner.verified_lease({"attempt_id": "a"}, 106.0, 125.0)
    assert exchange.call_args.args[2] == 21_000_000_000
    with pytest.raises(life.LifecycleUnavailable):
        owner.verified_lease({"attempt_id": "b"}, 106.0, 120.0)


@pytest.mark.parametrize(
    "lease,hard",
    [(float("nan"), 120), (True, 120), (99, 120), (111, 120), (105, 104), (105, 86501)],
)
def test_lease_rejects_nonfinite_expired_and_unbounded_values(monkeypatch, owner, lease, hard):
    monkeypatch.setattr(life.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(life.time, "clock_gettime_ns", lambda clock: 0, raising=False)
    with pytest.raises(life.LifecycleUnavailable):
        owner.verified_lease({}, lease, hard)


def test_audit_barrier_covers_other_threads_and_unreviewed_exec(monkeypatch, owner):
    monkeypatch.setattr(life, "_ACTIVE", owner)
    life._audit("open", ())
    for event in life._SPAWN_EVENTS | {"os.exec", "os.system"}:
        with pytest.raises(life.LifecycleUnavailable):
            life._audit(event, ())
    owner._launch_thread = life.threading.get_ident()
    for event in life._SPAWN_EVENTS:
        life._audit(event, ())


def test_child_drain_requires_echild_and_wall(monkeypatch, owner):
    outcomes = iter([InterruptedError(), (22, 0), (0, 0), ChildProcessError()])

    def wait(pid, flags):
        assert pid == -1 and flags == life.os.WNOHANG | life._WALL
        result = next(outcomes)
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(life.os, "waitpid", wait, raising=False)
    assert not owner._empty_children()
    assert owner._empty_children()
    monkeypatch.setattr(life.os, "waitpid", Mock(side_effect=OSError(errno.EIO, "unsafe")))
    with pytest.raises(life.LifecycleUnavailable):
        owner._empty_children()
    monkeypatch.setattr(life.os, "waitpid", Mock(side_effect=OSError(errno.ECHILD, "empty")))
    assert owner._empty_children()


def test_finish_requires_drain_and_durable_caller_before_done(monkeypatch, owner):
    monkeypatch.setattr(owner, "_exchange", Mock())
    monkeypatch.setattr(owner, "_empty_children", lambda: True)
    with pytest.raises(life.LifecycleUnavailable):
        owner.finished()
    owner._binding = b"b" * 32
    owner._launched = owner._drained = True
    owner.finished()
    owner._exchange.assert_called_once_with(life._DONE, 0, 0, b"b" * 32)
    with pytest.raises(life.LifecycleUnavailable):
        owner.finished()


def test_control_dispatches_only_verified_worker(monkeypatch, owner):
    monkeypatch.setattr(execution_control.os, "name", "posix")
    monkeypatch.setattr(life, "_ACTIVE", owner)
    monkeypatch.setattr(owner, "run", Mock(return_value=3))
    control = Mock()
    control.stop_reason.return_value = ""
    assert execution_control.run(["fixed-tool"], 1, None, control) == 3


@pytest.mark.parametrize(
    "ending", ["normal", "descendant", "stopped", "grace", "uncertain", "observer"]
)
def test_run_uses_existing_launcher_and_requires_actual_drain(monkeypatch, owner, ending):
    from vardrrunner import runner

    owner._binding = b"a" * 32
    owner._hard = owner._lease = 10_000_000_000
    events = []
    process = SimpleNamespace(pid=42, poll=Mock(return_value=0))
    if ending in {"grace", "uncertain"}:
        process.poll = Mock(side_effect=[None, 0] if ending == "grace" else [None] * 20)

    def spawn(cmd):
        assert cmd == ["reviewed-tool"]
        assert owner._launch_thread == life.threading.get_ident()
        events.append("spawn")
        return process

    monkeypatch.setattr(runner, "_spawn_tool", spawn)
    emptiness = iter([True, False, True] if ending == "descendant" else [True, True])
    monkeypatch.setattr(owner, "_empty_children", lambda: next(emptiness))
    monkeypatch.setattr(life.launch_guard, "timeout", lambda seconds: seconds)
    monkeypatch.setattr(life.time, "sleep", lambda seconds: events.append("sleep"))
    monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(life.time, "clock_gettime_ns", lambda clock: 0, raising=False)
    ticks = iter(i / 100 for i in range(100))
    monkeypatch.setattr(life.time, "monotonic", lambda: next(ticks))
    killed = Mock()
    monkeypatch.setattr(life.os, "killpg", killed, raising=False)
    control = SimpleNamespace(
        stop_reason=lambda: "remote_stop" if ending in {"stopped", "grace", "uncertain"} else "",
        grace=0.02,
    )

    def observer(pid):
        assert pid == 42
        if ending == "observer":
            raise OSError("journal unavailable")

    if ending in {"normal", "descendant"}:
        assert owner.run(["reviewed-tool"], 1, observer, control) == 0
        assert owner._drained
    elif ending == "observer":
        with pytest.raises(OSError):
            owner.run(["reviewed-tool"], 1, observer, control)
        assert not owner._drained
    else:
        with pytest.raises(execution_control.ExecutionStopped) as caught:
            owner.run(["reviewed-tool"], 1, observer, control)
        assert caught.value.confirmed is (ending != "uncertain")
        if ending in {"grace", "uncertain"}:
            killed.assert_called_once_with(42, signal.SIGTERM)
    assert events[0] == "spawn" and owner._launch_thread is None
    with pytest.raises(life.LifecycleUnavailable):
        owner.run(["reviewed-tool"], 1, None, control)


@pytest.mark.parametrize("fault", [None, "nonce", "platform", "readback", "socket"])
def test_connect_requires_actual_private_handshake_and_cleans_context(
    monkeypatch, admission, fault
):
    monkeypatch.setattr(life.sys, "platform", "win32" if fault == "platform" else "linux")
    monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(life.time, "clock_gettime_ns", lambda clock: 1_000_000_000, raising=False)
    monkeypatch.setattr(life, "_ACTIVE", None)
    monkeypatch.setattr(life, "_HOOK_INSTALLED", False)
    monkeypatch.setattr(life.threading, "active_count", lambda: 1)
    monkeypatch.setattr(life, "_prctl", lambda *args: 0)
    readback = Mock(side_effect=life.LifecycleUnavailable() if fault == "readback" else None)
    monkeypatch.setattr(life, "_process_readback", readback)
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(socket, "SO_PASSCRED", 16, raising=False)
    monkeypatch.setattr(socket, "SOCK_SEQPACKET", 5, raising=False)
    channel = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
    channel.getsockopt.return_value = 1
    channel.get_inheritable.return_value = False
    factory = Mock(return_value=channel, side_effect=OSError() if fault == "socket" else None)
    monkeypatch.setattr(socket, "socket", factory)
    monkeypatch.setattr(
        life.WorkerOwner,
        "_receive",
        lambda self: (life._READY, 0, 0, bytes.fromhex(("cd" if fault == "nonce" else "ab") * 32)),
    )
    monkeypatch.setattr(life.WorkerOwner, "_exchange", lambda *args: None)
    hooked = Mock()
    monkeypatch.setattr(life.sys, "addaudithook", hooked)
    if fault is None:
        with life.connect(admission) as connected:
            assert life.current() is connected
            connected.require_ready(admission)
        assert life.current() is None
        channel.close.assert_called_once()
        channel.set_inheritable.assert_called_once_with(False)
        hooked.assert_called_once_with(life._audit)
    else:
        with pytest.raises((life.LifecycleUnavailable, OSError)):
            with life.connect(admission):
                pytest.fail("unverified owner accepted")
        assert life.current() is None
        if fault == "nonce":
            channel.close.assert_called_once()


def test_clock_conversion_samples_boottime_before_monotonic(monkeypatch, owner):
    calls = []
    monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(
        life.time,
        "clock_gettime_ns",
        lambda clock: calls.append("boot") or 1_000_000_000,
        raising=False,
    )
    monkeypatch.setattr(life.time, "monotonic", lambda: calls.append("mono") or 100.0)
    monkeypatch.setattr(owner, "_exchange", Mock())
    owner.verified_lease({}, 105.0, 120.0)
    assert calls == ["boot", "mono"]


@pytest.mark.parametrize("pause", ["before_first", "later_refresh", "between_samples"])
def test_connection_anchor_never_moves_authority_forward_after_pause(monkeypatch, owner, pause):
    monkeypatch.setattr(life.time, "CLOCK_BOOTTIME", 7, raising=False)
    mono, boot = [100.0], [1_000_000_000]
    monkeypatch.setattr(life.time, "clock_gettime_ns", lambda clock: boot[0], raising=False)
    monkeypatch.setattr(life.time, "monotonic", lambda: mono[0])
    exchange = Mock()
    monkeypatch.setattr(owner, "_exchange", exchange)
    if pause == "later_refresh":
        owner.verified_lease({}, 105.0, 120.0)
    if pause == "between_samples":
        # A pause after the BOOTTIME anchor and before MONOTONIC makes its
        # offset conservative; it must not add the pause back at first arm.
        owner._clock_boot, owner._clock_monotonic = 1_000_000_000, 102.0
        mono[0] = 102.0
    boot[0] = 8_000_000_000
    with pytest.raises(life.LifecycleUnavailable):
        owner.verified_lease({}, 105.0, 120.0)
    assert exchange.call_count == (1 if pause == "later_refresh" else 0)
