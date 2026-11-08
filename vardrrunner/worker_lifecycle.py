"""Worker-only private PID-1 channel and single-attempt Linux child ownership.

Admission JSON is public correlation metadata. Only the inherited, credentialed
native-owner channel plus actual process readbacks enable controlled execution.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import math
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, NoReturn

from vardrrunner import launch_guard
from vardrrunner.authorization.codec import encoded
from vardrrunner.authorization.persistent_codec import MAX_SEQUENCE, wire_sequence64

if TYPE_CHECKING:
    from vardrrunner.authorization.local_admission import LocalAdmission
    from vardrrunner.authorization.worker_admission import Admission
    from vardrrunner.execution_control import Control

_PACKET = struct.Struct("<IIQQ32s")
_PACKET_V2 = struct.Struct("<IIQQQ32s")
_CREDENTIALS = struct.Struct("=iii")
_MAGIC = 0x31574456
_MAGIC_V2 = 0x32574456
_MAGIC_V3 = 0x33574456
_READY, _HELLO, _LEASE, _DONE, _ACK = 1, 2, 3, 4, 5
_WALL = 0x40000000
REPORT_RUNWAY_SECONDS = 150
_SECOND = 1_000_000_000
_IDLE_SECONDS = 60
_IDLE_STOP_RESERVE = 5 * _SECOND
_BINDING = frozenset(
    {"origin", "job_id", "runner_id", "contract_id", "attempt_id", "fence", "contract_sha256"}
)
_CONTROL_BINDING = (_BINDING - {"contract_sha256"}) | {"authority_revision", "authority_sha256"}
_ACTIVE: WorkerOwner | None = None
_GLOBAL = threading.Lock()
_HOOK_INSTALLED = False
_SPAWN_EVENTS = frozenset({"subprocess.Popen", "os.fork", "os.forkpty", "os.posix_spawn"})


class LifecycleUnavailable(RuntimeError):
    """Incomplete ownership or child-drain proof; retain the attempt hold."""


class IdleBoundaryReached(LifecycleUnavailable):
    """Verified v3 idle cutoff reached; no execution permission remains."""


def _require(value: object) -> None:
    if not value:
        raise LifecycleUnavailable("worker_lifecycle_unavailable")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _incarnation_clock(admission: Admission | LocalAdmission) -> tuple[tuple[int, float], int]:
    # UTC last is conservative across pauses between the elapsed-clock samples
    # and timestamp validation. Later conversions never resample this offset.
    boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
    mono = time.monotonic()
    now = _utcnow()
    expiry = admission.expires_at
    _require(isinstance(expiry, datetime) and expiry.tzinfo is not None)
    assert expiry is not None
    remaining = (expiry - now).total_seconds()
    _require(REPORT_RUNWAY_SECONDS < remaining <= 604800)
    grant_end = boot + int(remaining * _SECOND)
    return (boot, mono), grant_end


def _prctl(option: int, value: object = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(ctypes.c_int(option), value, 0, 0, 0)
    if result < 0:
        raise LifecycleUnavailable("worker_kernel_readback_unavailable")
    return int(result)


def _process_readback() -> None:
    _require(sys.platform == "linux" and sys.byteorder == "little")
    _require(os.getresuid() == (10001,) * 3 and os.getresgid() == (10001,) * 3)  # type: ignore[attr-defined]
    _require(not os.getgroups() and os.getppid() == 1)  # type: ignore[attr-defined]
    _require(os.getsid(0) == os.getpid() and os.getsid(0) != os.getsid(1))  # type: ignore[attr-defined]
    _require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)  # type: ignore[attr-defined]
    _require(signal.SIGCHLD not in signal.pthread_sigmask(signal.SIG_BLOCK, []))  # type: ignore[attr-defined]
    _require(_prctl(3) == 0)  # PR_GET_DUMPABLE; tools cannot recover fd3 via procfs.
    _require(_prctl(39) == 1)  # PR_GET_NO_NEW_PRIVS; no privilege from later exec.
    with open("/proc/self/status", encoding="ascii") as stream:
        status = dict(line.strip().split(":", 1) for line in stream if ":" in line)
    for field in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"):
        _require(int(status[field].strip(), 16) == 0)
    _require(status["NoNewPrivs"].strip() == "1")
    subreaper = ctypes.c_int()
    _prctl(37, ctypes.byref(subreaper))
    _require(subreaper.value == 1)


def _audit(event: str, _args: tuple) -> None:
    owner = _ACTIVE
    if owner is not None:
        if event in _SPAWN_EVENTS:
            _require(owner._launch_thread == threading.get_ident())
        elif event in {"os.exec", "os.system"}:
            raise LifecycleUnavailable("worker_unreviewed_process_creation")


def current() -> WorkerOwner | None:
    owner = _ACTIVE
    return owner if owner is not None and owner._ready and not owner._closed else None


class WorkerOwner:
    """One exact native owner, one immutable attempt binding, one tool lineage."""

    def __init__(
        self,
        channel: socket.socket,
        admission: Admission | LocalAdmission,
        clock_anchor: tuple[int, float],
        grant_end: int,
    ):
        self._channel = channel
        self._admission = admission
        self._pid = os.getpid()
        self._clock_boot, self._clock_monotonic = clock_anchor
        self._grant_end = grant_end
        self._work_end = grant_end - REPORT_RUNWAY_SECONDS * _SECOND
        self._lock = threading.Lock()
        self._ready = False
        self._closed = False
        self._binding: bytes | None = None
        self._hard = 0
        self._lease = 0
        self._launched = False
        self._drained = False
        self._normal_return = False
        self._finished = False
        self._launch_thread: int | None = None

    def _receive(self) -> tuple[int, int, int, bytes]:
        data, ancillary, flags, _ = self._channel.recvmsg(  # type: ignore[attr-defined]
            _PACKET.size,
            socket.CMSG_SPACE(_CREDENTIALS.size),  # type: ignore[attr-defined]
        )
        _require(not flags and len(data) == _PACKET.size and len(ancillary) == 1)
        level, kind, credential = ancillary[0]
        _require(level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS)  # type: ignore[attr-defined]
        _require(len(credential) == _CREDENTIALS.size)
        _require(_CREDENTIALS.unpack(credential) == (1, 10000, 10000))
        magic, kind, lease, hard, binding = _PACKET.unpack(data)
        _require(magic == _MAGIC)
        return kind, lease, hard, binding

    def _exchange(self, kind: int, lease: int, hard: int, binding: bytes) -> None:
        _require(
            self._channel.send(_PACKET.pack(_MAGIC, kind, lease, hard, binding)) == _PACKET.size
        )
        _require(self._receive() == (_ACK, lease, hard, binding))

    def _handshake(self, nonce: bytes) -> None:
        _require(self._receive() == (_READY, 0, 0, nonce))
        _require(time.clock_gettime_ns(time.CLOCK_BOOTTIME) < self._work_end)  # type: ignore[attr-defined]
        self._exchange(_HELLO, self._work_end, self._grant_end, nonce)

    def require_ready(self, admission: Admission | LocalAdmission) -> None:
        _require(self._ready and not self._closed and os.getpid() == self._pid)
        _require(admission == self._admission and not self._finished)
        _process_readback()
        _require(not self._channel.get_inheritable())
        _require(time.clock_gettime_ns(time.CLOCK_BOOTTIME) < self._work_end)  # type: ignore[attr-defined]

    def require_allocation(self, seconds: int) -> None:
        """Refuse before claim RPC unless the entire requested allocation fits."""
        self.require_ready(self._admission)
        _require(type(seconds) is int and 1 <= seconds <= 86400)
        boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
        _require(boot + seconds * _SECOND <= self._work_end)

    def verified_lease(
        self, binding: dict, lease_end_monotonic: float, hard_end_monotonic: float
    ) -> None:
        """Called only after the existing ManagedGate validates current authority."""
        with self._lock:
            self.require_ready(self._admission)
            for value in (lease_end_monotonic, hard_end_monotonic):
                _require(type(value) in (int, float) and math.isfinite(value))
            boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
            mono = time.monotonic()
            lease_remaining = lease_end_monotonic - mono
            hard_remaining = hard_end_monotonic - mono
            _require(0 < lease_remaining <= 10 and lease_remaining <= hard_remaining <= 86400)
            # Absolute BOOTTIME values: IPC latency never extends permission.
            lease = self._clock_boot + int(
                (lease_end_monotonic - self._clock_monotonic) * 1_000_000_000
            )
            hard = self._clock_boot + int(
                (hard_end_monotonic - self._clock_monotonic) * 1_000_000_000
            )
            hard = min(hard, self._work_end)
            hashed = hashlib.sha256(encoded(binding)).digest()
            if self._binding is not None:
                _require(hashed == self._binding)
                hard = min(hard, self._hard)
            lease = min(lease, hard)
            _require(boot < lease <= hard)
            self._exchange(_LEASE, lease, hard, hashed)
            self._binding, self._hard, self._lease = hashed, hard, lease

    def _empty_children(self) -> bool:
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG | _WALL)  # type: ignore[attr-defined]
            except InterruptedError:
                continue
            except ChildProcessError:
                return True
            except OSError as exc:
                if exc.errno == errno.ECHILD:
                    return True
                raise LifecycleUnavailable("worker_child_wait_uncertain") from exc
            if pid == 0:
                return False

    def run(
        self, cmd: list[str], seconds: int, observer: Callable[[int], None] | None, control: Control
    ) -> int:
        """Reuse Runner's sole launcher; wait direct tool then all adopted children."""
        from vardrrunner import execution_control, runner

        self.require_ready(self._admission)
        _require(self._binding is not None and not self._launched)
        _require(self._empty_children())
        self._launched = True
        self._launch_thread = threading.get_ident()
        try:
            process = runner._spawn_tool(cmd)
        finally:
            self._launch_thread = None
        started = time.monotonic()
        try:
            if observer is not None:
                observer(process.pid)
            while True:
                reason = control.stop_reason()
                if launch_guard.timeout(seconds) <= 0:
                    reason = reason or "authorization_deadline"
                if time.monotonic() - started >= seconds:
                    reason = reason or "tool_timeout"
                code = process.poll()
                if code is not None and self._empty_children():
                    self._drained = True
                    if reason:
                        raise execution_control.ExecutionStopped(reason, True)
                    self._normal_return = True
                    return code
                if reason:
                    # Best-effort group cleanup cannot prove escaped descendants.
                    # Leave the owner armed; only ECHILD or host exit may confirm.
                    try:
                        os.killpg(process.pid, signal.SIGTERM)  # type: ignore[attr-defined]
                    except ProcessLookupError:
                        pass
                    remaining = (
                        min(self._lease, self._hard) - time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
                    ) / 1_000_000_000
                    until = time.monotonic() + max(0.0, min(control.grace, remaining))
                    while time.monotonic() < until:
                        code = process.poll()
                        if code is not None and self._empty_children():
                            self._drained = True
                            raise execution_control.ExecutionStopped(reason, True)
                        time.sleep(0.02)
                    raise execution_control.ExecutionStopped(reason, False, pid=process.pid)
                time.sleep(0.02)
        except BaseException:
            # No disarm or manufactured stop receipt. PID1 keeps its last lease.
            raise

    def finished(self) -> None:
        with self._lock:
            self.require_ready(self._admission)
            binding = self._binding
            if binding is None:
                raise LifecycleUnavailable("worker_attempt_not_armed")
            _require(self._launched and self._drained)
            _require(self._empty_children())
            self._exchange(_DONE, 0, 0, binding)
            self._finished = True


class AttemptEpoch:
    """An immutable sequence identity; stale callbacks never select a newer attempt."""

    def __init__(self, owner: SequentialWorkerOwner, sequence: int):
        self._owner, self._sequence = owner, sequence
        self._sealed = self._finished = False
        self._binding: dict | None = None
        self._control: Control | None = None
        self._clock_boot, self._clock_monotonic = owner._epoch_clock()

    @property
    def runtime_sequence(self) -> int:
        return self._sequence

    def _current(self) -> None:
        self._owner.require_ready(self._owner._admission)
        _require(self._owner._epoch is self and not self._finished)

    def require_active(self) -> None:
        self._current()
        _require(not self._sealed)

    def verified_lease(self, binding: dict, lease_end: float, hard_end: float) -> None:
        owner = self._owner
        with owner._lock:
            self.require_active()
            _require(type(binding) is dict and set(binding) == _BINDING)
            _require(binding["origin"] == owner._admission.origin)
            _require(binding["runner_id"] == owner._admission.runner_id)
            _require(
                type(binding["job_id"]) is str
                and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", binding["job_id"])
            )
            for key in ("runner_id", "contract_id", "attempt_id"):
                _require(type(binding[key]) is str and str(uuid.UUID(binding[key])) == binding[key])
            _require(type(binding["fence"]) is int and 1 <= binding["fence"] <= 2**53 - 1)
            _require(
                type(binding["contract_sha256"]) is str
                and re.fullmatch(r"[a-f0-9]{64}", binding["contract_sha256"])
            )
            _require(self._binding is None or self._binding == binding)
            for value in (lease_end, hard_end):
                _require(type(value) in (int, float) and math.isfinite(value))
            boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
            mono = time.monotonic()
            _require(0 < lease_end - mono <= 10 and lease_end <= hard_end <= mono + 86400)
            lease = self._clock_boot + int((lease_end - self._clock_monotonic) * _SECOND)
            hard = min(
                self._clock_boot + int((hard_end - self._clock_monotonic) * _SECOND),
                owner._work_end,
            )
            if self._binding is not None:
                hard = min(hard, owner._hard)
            lease = min(lease, hard)
            _require(boot < lease <= hard)
            hashed = hashlib.sha256(
                encoded(owner._attempt_binding(self._sequence, binding))
            ).digest()
            owner._exchange_v2(_LEASE, self._sequence, lease, hard, hashed)
            self._binding = dict(binding)
            owner._binding, owner._lease, owner._hard = hashed, lease, hard

    def seal(self) -> None:
        with self._owner._lock:
            self._current()
            self._sealed = True

    def quiescence_deadline(self) -> float:
        with self._owner._lock:
            self._current()
            # Inverse conversion samples MONOTONIC first, BOOTTIME last: a
            # pause can only shorten the remaining native-owner wait budget.
            mono = time.monotonic()
            boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
            ceiling = min(self._owner._lease, self._owner._hard, self._owner._work_end)
            return mono + max(0.0, (ceiling - boot) / _SECOND)

    def finished(self) -> str:
        owner = self._owner
        with owner._lock:
            self._current()
            _require(self._sealed and self._binding is not None)
            _require(self._control is not None and self._control.worker_quiescent())
            assert self._control is not None
            _require(owner._launched and owner._drained and owner._empty_children())
            if isinstance(owner, PersistentWorkerOwner):
                _require(owner._normal_return and not self._control.stop_reason())
                _require(self._control.worker_reuse_safe())
            binding = owner._binding
            if binding is None:
                raise LifecycleUnavailable("worker_attempt_not_armed")
            before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
            _require(before < min(owner._lease, owner._hard, owner._work_end))
            proof = owner._exchange_v2(_DONE, self._sequence, 0, 0, binding)
            owner._idle_end = owner._next_idle_end(before)
            if (
                isinstance(owner, PersistentWorkerOwner)
                and owner._admission.idle_timeout_seconds is not None
            ):
                owner._idle_wait_end = owner._next_idle_wait_end(
                    time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
                )
            self._finished = True
            return proof


class SequentialWorkerOwner(WorkerOwner):
    """V2 native channel with bounded idle and per-attempt ownership epochs."""

    _magic = _MAGIC_V2

    def __init__(
        self,
        channel: socket.socket,
        admission: Admission | LocalAdmission,
        clock_anchor: tuple[int, float],
        grant_end: int,
    ):
        super().__init__(channel, admission, clock_anchor, grant_end)
        _require(getattr(admission, "mode", None) is None)
        _require(
            type(self._admission.max_attempts) is int and 1 <= self._admission.max_attempts <= 32
        )
        self._epoch: AttemptEpoch | None = None
        self._sequence = 0
        self._idle_end = self._work_end

    def _epoch_clock(self) -> tuple[int, float]:
        return self._clock_boot, self._clock_monotonic

    def _sequence_limit(self) -> int:
        maximum = self._admission.max_attempts
        _require(maximum is not None)
        assert maximum is not None
        return maximum

    def _next_idle_end(self, before: int) -> int:
        return min(before + _IDLE_SECONDS * _SECOND, self._work_end)

    def _attempt_binding(self, sequence: int, binding: dict) -> dict:
        return {
            "runtime_id": self._admission.runtime_id,
            "runtime_sha256": self._admission.runtime_sha256,
            "runtime_sequence": sequence,
            "binding": binding,
        }

    def _receive_v2(self) -> tuple[int, int, int, int, bytes]:
        data, ancillary, flags, _ = self._channel.recvmsg(  # type: ignore[attr-defined]
            _PACKET_V2.size,
            socket.CMSG_SPACE(_CREDENTIALS.size),  # type: ignore[attr-defined]
        )
        _require(not flags and len(data) == _PACKET_V2.size and len(ancillary) == 1)
        level, kind, credentials = ancillary[0]
        _require(level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS)  # type: ignore[attr-defined]
        _require(len(credentials) == _CREDENTIALS.size)
        _require(_CREDENTIALS.unpack(credentials) == (1, 10000, 10000))
        magic, kind, sequence, lease, hard, binding = _PACKET_V2.unpack(data)
        _require(magic == self._magic)
        return kind, sequence, lease, hard, binding

    def _exchange_v2(self, kind: int, sequence: int, lease: int, hard: int, binding: bytes) -> str:
        _require(
            self._channel.send(_PACKET_V2.pack(self._magic, kind, sequence, lease, hard, binding))
            == _PACKET_V2.size
        )
        _require(self._receive_v2() == (_ACK, sequence, lease, hard, binding))
        return hashlib.sha256(
            _PACKET_V2.pack(self._magic, _ACK, sequence, lease, hard, binding)
        ).hexdigest()

    def _handshake_local(self) -> None:
        """Accept freshness only from the already credential-checked PID-1 peer."""
        kind, sequence, lease, hard, nonce = self._receive_v2()
        _require((kind, sequence, lease, hard) == (_READY, 0, 0, 0))
        self._hello(nonce)

    def _handshake(self, nonce: bytes) -> None:
        _require(self._receive_v2() == (_READY, 0, 0, 0, nonce))
        self._hello(nonce)

    def _hello(self, nonce: bytes) -> None:
        before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
        _require(before < self._work_end)
        self._exchange_v2(_HELLO, 0, self._work_end, self._grant_end, nonce)
        self._idle_end = min(before + _IDLE_SECONDS * _SECOND, self._work_end)

    def require_ready(self, admission: Admission | LocalAdmission) -> None:
        super().require_ready(admission)
        if self._epoch is None or self._epoch._finished or self._binding is None:
            _require(time.clock_gettime_ns(time.CLOCK_BOOTTIME) < self._idle_end)  # type: ignore[attr-defined]

    def begin_attempt(self, runtime_sequence: int) -> AttemptEpoch:
        with self._lock:
            self.require_ready(self._admission)
            _require(self._epoch is None or self._epoch._finished)
            _require(type(runtime_sequence) is int and runtime_sequence == self._sequence + 1)
            _require(1 <= runtime_sequence <= self._sequence_limit())
            _require(self._empty_children())
            self._binding, self._lease, self._hard = None, 0, 0
            self._launched = self._drained = self._normal_return = False
            self._sequence = runtime_sequence
            self._epoch = AttemptEpoch(self, runtime_sequence)
            return self._epoch

    def verified_lease(
        self, binding: dict, lease_end_monotonic: float, hard_end_monotonic: float
    ) -> None:
        raise LifecycleUnavailable("worker_attempt_epoch_required")

    def finished(self) -> None:
        raise LifecycleUnavailable("worker_attempt_epoch_required")

    def run(
        self, cmd: list[str], seconds: int, observer: Callable[[int], None] | None, control: Control
    ) -> int:
        epoch = self._epoch
        if epoch is None:
            raise LifecycleUnavailable("worker_attempt_epoch_required")
        epoch.require_active()
        binding = epoch._binding
        if binding is None:
            raise LifecycleUnavailable("worker_attempt_not_armed")
        _require(set(control.binding) == _CONTROL_BINDING)
        _require(
            all(control.binding[key] == binding[key] for key in _BINDING - {"contract_sha256"})
        )
        _require(epoch._control is None or epoch._control is control)
        epoch._control = control
        return super().run(cmd, seconds, observer, control)


class PersistentWorkerOwner(SequentialWorkerOwner):
    """Explicit v3 idle availability; every attempt still needs a finite native lease."""

    _magic = _MAGIC_V3
    _admission: Admission

    def __init__(
        self,
        channel: socket.socket,
        admission: Admission,
        clock_anchor: tuple[int, float],
        grant_end: int,
    ):
        WorkerOwner.__init__(self, channel, admission, clock_anchor, grant_end)
        _require(admission.mode == "persistent")
        admission.to_document()
        self._epoch = None
        self._sequence = 0
        self._work_end = self._grant_end = self._idle_end = (1 << 64) - 1
        self._idle_wait_end = self._idle_end
        self._idle_closing = False

    def _epoch_clock(self) -> tuple[int, float]:
        # A fresh conservative offset belongs to this attempt only. Never sample
        # again when that active epoch refreshes its immutable hard ceiling.
        boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
        return boot, time.monotonic()

    def _sequence_limit(self) -> int:
        return (
            MAX_SEQUENCE if self._admission.max_attempts is None else self._admission.max_attempts
        )

    def _next_idle_end(self, before: int) -> int:
        seconds = self._admission.idle_timeout_seconds
        return (
            self._work_end if seconds is None else min(before + seconds * _SECOND, self._work_end)
        )

    def _next_idle_wait_end(self, acknowledged: int) -> int:
        seconds = self._admission.idle_timeout_seconds
        _require(seconds is not None)
        assert seconds is not None
        # Shutdown observation only: never extend the pre-ACK claim cutoff.
        _require(
            type(acknowledged) is int
            and 0 <= acknowledged <= (1 << 64) - 1 - seconds * _SECOND - _IDLE_STOP_RESERVE
        )
        return self._next_idle_end(acknowledged) + _IDLE_STOP_RESERVE

    def _attempt_binding(self, sequence: int, binding: dict) -> dict:
        return {
            **super()._attempt_binding(sequence, binding),
            "admission_sha256": self._admission.admission_sha256,
            "runtime_sequence": wire_sequence64(sequence, minimum=1),
        }

    def _handshake(self, nonce: bytes) -> None:
        _require(self._receive_v2() == (_READY, 0, 0, 0, nonce))
        before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
        # These HELLO fields are immutable optional policy, not job deadlines.
        self._exchange_v2(
            _HELLO,
            0,
            self._admission.idle_timeout_seconds or 0,
            self._admission.max_attempts or 0,
            nonce,
        )
        self._idle_end = self._next_idle_end(before)
        if self._admission.idle_timeout_seconds is not None:
            self._idle_wait_end = self._next_idle_wait_end(
                time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
            )

    def require_ready(self, admission: Admission | LocalAdmission) -> None:
        from vardrrunner.authorization.local_admission import LocalAdmission

        _require(not isinstance(admission, LocalAdmission))
        assert not isinstance(admission, LocalAdmission)
        WorkerOwner.require_ready(self, admission)
        admission.to_document()
        if self._idle_closing:
            raise IdleBoundaryReached("worker_idle_boundary_reached")
        if self._epoch is None or self._epoch._finished or self._binding is None:
            if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= self._idle_end:  # type: ignore[attr-defined]
                _require(self._admission.idle_timeout_seconds is not None)
                self._idle_closing = True
                raise IdleBoundaryReached("worker_idle_boundary_reached")

    def wait_idle_stop(self) -> NoReturn:
        """Keep fd3 open; only PID1 may establish the physical idle-limit exit."""
        _require(self._idle_closing and self._admission.idle_timeout_seconds is not None)
        _require(self._epoch is None or self._epoch._finished)
        _require(self._empty_children())
        while True:
            WorkerOwner.require_ready(self, self._admission)
            boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
            _require(boot < self._idle_wait_end)
            # The post-ACK bound plus fixed shutdown reserve grants no execution.
            time.sleep(min(0.05, (self._idle_wait_end - boot) / _SECOND))

    def require_allocation(self, seconds: int) -> None:
        self.require_ready(self._admission)
        _require(type(seconds) is int and 1 <= seconds <= 86400)


@contextmanager
def connect(admission: Admission | LocalAdmission) -> Iterator[WorkerOwner]:
    """Accept only the fixed inherited fd3; never an env flag or caller socket."""
    global _ACTIVE, _HOOK_INSTALLED
    _require(sys.platform == "linux" and hasattr(time, "CLOCK_BOOTTIME"))
    # Reuse this conservative offset for the complete connection. A later
    # suspend must shorten/refuse permission, never shift first arm or renewal.
    persistent = getattr(admission, "mode", None) == "persistent"
    clock_anchor, grant_end = (
        ((0, 0.0), (1 << 64) - 1) if persistent else _incarnation_clock(admission)
    )
    with _GLOBAL:
        _require(_ACTIVE is None and threading.active_count() == 1)
        _prctl(4, 0)  # PR_SET_DUMPABLE in the actual Python process after exec.
        _prctl(36, 1)  # PR_SET_CHILD_SUBREAPER; native bootstrap is not the proof.
        _process_readback()
        channel = socket.socket(fileno=3)
        try:
            channel.set_inheritable(False)
            channel.settimeout(1.0)
            _require(channel.family == socket.AF_UNIX and channel.type == socket.SOCK_SEQPACKET)  # type: ignore[attr-defined]
            _require(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1)  # type: ignore[attr-defined]
            from vardrrunner.authorization.local_admission import LocalAdmission

            if isinstance(admission, LocalAdmission):
                _require(admission.origin == "standalone" and admission.max_attempts == 1)
                _require(admission.mode is None)
                owner: WorkerOwner = SequentialWorkerOwner(
                    channel, admission, clock_anchor, grant_end
                )
                assert isinstance(owner, SequentialWorkerOwner)
                owner._handshake_local()
            else:
                owner_type = (
                    PersistentWorkerOwner
                    if persistent
                    else SequentialWorkerOwner
                    if getattr(admission, "max_attempts", None) is not None
                    else WorkerOwner
                )
                owner = owner_type(channel, admission, clock_anchor, grant_end)
                nonce = bytes.fromhex(admission.identity["owner_nonce"])
                owner._handshake(nonce)
            if not _HOOK_INSTALLED:
                sys.addaudithook(_audit)
                _HOOK_INSTALLED = True
            owner._ready = True
            _ACTIVE = owner
        except BaseException:
            channel.close()
            raise
    try:
        yield owner
    finally:
        with _GLOBAL:
            owner._closed = True
            _ACTIVE = None
            channel.close()
