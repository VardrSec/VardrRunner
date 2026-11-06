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
import signal
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from vardrrunner import launch_guard
from vardrrunner.authorization.codec import encoded

if TYPE_CHECKING:
    from vardrrunner.authorization.worker_admission import Admission
    from vardrrunner.execution_control import Control

_PACKET = struct.Struct("<IIQQ32s")
_CREDENTIALS = struct.Struct("=iii")
_MAGIC = 0x31574456
_READY, _HELLO, _LEASE, _DONE, _ACK = 1, 2, 3, 4, 5
_WALL = 0x40000000
REPORT_RUNWAY_SECONDS = 150
_SECOND = 1_000_000_000
_ACTIVE: WorkerOwner | None = None
_GLOBAL = threading.Lock()
_HOOK_INSTALLED = False
_SPAWN_EVENTS = frozenset({"subprocess.Popen", "os.fork", "os.forkpty", "os.posix_spawn"})


class LifecycleUnavailable(RuntimeError):
    """Incomplete ownership or child-drain proof; retain the attempt hold."""


def _require(value: object) -> None:
    if not value:
        raise LifecycleUnavailable("worker_lifecycle_unavailable")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _incarnation_clock(admission: Admission) -> tuple[tuple[int, float], int]:
    # UTC last is conservative across pauses between the elapsed-clock samples
    # and timestamp validation. Later conversions never resample this offset.
    boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
    mono = time.monotonic()
    now = _utcnow()
    expiry = admission.expires_at
    _require(isinstance(expiry, datetime) and expiry.tzinfo is not None)
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
        admission: Admission,
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

    def require_ready(self, admission: Admission) -> None:
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


@contextmanager
def connect(admission: Admission) -> Iterator[WorkerOwner]:
    """Accept only the fixed inherited fd3; never an env flag or caller socket."""
    global _ACTIVE, _HOOK_INSTALLED
    _require(sys.platform == "linux" and hasattr(time, "CLOCK_BOOTTIME"))
    # Reuse this conservative offset for the complete connection. A later
    # suspend must shorten/refuse permission, never shift first arm or renewal.
    clock_anchor, grant_end = _incarnation_clock(admission)
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
            owner = WorkerOwner(channel, admission, clock_anchor, grant_end)
            ready = owner._receive()
            nonce = bytes.fromhex(admission.identity["owner_nonce"])
            _require(ready == (_READY, 0, 0, nonce))
            _require(time.clock_gettime_ns(time.CLOCK_BOOTTIME) < owner._work_end)  # type: ignore[attr-defined]
            owner._exchange(_HELLO, owner._work_end, owner._grant_end, nonce)
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
