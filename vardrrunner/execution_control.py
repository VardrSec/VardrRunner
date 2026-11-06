"""Opt-in control of one explicitly invoked execution, never a queue worker."""

from __future__ import annotations

import math
import os
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from vardrrunner import config, launch_guard


class ExecutionStopped(Exception):
    """Execution ended without successful completion; partial files are retained."""

    def __init__(self, reason: str, confirmed: bool, *, pid: int | None = None):
        super().__init__(reason)
        self.confirmed = confirmed
        self.pid = pid


class Control:
    """Monotonic fail-closed permission with an independent refresh thread.

    A blocked HTTP refresh cannot extend execution. A late response cannot
    resurrect expired permission. Only a matching authenticated response renews.
    """

    def __init__(
        self,
        refresh: Callable[[], dict],
        binding: dict,
        lease_seconds: float,
        *,
        started: float,
        local_stop: Callable[[], bool],
        grace: float = 2.0,
        lease_deadline: Callable[[], float] | None = None,
    ):
        self.refresh = refresh
        self.binding = binding
        self.deadline = started + lease_seconds
        self.local_stop = local_stop
        self.grace = grace
        self.lease_deadline = lease_deadline
        self.reason = ""
        self._worker_reuse_safe = True
        self._lock = threading.Lock()
        self._close = threading.Event()
        self._thread = threading.Thread(target=self._refresh, daemon=True, name="vardr-control")

    def stop_reason(self) -> str:
        with self._lock:
            try:
                cap = self._capped(self.deadline)
            except Exception:
                self.reason = self.reason or "control_cap_unavailable"
                cap = self.deadline
            if not self.reason and time.monotonic() >= cap:
                self.reason = "control_lease_expired"
            if not self.reason and self.local_stop():
                self.reason = "local_emergency_stop"
            return self.reason

    def _capped(self, deadline: float) -> float:
        if self.lease_deadline is None:
            return deadline
        cap = self.lease_deadline()
        if isinstance(cap, bool) or not isinstance(cap, (int, float)) or not math.isfinite(cap):
            raise ValueError("invalid verified control deadline")
        return min(deadline, cap)

    def _refresh(self) -> None:
        while not self._close.wait(0.5):
            if self.stop_reason():
                return
            started = time.monotonic()
            try:
                response = self.refresh()
                if any(response.get(key) != value for key, value in self.binding.items()):
                    raise ValueError("control binding mismatch")
                lease = response.get("lease_seconds")
                if (
                    isinstance(lease, bool)
                    or not isinstance(lease, (int, float))
                    or not 0 < lease <= 10
                ):
                    raise ValueError("invalid control lease")
                with self._lock:
                    if self.reason or time.monotonic() >= self.deadline:
                        self.reason = self.reason or "control_lease_expired"
                        return
                    if response.get("action") != "continue":
                        self._worker_reuse_safe = False
                        self.reason = "remote_stop_requested"
                        return
                    self.deadline = self._capped(started + lease)
            except BaseException as error:
                with self._lock:
                    self._worker_reuse_safe = False
                if not isinstance(error, Exception):
                    raise
                # Do not log remote payloads/errors or extend the last lease.
                continue

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._close.set()
        self._thread.join(timeout=0.1)

    def quiesce(self, absolute_deadline: float) -> None:
        """Worker-only join barrier; a timed-out refresh never permits reuse."""
        if (
            isinstance(absolute_deadline, bool)
            or not isinstance(absolute_deadline, (int, float))
            or not math.isfinite(absolute_deadline)
            or threading.current_thread() is self._thread
        ):
            raise RuntimeError("worker_control_quiescence_unavailable")
        self._close.set()
        if self._thread.ident is not None:
            self._thread.join(timeout=max(0.0, absolute_deadline - time.monotonic()))
        if self._thread.is_alive():
            raise RuntimeError("worker_control_quiescence_unavailable")

    def worker_quiescent(self) -> bool:
        """Read actual closure/thread state for the native worker epoch barrier."""
        return (
            self._close.is_set() and self._thread.ident is not None and not self._thread.is_alive()
        )

    def worker_reuse_safe(self) -> bool:
        """V3 reuse metadata; refresh failure never grants another attempt."""
        with self._lock:
            return self._worker_reuse_safe


_CONTROL: ContextVar[Control | None] = ContextVar("execution_control", default=None)


@contextmanager
def controlled(control: Control) -> Iterator[None]:
    token = _CONTROL.set(control)
    try:
        with control:
            yield
    finally:
        _CONTROL.reset(token)


def current() -> Control | None:
    return _CONTROL.get()


def available() -> bool:
    if os.name == "nt":
        return True
    from vardrrunner.worker_lifecycle import current as worker_owner

    return worker_owner() is not None


def require_permission(control: Control) -> None:
    reason = control.stop_reason()
    if reason:
        raise ExecutionStopped(reason, True)


def run(
    cmd: list[str], seconds: int, observer: Callable[[int], None] | None, control: Control
) -> int:
    """Own the complete process lifetime, including exceptions and leftover children."""
    require_permission(control)
    if not available():
        raise ExecutionStopped("controlled_process_tree_unsupported", True)
    if os.name != "nt":
        from vardrrunner.worker_lifecycle import current as worker_owner

        owner = worker_owner()
        if owner is None:
            raise ExecutionStopped("controlled_process_tree_unsupported", True)
        return owner.run(cmd, seconds, observer, control)
    from vardrrunner.windows_job import WindowsJob

    try:
        process = WindowsJob(cmd, config.tool_environment(), lambda: require_permission(control))
    except OSError as exc:
        raise ExecutionStopped("launch_or_containment_uncertain", False) from exc
    started = time.monotonic()
    try:
        if observer:
            observer(process.pid)
        while True:
            reason = control.stop_reason()
            if launch_guard.timeout(seconds) <= 0:
                reason = reason or "authorization_deadline"
            if time.monotonic() - started >= seconds:
                reason = reason or "tool_timeout"
            code = process.poll()
            if code is not None and not process.active() and not reason:
                return code
            if code is not None:
                reason = reason or "descendants_after_tool_exit"
            if reason:
                confirmed = _stop(process, control.grace)
                raise ExecutionStopped(reason, confirmed)
            time.sleep(0.05)
    except ExecutionStopped:
        raise
    except BaseException as exc:
        # Includes Ctrl-C, journal/observer errors and control-file errors.
        if not _stop(process, control.grace):
            raise ExecutionStopped("execution_state_uncertain", False) from exc
        raise
    finally:
        process.close()


def _stop(process, grace: float) -> bool:
    try:
        process.graceful()
        until = time.monotonic() + grace
        while process.active() and time.monotonic() < until:
            time.sleep(0.05)
        if process.active():
            process.force()
        until = time.monotonic() + 2
        while process.active() and time.monotonic() < until:
            time.sleep(0.05)
        return not process.active()
    except OSError:
        try:
            process.force()
        except OSError:
            pass
        return False
