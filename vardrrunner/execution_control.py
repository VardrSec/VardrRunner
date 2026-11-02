"""Opt-in control of one explicitly invoked execution, never a queue worker."""

from __future__ import annotations

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
    ):
        self.refresh = refresh
        self.binding = binding
        self.deadline = started + lease_seconds
        self.local_stop = local_stop
        self.grace = grace
        self.reason = ""
        self._lock = threading.Lock()
        self._close = threading.Event()
        self._thread = threading.Thread(target=self._refresh, daemon=True, name="vardr-control")

    def stop_reason(self) -> str:
        with self._lock:
            if not self.reason and time.monotonic() >= self.deadline:
                self.reason = "control_lease_expired"
            if not self.reason and self.local_stop():
                self.reason = "local_emergency_stop"
            return self.reason

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
                        self.reason = "remote_stop_requested"
                        return
                    self.deadline = started + lease
            except Exception:
                # Do not log remote payloads/errors or extend the last lease.
                continue

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._close.set()
        self._thread.join(timeout=0.1)


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
    return os.name == "nt"


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
