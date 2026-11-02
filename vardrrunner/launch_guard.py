"""Optional execution-local permission check held across the actual creation call."""

import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from contextvars import ContextVar

_GATE: ContextVar[Callable[[], AbstractContextManager] | None] = ContextVar(
    "vardr_launch_gate", default=None
)
_DEADLINE: ContextVar[tuple[float, float] | None] = ContextVar(
    "vardr_launch_deadline", default=None
)
_RECHECK: ContextVar[Callable[[], None] | None] = ContextVar("vardr_launch_recheck", default=None)
_MONOTONIC: ContextVar[float | None] = ContextVar("vardr_monotonic_permission", default=None)


class DeadlineExpired(RuntimeError):
    """The immutable execution permission elapsed before OS process creation."""


@contextmanager
def boundary() -> Iterator[None]:
    gate = _GATE.get()
    with gate() if gate else nullcontext():
        require_permission()
        yield


def require_permission() -> None:
    check = _RECHECK.get()
    if check:
        check()
    require_deadline()


@contextmanager
def revalidation(check: Callable[[], None]) -> Iterator[None]:
    """Recheck captured permission inside the already-held launch transaction."""
    token = _RECHECK.set(check)
    try:
        yield
    finally:
        _RECHECK.reset(token)


def require_deadline() -> None:
    if timeout(1) <= 0:
        raise DeadlineExpired("execution_authorization_deadline")


def timeout(seconds: int | float) -> int | float:
    until = _DEADLINE.get()
    remaining = (
        seconds
        if until is None
        else min(seconds, until[0] - time.time(), until[1] - time.monotonic())
    )
    monotonic = _MONOTONIC.get()
    return remaining if monotonic is None else min(remaining, monotonic - time.monotonic())


@contextmanager
def monotonic_deadline(until: float | None) -> Iterator[None]:
    """Immutable allocated permission, composed with all surrounding limits."""
    previous = _MONOTONIC.get()
    effective = previous if until is None else until if previous is None else min(previous, until)
    token = _MONOTONIC.set(effective)
    try:
        yield
    finally:
        _MONOTONIC.reset(token)


@contextmanager
def deadline(until: float | None) -> Iterator[None]:
    previous = _DEADLINE.get()
    effective = previous
    if until is not None:
        candidate = (until, time.monotonic() + until - time.time())
        effective = (
            candidate
            if previous is None
            else (min(previous[0], candidate[0]), min(previous[1], candidate[1]))
        )
    token = _DEADLINE.set(effective)
    try:
        yield
    finally:
        _DEADLINE.reset(token)


@contextmanager
def install(gate: Callable[[], AbstractContextManager]) -> Iterator[None]:
    token = _GATE.set(gate)
    try:
        yield
    finally:
        _GATE.reset(token)
