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


class DeadlineExpired(RuntimeError):
    """The immutable execution permission elapsed before OS process creation."""


@contextmanager
def boundary() -> Iterator[None]:
    gate = _GATE.get()
    with gate() if gate else nullcontext():
        require_deadline()
        yield


def require_deadline() -> None:
    if timeout(1) <= 0:
        raise DeadlineExpired("execution_authorization_deadline")


def timeout(seconds: int | float) -> int | float:
    until = _DEADLINE.get()
    return (
        seconds
        if until is None
        else min(seconds, until[0] - time.time(), until[1] - time.monotonic())
    )


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
