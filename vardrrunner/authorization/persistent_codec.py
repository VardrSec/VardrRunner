"""Exact persistent protocol counters; legacy integer contracts stay unchanged."""

from __future__ import annotations

import re

from .codec import AuthorizationError, fields, integer

MAX_SEQUENCE = (1 << 63) - 1


def sequence64(value: object, *, minimum: int = 0) -> int:
    """Parse a bounded ASCII decimal string without JavaScript number rounding."""
    if (
        type(value) is not str
        or not 1 <= len(value) <= 19
        or re.fullmatch(r"0|[1-9][0-9]{0,18}", value) is None
    ):
        raise AuthorizationError("worker_persistent_sequence")
    return integer(int(value), minimum, MAX_SEQUENCE)


def wire_sequence64(value: int, *, minimum: int = 0) -> str:
    return str(integer(value, minimum, MAX_SEQUENCE))


def parse_limits(value: object) -> tuple[int | None, int | None]:
    limits = fields(value, {"max_attempts", "idle_timeout_seconds"})
    maximum = limits["max_attempts"]
    idle = limits["idle_timeout_seconds"]
    return (
        None if maximum is None else sequence64(maximum, minimum=1),
        None if idle is None else integer(idle, 1, 86400),
    )
