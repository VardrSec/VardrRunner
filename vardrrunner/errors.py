"""Domain exceptions and the failure taxonomy every reported failure maps onto.

Any failure that reaches an operator, a log line, a job event or — from the
execution journal onward — a durable audit record is classified into exactly one
:class:`FailureCategory` first. The category is the stable, machine-readable
half of a failure; the human-readable message alongside it may change freely.

**Category values are written to durable records.** Renaming a member breaks
anything that already stored it, so add a new member rather than repurposing an
existing one.

This module imports nothing from the rest of the package and nothing outside the
standard library. It is deliberately the bottom of the dependency graph so any
module can raise a classified error without risking a circular import, and so
the classifier can be tested without a network stack.
"""

from __future__ import annotations

from enum import Enum


class FailureCategory(str, Enum):
    """Stable identifiers for why something stopped.

    Ordered roughly from "the operator did this deliberately" through to
    "something is broken". `str` mixin so a category serialises as its value.
    """

    STOP_WORK = "stop_work"
    CLAIM_RACE = "claim_race"
    AUTH = "auth"
    NOT_FOUND = "not_found"
    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_JOB = "unsupported_job"
    INVALID_CONFIG = "invalid_config"
    TARGET_RESOLUTION = "target_resolution"
    TOOL_MISSING = "tool_missing"
    TOOL_FAILED = "tool_failed"
    TOOL_TIMEOUT = "tool_timeout"
    UPLOAD_FAILED = "upload_failed"
    RATE_LIMITED = "rate_limited"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    UNKNOWN = "unknown"


class RunnerError(Exception):
    """Base for every classified runner failure.

    Subclasses set :attr:`category`. Raise these with ``from`` so the underlying
    cause survives for diagnostics without the category being inferred twice.
    """

    category: FailureCategory = FailureCategory.UNKNOWN

    def __init__(self, message: str = "", *, reason: str = ""):
        super().__init__(message)
        self.message = message
        # `reason` is the backend's own machine-readable code where one was
        # supplied (e.g. "stop_work_active"). Empty when the runner classified
        # the failure itself from a bare status code.
        self.reason = reason


class StopWorkError(RunnerError):
    """The engagement's stop-work switch is engaged; execution must halt.

    This is not the platform overruling the operator — it is the operator's own
    emergency brake. It is the single policy condition that blocks rather than
    warns, and it must never be presented as a generic claim failure.
    """

    category = FailureCategory.STOP_WORK


class ClaimRace(RunnerError):
    """Another runner claimed the job first. Expected, benign, not a failure.

    The job belongs to whoever won; this runner moves on without marking it
    failed, because it is neither this runner's work nor broken.
    """

    category = FailureCategory.CLAIM_RACE


class AuthError(RunnerError):
    """The API key is missing, expired or revoked."""

    category = FailureCategory.AUTH


class NotFoundError(RunnerError):
    """No such object, or it belongs to another account.

    VardrMap deliberately answers cross-account access with 404 rather than 403
    so object existence is not disclosed, so this covers both cases.
    """

    category = FailureCategory.NOT_FOUND


class InvalidRequestError(RunnerError):
    """The backend rejected the payload as malformed or out of range."""

    category = FailureCategory.INVALID_REQUEST


class RateLimited(RunnerError):
    """Backend asked us to slow down. Retryable after a backoff."""

    category = FailureCategory.RATE_LIMITED


class BackendUnavailable(RunnerError):
    """Backend is unreachable, erroring, or mid-restart. Retryable."""

    category = FailureCategory.BACKEND_UNAVAILABLE


# Statuses the runner understands semantically. Anything else falls through to
# BackendUnavailable (5xx) or InvalidRequestError (other 4xx).
#
# 403 is read as stop-work rather than generic authorization failure. That is
# specific to the VardrMap contract, which reserves 403 for the operator's halt
# switch and answers every other denial with 404 to avoid disclosing existence.
# Documented in docs/architecture.md; if that contract changes, this mapping and
# that document are what need updating.
_STATUS_MAP: dict[int, type[RunnerError]] = {
    401: AuthError,
    403: StopWorkError,
    404: NotFoundError,
    409: ClaimRace,
    422: InvalidRequestError,
    429: RateLimited,
}


def _extract_reason(body: object) -> tuple[str, str]:
    """Pull ``(reason, message)`` out of an error body, tolerating any shape.

    FastAPI nests its payload under ``detail``. Everything here is untrusted
    remote data, so every access is defensive: an unparseable body yields empty
    strings and the caller falls back to its own wording.
    """
    if not isinstance(body, dict):
        return "", ""
    detail = body.get("detail", body)
    if isinstance(detail, str):
        return "", detail
    if not isinstance(detail, dict):
        return "", ""
    reason = detail.get("reason") or detail.get("error") or ""
    message = detail.get("message") or detail.get("detail") or ""
    return (reason if isinstance(reason, str) else "", message if isinstance(message, str) else "")


def classify_status(status: int, body: object = None) -> RunnerError:
    """Map an HTTP status (plus optional parsed body) onto a domain error.

    Pure and side-effect free: it builds the exception but does not raise, so
    callers keep control of chaining. `body` is whatever ``response.json()``
    produced, or None when the response had no usable JSON.
    """
    reason, message = _extract_reason(body)
    if status in _STATUS_MAP:
        cls = _STATUS_MAP[status]
    elif status >= 500:
        cls = BackendUnavailable
    else:
        cls = InvalidRequestError
    return cls(
        message or _DEFAULT_MESSAGES.get(cls, f"backend returned HTTP {status}"), reason=reason
    )


_DEFAULT_MESSAGES: dict[type[RunnerError], str] = {
    StopWorkError: "stop-work is engaged for this engagement",
    ClaimRace: "another runner claimed this job first",
    AuthError: "the API key was rejected — re-run `vardrrunner login vardrmap`",
    NotFoundError: "not found, or it belongs to another account",
    RateLimited: "the backend is rate limiting this runner",
    BackendUnavailable: "the backend is unavailable",
}
