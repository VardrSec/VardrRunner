"""Parsing and presentation of the backend's advisory policy findings.

VardrMap evaluates every job against its authorization, testing window and
recorded scope. Findings ride back on the response as a ``warnings`` array and
**the work still runs** — staying in scope is the operator's responsibility, the
same as it is with any other tool in the kit. The runner's job is to make those
findings impossible to miss, not to enforce them.

Stop-work is the one exception, and it does not arrive here: it is a 403 turned
into :class:`~vardrrunner.errors.StopWorkError` by
:func:`~vardrrunner.errors.classify_status`.

**Trust boundary.** Everything this module parses is untrusted remote data. It
is rendered as text and recorded; it never influences control flow beyond
display, and it is never interpolated into a command line. All parsing lives
here so that a change to the backend's shape touches exactly one file.

**Failure mode is silence, not an exception.** A malformed, absent or
unexpected payload yields no warnings rather than raising, because failing to
display an advisory finding must never abort a job the backend already allowed.

Observed contract (VardrMap, 2026-08-17)::

    {"warnings": [{"reason": "<code>", "message": "<detail>"}]}
"""

from __future__ import annotations

from dataclasses import dataclass

from vardrrunner import redaction

# Human labels for the reason codes VardrMap emits. An unknown code is shown
# verbatim rather than dropped — a finding the runner does not recognise is
# still a finding the operator needs to see.
_REASON_LABELS: dict[str, str] = {
    "engagement_not_active": "Engagement is not active",
    "stop_work_active": "Stop-work is engaged",
    "authorization_missing": "No authorization record",
    "authorization_not_active": "Authorization is not active",
    "outside_testing_window": "Outside the agreed testing window",
    "capability_prohibited": "Capability prohibited by authorization",
    "target_excluded": "Target is explicitly out of scope",
    "target_out_of_scope": "Target is not in the recorded scope",
    "scope_ambiguous": "Scope could not be evaluated confidently",
}


@dataclass(frozen=True)
class PolicyWarning:
    """One advisory finding. Frozen so a parsed decision cannot be edited."""

    reason: str
    message: str = ""

    @property
    def label(self) -> str:
        """Human-readable heading, falling back to the raw code."""
        return _REASON_LABELS.get(self.reason, self.reason or "Policy finding")

    def describe(self) -> str:
        return f"{self.label}: {self.message}" if self.message else self.label


def parse_warnings(payload: object) -> tuple[PolicyWarning, ...]:
    """Extract advisory warnings from a backend response body.

    Accepts the whole response dict (the usual case) or a bare list. Any shape
    it does not understand yields an empty tuple.
    """
    raw: object
    if isinstance(payload, dict):
        raw = payload.get("warnings")
    elif isinstance(payload, list):
        raw = payload
    else:
        return ()

    if not isinstance(raw, list):
        return ()

    parsed: list[PolicyWarning] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        reason = item.get("reason")
        message = item.get("message")
        reason = reason if isinstance(reason, str) else ""
        message = message if isinstance(message, str) else ""
        if not reason and not message:
            continue
        parsed.append(PolicyWarning(reason=reason, message=message))
    return tuple(parsed)


def has_stop_work(warnings: tuple[PolicyWarning, ...]) -> bool:
    """True if a finding reports stop-work.

    Stop-work normally arrives as a 403 rather than a warning. This covers the
    case where the backend reports it advisorily on a path that does not refuse
    — the runner treats it as blocking wherever it appears.
    """
    return any(w.reason == "stop_work_active" for w in warnings)


def format_warnings(warnings: tuple[PolicyWarning, ...]) -> list[str]:
    """Render findings as Rich-markup lines, ready to print before execution."""
    return [f"[yellow]⚠ {redaction.redact_rich_text(w.describe())}[/yellow]" for w in warnings]


def summarize(warnings: tuple[PolicyWarning, ...]) -> str:
    """One-line summary for job events and logs. Empty when there is nothing."""
    if not warnings:
        return ""
    codes = ", ".join(w.reason or "unknown" for w in warnings)
    return f"{len(warnings)} policy warning(s): {codes}"
