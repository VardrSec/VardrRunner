"""The single sanitization layer applied before data crosses a trust boundary.

Anything that leaves this process — terminal output, log records, job events
posted to the backend, error messages, run manifests, audit exports — passes
through here first. Centralising it is the point: a redactor that lives in one
module can be audited and tested exhaustively, whereas ad-hoc masking scattered
across twenty call sites is guaranteed to have a gap.

**Deterministic by design.** The same input always produces the same output, and
no randomness or hashing salt is involved, so redacted records remain comparable
and a test can assert exact strings.

**Fail closed on shape, open on content.** Redaction never raises: a value it
cannot parse is returned unchanged *unless* it matches a secret pattern, in
which case it is masked. Sanitising must never be the reason a job dies, but an
unrecognised structure must not become an exfiltration path either — which is
why the recursive walker masks by *key name* as well as by value pattern.

**What this is not.** It is not a guarantee that a secret never reaches disk. A
tool's own output file is written by that tool, and VardrRunner does not rewrite
artifacts in place. This layer governs what the *runner* emits about them.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "***REDACTED***"

# Maximum depth the recursive walker will descend. Backend payloads are
# untrusted and could be deeply nested or self-referential; bounding the walk
# keeps sanitisation from becoming a denial-of-service on the runner itself.
_MAX_DEPTH = 12

# Keys whose *value* is a secret regardless of what it looks like. Compared
# case-insensitively against the whole key, and also as a substring for the
# compound forms tools invent (``x_api_key``, ``auth_token``).
_SECRET_KEY_PARTS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "authorization",
    "auth_token",
    "access_token",
    "refresh_token",
    "bearer",
    "cookie",
    "credential",
    "passwd",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
    "value_env",
    "value_keychain",
)

# Value patterns, applied to free text where there is no key to inspect: log
# lines, exception messages, tool stderr. Ordered most specific first so a
# VardrMap key is reported as such rather than caught by a generic rule.
_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # VardrMap API keys.
    ("vmap", re.compile(r"\bvmap_[A-Za-z0-9_\-]{4,}")),
    # Authorization headers, with or without a scheme.
    (
        "authz",
        re.compile(
            r"(?i)\bauthorization\s*[:=]\s*(?:bearer|basic|token)?\s*[A-Za-z0-9._\-+/=]{4,}"
        ),
    ),
    ("bearer", re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}")),
    # Cookie headers.
    ("cookie", re.compile(r"(?i)\b(?:set-)?cookie\s*[:=]\s*[^\s;]{4,}")),
    # Secrets carried in query strings.
    (
        "query",
        re.compile(
            r"(?i)([?&](?:api[_-]?key|token|access_token|secret|password|passwd|sig|"
            r"signature|session)=)[^&\s]+"
        ),
    ),
    # key=value / key: value in free text.
    (
        "assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|"
            r"private[_-]?key|password|passwd|secret|token|credential)"
            r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;)}\]]+)"
        ),
    ),
)


def _is_secret_key(key: str) -> bool:
    """True when a mapping key implies its value is sensitive.

    Hyphens and spaces are normalised to underscores first, so header-style
    names (``X-API-KEY``, ``Auth-Token``) match the same parts as snake_case
    ones. Matching is substring-based because tools invent compound forms
    (``x_api_key``, ``vardrmap_api_key``) faster than any exact list can track.
    """
    normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
    return any(part in normalized for part in _SECRET_KEY_PARTS)


def redact_text(text: str) -> str:
    """Mask secret-looking substrings in free text.

    Used for log lines, exception messages and any tool output the runner
    echoes. Non-strings are returned untouched so callers can pass anything.
    """
    if not isinstance(text, str) or not text:
        return text
    out = text
    for name, pattern in _VALUE_PATTERNS:
        if name == "query":
            out = pattern.sub(r"\1" + MASK, out)
        elif name == "assignment":
            out = pattern.sub(r"\1\2" + MASK, out)
        else:
            out = pattern.sub(MASK, out)
    return out


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively sanitize a structure for emission.

    Masks by key name *and* by value pattern, so a secret survives neither an
    unexpected key nor an unexpected shape. Depth-bounded against hostile
    nesting; beyond the bound the subtree is replaced with a marker rather than
    emitted unchecked.
    """
    if _depth > _MAX_DEPTH:
        return "***TRUNCATED***"

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and _is_secret_key(k):
                out[k] = MASK
            else:
                out[k] = redact(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        cleaned = [redact(v, _depth + 1) for v in value]
        return type(value)(cleaned) if isinstance(value, tuple) else cleaned
    # int/float/bool/None and anything else carry no secret we can detect.
    return value


def redact_exception(exc: BaseException) -> str:
    """Render an exception as a sanitized single line.

    Exception messages routinely embed the URL or payload that failed, which is
    exactly where a token ends up. Callers should prefer this over ``str(exc)``
    anywhere the result is logged, displayed or transmitted.
    """
    return f"{type(exc).__name__}: {redact_text(str(exc))}"


def redact_url(url: str) -> str:
    """Strip credentials and secret query parameters from a URL.

    Handles ``https://user:pass@host`` userinfo, which no value pattern catches
    because the secret has no key next to it.
    """
    if not isinstance(url, str) or not url:
        return url
    cleaned = re.sub(r"(?i)\b(https?://)([^/@\s]+):([^/@\s]+)@", r"\1\2:" + MASK + "@", url)
    return redact_text(cleaned)
