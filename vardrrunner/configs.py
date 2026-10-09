"""
Typed, validated configuration for scan jobs.

Job configs arrive from the backend as raw dicts. These dataclasses parse and
validate them once, up front, so the rest of the runner works with checked values
and a bad/drifted payload fails fast with a clear message instead of blowing up
deep inside execution. Each tool's config is a frozen dataclass with a
``from_dict`` classmethod that raises ``ConfigError`` on anything invalid.
"""

import re
from dataclasses import dataclass

# Severities nuclei accepts — mirrors the backend's own validation.
NUCLEI_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
GAU_PROVIDERS = frozenset({"wayback", "commoncrawl", "otx", "urlscan"})
SUPPORTED_JOB_SCHEMA_VERSIONS = frozenset({1})

# A wordlist arrives as a *name*, never a path: the runner resolves it against
# ~/.vardrmap/wordlists on the machine doing the scanning. This shape admits no
# separator, no dot and no whitespace, so a job cannot escape that directory or
# name a file elsewhere on the operator's disk for ffuf to read and replay at a
# target. Resolution is enforced again in runner.py; this is the first gate.
WORDLIST_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
# A fuzzing extension, as ffuf wants it: a dot and an alphanumeric suffix.
_EXTENSION = re.compile(r"^\.[A-Za-z0-9]{1,10}$")
_STATUS_CODE = re.compile(r"^\d{3}$")
# ffuf is the only tool here that generates sustained traffic at a client's host,
# so its request rate is capped by default rather than left to ffuf's unbounded
# threads. The operator can raise it; they cannot remove it.
FFUF_DEFAULT_RATE = 50
FFUF_MAX_RATE = 1000


class ConfigError(ValueError):
    """A job config value is missing, the wrong type, or out of range."""


@dataclass(frozen=True)
class JobEnvelope:
    """The validated job wrapper from the backend (everything but the tool config)."""

    id: str
    tool_type: str
    target_source: str
    engagement_id: str
    config: dict
    schema_version: int = 1

    @classmethod
    def from_dict(cls, job: dict) -> "JobEnvelope":
        required = ("id", "tool_type", "target_source", "engagement_id")
        missing = [k for k in required if not job.get(k)]
        if missing:
            raise ConfigError(f"job missing required field(s): {', '.join(missing)}")
        schema_version = job.get("schema_version", 1)
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version not in SUPPORTED_JOB_SCHEMA_VERSIONS
        ):
            raise ConfigError(
                f"unsupported job schema_version {schema_version!r}; "
                f"supported: {sorted(SUPPORTED_JOB_SCHEMA_VERSIONS)}"
            )
        return cls(
            id=str(job["id"]),
            tool_type=str(job["tool_type"]),
            target_source=str(job["target_source"]),
            engagement_id=str(job["engagement_id"]),
            config=job.get("config") or {},
            schema_version=schema_version,
        )


def _opt_int(cfg: dict, key: str, *, minimum: int | None = None, maximum: int | None = None):
    """Parse an optional int; return None when absent. Raise ConfigError if invalid."""
    raw = cfg.get(key)
    if raw is None or raw == "":
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"{key!r} must be an integer, got {raw!r}") from None
    if minimum is not None and value < minimum:
        raise ConfigError(f"{key!r} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{key!r} must be <= {maximum}, got {value}")
    return value


def _req_int(
    cfg: dict, key: str, default: int, *, minimum: int | None = None, maximum: int | None = None
) -> int:
    """Parse an int with a default when absent."""
    value = _opt_int(cfg, key, minimum=minimum, maximum=maximum)
    return default if value is None else value


def _parse_severity(raw) -> str | None:
    """Normalize a severity filter (string or list) to a comma string, validating tokens."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, str):
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
    elif isinstance(raw, (list, tuple)):
        tokens = [str(t).strip() for t in raw if str(t).strip()]
    else:
        raise ConfigError(f"'severity' must be a string or list, got {type(raw).__name__}")
    invalid = [t for t in tokens if t not in NUCLEI_SEVERITIES]
    if invalid:
        raise ConfigError(f"invalid severity {invalid}; allowed: {sorted(NUCLEI_SEVERITIES)}")
    return ",".join(tokens) or None


def _opt_bool(cfg: dict, key: str, default: bool) -> bool:
    """Parse a boolean that may arrive as JSON or as a form string ("true"/"false")."""
    raw = cfg.get(key)
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str) and raw.strip().lower() in ("true", "false"):
        return raw.strip().lower() == "true"
    raise ConfigError(f"{key!r} must be true or false, got {raw!r}")


def _parse_choices(raw, key: str, allowed: frozenset[str]) -> tuple[str, ...]:
    """Normalize a comma string or list to a de-duplicated tuple drawn from ``allowed``."""
    if raw is None or raw == "":
        return ()
    if isinstance(raw, str):
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
    elif isinstance(raw, (list, tuple)):
        tokens = [str(t).strip() for t in raw if str(t).strip()]
    else:
        raise ConfigError(f"{key!r} must be a string or list, got {type(raw).__name__}")
    invalid = sorted(set(tokens) - allowed)
    if invalid:
        raise ConfigError(f"invalid {key} {invalid}; allowed: {sorted(allowed)}")
    return tuple(dict.fromkeys(tokens))


def _parse_templates(raw) -> str | None:
    """Normalize nuclei templates (string or list) to a comma string."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, (list, tuple)):
        return ",".join(str(t) for t in raw) or None
    return str(raw)


@dataclass(frozen=True)
class HttpxConfig:
    limit: int = 100
    status_code: int | None = None
    timeout: int | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "HttpxConfig":
        return cls(
            limit=_req_int(cfg, "limit", 100, minimum=1),
            status_code=_opt_int(cfg, "status_code"),
            timeout=_opt_int(cfg, "timeout", minimum=1),
        )


@dataclass(frozen=True)
class NucleiConfig:
    limit: int = 100
    status_code: int | None = None
    severity: str | None = None
    templates: str | None = None
    timeout: int | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "NucleiConfig":
        return cls(
            limit=_req_int(cfg, "limit", 100, minimum=1),
            status_code=_opt_int(cfg, "status_code"),
            severity=_parse_severity(cfg.get("severity")),
            templates=_parse_templates(cfg.get("templates")),
            timeout=_opt_int(cfg, "timeout", minimum=1),
        )


@dataclass(frozen=True)
class NmapConfig:
    top_ports: int = 100
    timing: int = 3
    limit: int = 500
    timeout: int | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "NmapConfig":
        return cls(
            top_ports=_req_int(cfg, "top_ports", 100, minimum=1, maximum=65535),
            timing=_req_int(cfg, "timing", 3, minimum=0, maximum=4),
            limit=_req_int(cfg, "limit", 500, minimum=1),
            timeout=_opt_int(cfg, "timeout", minimum=1),
        )


@dataclass(frozen=True)
class SubfinderConfig:
    timeout: int | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "SubfinderConfig":
        return cls(timeout=_opt_int(cfg, "timeout", minimum=1))


@dataclass(frozen=True)
class DnsxConfig:
    limit: int = 500
    timeout: int | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "DnsxConfig":
        return cls(
            limit=_req_int(cfg, "limit", 500, minimum=1),
            timeout=_opt_int(cfg, "timeout", minimum=1),
        )


@dataclass(frozen=True)
class NaabuConfig:
    top_ports: int = 100
    limit: int = 500
    timeout: int | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "NaabuConfig":
        return cls(
            top_ports=_req_int(cfg, "top_ports", 100, minimum=1, maximum=65535),
            limit=_req_int(cfg, "limit", 500, minimum=1),
            timeout=_opt_int(cfg, "timeout", minimum=1),
        )


@dataclass(frozen=True)
class KatanaConfig:
    limit: int = 100
    status_code: int | None = None
    depth: int = 3
    js_crawl: bool = False
    timeout: int | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "KatanaConfig":
        return cls(
            limit=_req_int(cfg, "limit", 100, minimum=1),
            status_code=_opt_int(cfg, "status_code"),
            depth=_req_int(cfg, "depth", 3, minimum=1, maximum=10),
            js_crawl=_opt_bool(cfg, "js_crawl", False),
            timeout=_opt_int(cfg, "timeout", minimum=1),
        )


@dataclass(frozen=True)
class GauConfig:
    # Wildcard scope entries are the targets, so subdomains are included by default.
    subs: bool = True
    # Empty means gau's own default: every provider.
    providers: tuple[str, ...] = ()
    timeout: int | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "GauConfig":
        return cls(
            subs=_opt_bool(cfg, "subs", True),
            providers=_parse_choices(cfg.get("providers"), "providers", GAU_PROVIDERS),
            timeout=_opt_int(cfg, "timeout", minimum=1),
        )


def _parse_wordlist(raw) -> str:
    """Validate a wordlist *name*. Paths are refused outright, not sanitized."""
    if raw is None or raw == "":
        return "common"
    if not isinstance(raw, str):
        raise ConfigError(f"'wordlist' must be a name, got {type(raw).__name__}")
    name = raw.strip()
    if not WORDLIST_NAME.match(name):
        raise ConfigError(
            f"invalid wordlist name {raw!r}: expected a name like 'common' or 'api-paths' "
            "(lowercase letters, digits, '-' and '_'), not a path. Wordlists are resolved "
            "against the runner's own wordlists directory."
        )
    return name


def _parse_extensions(raw) -> tuple[str, ...]:
    """Normalize fuzzing extensions to a de-duplicated tuple of '.ext' tokens."""
    if raw is None or raw == "":
        return ()
    if isinstance(raw, str):
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
    elif isinstance(raw, (list, tuple)):
        tokens = [str(t).strip() for t in raw if str(t).strip()]
    else:
        raise ConfigError(f"'extensions' must be a string or list, got {type(raw).__name__}")
    normalized = [t if t.startswith(".") else f".{t}" for t in tokens]
    invalid = [t for t in normalized if not _EXTENSION.match(t)]
    if invalid:
        raise ConfigError(f"invalid extension(s) {invalid}; expected values like '.php' or '.bak'")
    return tuple(dict.fromkeys(normalized))


def _parse_match_codes(raw) -> str | None:
    """Normalize ffuf's status-code filter to a comma string, or None for its default."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, str):
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
    elif isinstance(raw, (list, tuple)):
        tokens = [str(t).strip() for t in raw if str(t).strip()]
    else:
        raise ConfigError(f"'match_codes' must be a string or list, got {type(raw).__name__}")
    if tokens == ["all"]:
        return "all"
    invalid = [t for t in tokens if not _STATUS_CODE.match(t)]
    if invalid:
        raise ConfigError(
            f"invalid match_codes {invalid}; expected three-digit statuses like '200,301,403', "
            "or 'all'"
        )
    return ",".join(dict.fromkeys(tokens)) or None


@dataclass(frozen=True)
class FfufConfig:
    """Config for a content-discovery fuzz with ffuf.

    ``wordlist`` is a name, not a path — see ``WORDLIST_NAME``. ``rate`` caps
    requests per second because this is the one tool here that puts sustained
    load on a client's host; it has a default and a ceiling, and no way to
    disable it.
    """

    wordlist: str = "common"
    extensions: tuple[str, ...] = ()
    match_codes: str | None = None
    rate: int = FFUF_DEFAULT_RATE
    limit: int = 100
    timeout: int | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "FfufConfig":
        return cls(
            wordlist=_parse_wordlist(cfg.get("wordlist")),
            extensions=_parse_extensions(cfg.get("extensions")),
            match_codes=_parse_match_codes(cfg.get("match_codes")),
            rate=_req_int(cfg, "rate", FFUF_DEFAULT_RATE, minimum=1, maximum=FFUF_MAX_RATE),
            limit=_req_int(cfg, "limit", 100, minimum=1),
            timeout=_opt_int(cfg, "timeout", minimum=1),
        )


@dataclass(frozen=True)
class VardrGateConfig:
    """Config for a VardrGate API authorization test job.

    Unlike the recon tools, this job is self-contained: the ``test_case`` (and
    optional ``execution`` settings) travel inside the job config rather than
    being resolved from engagement scope/recon. VardrGate itself enforces SSRF and
    credential-redaction guarantees; the runner only shells out to it.
    """

    test_case: dict
    execution: dict
    policy_id: str | None = None

    @classmethod
    def from_dict(cls, cfg: dict) -> "VardrGateConfig":
        test_case = cfg.get("test_case")
        if not isinstance(test_case, dict) or not test_case:
            raise ConfigError("'test_case' is required and must be an object")
        execution = cfg.get("execution") or {}
        if not isinstance(execution, dict):
            raise ConfigError("'execution' must be an object")
        policy_id = cfg.get("policy_id")
        return cls(
            test_case=test_case,
            execution=execution,
            policy_id=str(policy_id) if policy_id else None,
        )
