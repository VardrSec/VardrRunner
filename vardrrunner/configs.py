"""
Typed, validated configuration for scan jobs.

Job configs arrive from the backend as raw dicts. These dataclasses parse and
validate them once, up front, so the rest of the runner works with checked values
and a bad/drifted payload fails fast with a clear message instead of blowing up
deep inside execution. Each tool's config is a frozen dataclass with a
``from_dict`` classmethod that raises ``ConfigError`` on anything invalid.
"""

from dataclasses import dataclass

# Severities nuclei accepts — mirrors the backend's own validation.
NUCLEI_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
SUPPORTED_JOB_SCHEMA_VERSIONS = frozenset({1})


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
