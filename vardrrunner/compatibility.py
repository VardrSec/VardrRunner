"""Runner/backend capability advertisement and compatibility evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from vardrrunner import __version__

JOB_SCHEMA_VERSIONS = (1,)
CAPABILITIES = frozenset(
    {
        "audit_journal_v1",
        "job_events",
        "job_schema_v1",
        "manifest_v1",
        "policy_warnings",
        "runner_identity_v1",
        "stop_work",
    }
)

_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")


class CompatibilityLevel(str, Enum):
    OK = "ok"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class CompatibilityReport:
    level: CompatibilityLevel
    messages: tuple[str, ...] = ()

    @property
    def compatible(self) -> bool:
        return self.level is not CompatibilityLevel.BLOCK


def version_tuple(value: str) -> tuple[int, int, int]:
    match = _SEMVER.fullmatch(value.strip())
    if not match:
        raise ValueError(f"invalid semantic version {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def advertisement() -> dict[str, object]:
    return {
        "runner_version": __version__,
        "job_schema_versions": list(JOB_SCHEMA_VERSIONS),
        "capabilities": sorted(CAPABILITIES),
    }


def evaluate(payload: object, current_version: str = __version__) -> CompatibilityReport:
    """Evaluate optional compatibility data; absent data means a legacy backend."""
    if not isinstance(payload, dict):
        return CompatibilityReport(CompatibilityLevel.OK)
    raw = payload.get("compatibility")
    if raw is None:
        return CompatibilityReport(CompatibilityLevel.OK)
    if not isinstance(raw, dict):
        return CompatibilityReport(
            CompatibilityLevel.WARN, ("backend returned malformed compatibility metadata",)
        )

    blocks: list[str] = []
    warnings: list[str] = []
    try:
        current = version_tuple(current_version)
    except ValueError:
        return CompatibilityReport(
            CompatibilityLevel.BLOCK, ("runner has an invalid package version",)
        )

    for key, comparison, wording in (
        ("min_runner_version", lambda have, bound: have < bound, "requires runner >="),
        ("max_runner_version", lambda have, bound: have > bound, "supports runner <="),
    ):
        value = raw.get(key)
        if value is None:
            continue
        try:
            bound = version_tuple(str(value))
        except ValueError:
            warnings.append(f"backend returned invalid {key}")
            continue
        if comparison(current, bound):
            blocks.append(f"backend {wording} {value}; this runner is {current_version}")

    required = raw.get("required_capabilities", [])
    if isinstance(required, list) and all(isinstance(item, str) for item in required):
        missing = sorted(set(required) - CAPABILITIES)
        if missing:
            blocks.append("runner lacks required capabilities: " + ", ".join(missing))
    elif required not in (None, []):
        warnings.append("backend returned malformed required_capabilities")

    schemas = raw.get("job_schema_versions")
    if isinstance(schemas, list) and schemas:
        remote = {item for item in schemas if isinstance(item, int) and not isinstance(item, bool)}
        if not remote.intersection(JOB_SCHEMA_VERSIONS):
            blocks.append("runner and backend share no supported job schema version")
    elif schemas not in (None, []):
        warnings.append("backend returned malformed job_schema_versions")

    if blocks:
        return CompatibilityReport(CompatibilityLevel.BLOCK, tuple(blocks + warnings))
    if warnings:
        return CompatibilityReport(CompatibilityLevel.WARN, tuple(warnings))
    return CompatibilityReport(CompatibilityLevel.OK)
