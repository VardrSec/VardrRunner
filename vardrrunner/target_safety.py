"""Classification of resolved targets, and locally-configured deny rules.

`targets.validate_targets()` answers "is this a well-formed target?". This module
answers a different question: "is this target somewhere you probably did not mean
to point a scanner?"

**Warnings never block.** Loopback, link-local and cloud-metadata findings are
advisory, exactly like the backend's scope findings — the operator is
responsible for where they aim, and a runner that guesses wrong blocks
legitimate work mid-engagement. The one thing that blocks is a **local deny
rule** the operator configured themselves, and even that has an explicit,
audited override.

The cloud-metadata case is why this module exists. VardrRunner is designed to run
unattended on a VPS, and `169.254.169.254` answers from inside almost every cloud
network with instance credentials attached. A job whose targets resolve there is
worth saying something about, loudly, before a tool is spawned.

Classification is purely lexical — an address literal is parsed, a hostname is
not resolved. Doing DNS here would mean a network call per target on a path that
must stay fast and offline-safe, and would introduce a TOCTOU gap between the
check and the tool's own resolution anyway.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from vardrrunner import config


class TargetClass(str, Enum):
    """What kind of address a target names. Values are stable — they appear in
    deny rules the operator writes and in audit records."""

    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    CLOUD_METADATA = "cloud_metadata"
    HOSTNAME = "hostname"


# Link-local addresses that serve instance metadata, across providers. These are
# checked before the generic link-local rule so the more specific — and far more
# sensitive — finding wins.
_METADATA_IPS = frozenset(
    {
        "169.254.169.254",  # AWS, GCP, Azure, DigitalOcean, OpenStack
        "169.254.169.253",  # AWS VPC DNS
        "169.254.169.123",  # AWS VPC NTP
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud (legacy)
        "fd00:ec2::254",  # AWS IPv6
    }
)

_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
    }
)

# Classes that produce an advisory warning when seen. PRIVATE is classified and
# counted but not warned about: internal-range targets are routine and expected
# on an internal engagement, and warning on them would train operators to ignore
# the output.
WARNED_CLASSES = frozenset(
    {TargetClass.CLOUD_METADATA, TargetClass.LOOPBACK, TargetClass.LINK_LOCAL}
)

_CLASS_MESSAGES = {
    TargetClass.CLOUD_METADATA: (
        "cloud instance-metadata endpoint — reachable from inside the cloud network "
        "and commonly serves instance credentials"
    ),
    TargetClass.LOOPBACK: "loopback address — this scans the runner host itself",
    TargetClass.LINK_LOCAL: "link-local address — not routable beyond this network segment",
}

# Hostnames that always denote the runner host itself. Classified lexically
# because "scanning localhost" is worth flagging whether or not DNS agrees.
_LOOPBACK_HOSTS = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

ENV_DENY = "VARDRRUNNER_DENY_TARGETS"
ENV_ALLOW_DENIED = "VARDRRUNNER_ALLOW_DENIED_TARGETS"
CONFIG_DENY_KEY = "deny_targets"


def host_of(target: str) -> str:
    """Extract the host from a URL or bare ``host[:port]`` target.

    Purely lexical and total: anything unparseable comes back as-is so the
    caller still has something to show the operator.
    """
    value = (target or "").strip()
    if not value:
        return value
    if "://" in value:
        parsed = urlsplit(value)
        return parsed.hostname or value
    # Bare IPv6 literals may be bracketed, with or without a port.
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    # Strip a port only when it cannot be part of a bare IPv6 address.
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.split("/", 1)[0]


def classify(target: str) -> TargetClass:
    """Classify a single target. Never raises; never performs DNS."""
    host = host_of(target).lower().rstrip(".")
    if not host:
        return TargetClass.HOSTNAME
    if host in _METADATA_HOSTS:
        return TargetClass.CLOUD_METADATA
    if host in _LOOPBACK_HOSTS:
        return TargetClass.LOOPBACK

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return TargetClass.HOSTNAME

    if host in _METADATA_IPS or str(ip) in _METADATA_IPS:
        return TargetClass.CLOUD_METADATA
    if ip.is_loopback:
        return TargetClass.LOOPBACK
    if ip.is_link_local:
        return TargetClass.LINK_LOCAL
    if ip.is_private:
        return TargetClass.PRIVATE
    return TargetClass.PUBLIC


@dataclass(frozen=True)
class TargetFinding:
    """One advisory finding about one target."""

    target: str
    target_class: TargetClass
    message: str

    def describe(self) -> str:
        return f"{self.target} — {self.message}"


@dataclass(frozen=True)
class TargetStats:
    """Counts for the audit trail. No target values, so it is safe to log."""

    received: int = 0
    accepted: int = 0
    duplicates_removed: int = 0
    blank_skipped: int = 0
    by_class: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        parts = [f"{self.accepted} target(s)"]
        if self.duplicates_removed:
            parts.append(f"{self.duplicates_removed} duplicate(s) removed")
        if self.blank_skipped:
            parts.append(f"{self.blank_skipped} blank line(s) skipped")
        classes = ", ".join(f"{k}={v}" for k, v in sorted(self.by_class.items()))
        if classes:
            parts.append(classes)
        return "; ".join(parts)


def summarize(original: list[str], accepted: list[str]) -> TargetStats:
    """Build stats by comparing what came in against what survived validation."""
    blanks = sum(1 for t in original if isinstance(t, str) and not t.strip())
    non_blank = len(original) - blanks
    by_class: dict[str, int] = {}
    for target in accepted:
        key = classify(target).value
        by_class[key] = by_class.get(key, 0) + 1
    return TargetStats(
        received=len(original),
        accepted=len(accepted),
        duplicates_removed=max(0, non_blank - len(accepted)),
        blank_skipped=blanks,
        by_class=by_class,
    )


def assess(targets: list[str]) -> tuple[TargetFinding, ...]:
    """Advisory findings for a resolved target list. Warnings only — never blocks."""
    findings: list[TargetFinding] = []
    for target in targets:
        klass = classify(target)
        if klass in WARNED_CLASSES:
            findings.append(TargetFinding(target, klass, _CLASS_MESSAGES[klass]))
    return tuple(findings)


def load_deny_rules() -> tuple[str, ...]:
    """Local deny rules, from the config file or the environment.

    Empty by default: **nothing blocks unless the operator configured it.** A
    rule is either a class name (``cloud_metadata``, ``loopback``,
    ``link_local``, ``private``, ``public``) or a literal host / IP / CIDR.
    """
    raw = os.environ.get(ENV_DENY)
    if raw is None:
        try:
            value = config.load().get(CONFIG_DENY_KEY)
        except config.InvalidConfigFile:
            return ()
        if isinstance(value, list):
            return tuple(str(v).strip() for v in value if str(v).strip())
        raw = value if isinstance(value, str) else ""
    return tuple(part.strip() for part in str(raw).split(",") if part.strip())


def _matches(target: str, rule: str) -> bool:
    """True when a deny rule covers a target. Unparseable rules match nothing."""
    rule = rule.strip().lower()
    if not rule:
        return False

    klass = classify(target)
    if rule == klass.value:
        return True

    host = host_of(target).lower().rstrip(".")
    if rule == host:
        return True

    if "/" in rule:
        try:
            network = ipaddress.ip_network(rule, strict=False)
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False
    return False


def apply_deny_rules(
    targets: list[str], rules: tuple[str, ...]
) -> tuple[list[str], tuple[TargetFinding, ...]]:
    """Split targets into allowed and denied. With no rules, nothing is denied."""
    if not rules:
        return list(targets), ()

    allowed: list[str] = []
    denied: list[TargetFinding] = []
    for target in targets:
        hit = next((r for r in rules if _matches(target, r)), None)
        if hit is None:
            allowed.append(target)
        else:
            denied.append(
                TargetFinding(target, classify(target), f"blocked by local deny rule {hit!r}")
            )
    return allowed, tuple(denied)


def override_enabled() -> bool:
    """Whether the operator has explicitly opted out of local deny rules.

    An environment variable rather than a CLI flag, deliberately: deny rules
    matter most on the unattended daemon path, where there is no command line to
    put a flag on. It mirrors ``VARDRRUNNER_ALLOW_INSECURE`` and, being part of
    the service environment, it is visible to anyone auditing the host.
    """
    return os.environ.get(ENV_ALLOW_DENIED, "").strip() in {"1", "true", "yes"}
