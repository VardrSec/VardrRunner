"""
Target resolution — turn a target source (scope, recon, inline, or file) into a
concrete list of targets.

This lives in its own module (rather than in `commands/run.py`) so both the direct
`run` commands and the tool handlers can share it without an import cycle.
"""

from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit

import typer
from rich.console import Console

from vardrrunner import api, redaction, target_safety

console = Console()

# Wildcard prefixes we refuse to scan directly (enumerate with subfinder first).
_WILDCARD_PREFIXES = ("*.", "*")
MAX_TARGET_LENGTH = 2048
MAX_TARGET_FILE_BYTES = 10 * 1024**2


class TargetValidationError(ValueError):
    """A target has an unsafe or unsupported shape."""


def validate_targets(targets: list[str]) -> list[str]:
    """Validate, trim, and de-duplicate targets without changing authorization policy."""
    clean: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(targets, start=1):
        if not isinstance(raw, str):
            raise TargetValidationError(f"target {index} is not a string")
        value = raw.strip()
        if not value:
            continue
        if len(value) > MAX_TARGET_LENGTH:
            raise TargetValidationError(f"target {index} exceeds {MAX_TARGET_LENGTH} characters")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise TargetValidationError(f"target {index} contains control characters")
        if any(char.isspace() for char in value):
            raise TargetValidationError(f"target {index} contains whitespace")
        if value.startswith("-"):
            raise TargetValidationError(f"target {index} begins with an option marker")
        if "://" in value:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise TargetValidationError(f"target {index} is not an http(s) URL")
            if parsed.username is not None or parsed.password is not None:
                raise TargetValidationError(f"target {index} contains URL credentials")
        if value not in seen:
            seen.add(value)
            clean.append(value)
    return clean


def _safe(targets: list[str]) -> list[str]:
    try:
        clean = validate_targets(targets)
    except TargetValidationError as exc:
        console.print(f"[red]Invalid target input:[/red] {exc}")
        raise typer.Exit(1) from exc
    return screen_targets(clean)


def screen_targets(targets: list[str]) -> list[str]:
    """Surface advisory findings and enforce locally-configured deny rules.

    Findings (loopback, link-local, cloud metadata) are **advisory** and never
    block — the same contract the backend's scope findings follow. Only a deny
    rule the operator configured blocks, and ``VARDRRUNNER_ALLOW_DENIED_TARGETS``
    overrides that explicitly.
    """
    for finding in target_safety.assess(targets):
        console.print(f"[yellow]⚠ {redaction.redact_rich_text(finding.describe())}[/yellow]")

    rules = target_safety.load_deny_rules()
    allowed, denied = target_safety.apply_deny_rules(targets, rules)
    if not denied:
        return allowed

    if target_safety.override_enabled():
        for finding in denied:
            console.print(
                f"[yellow]override:[/yellow] "
                f"{redaction.redact_rich_text(finding.describe())} — permitted by "
                f"{target_safety.ENV_ALLOW_DENIED}"
            )
        return list(targets)

    for finding in denied:
        console.print(f"[red]blocked:[/red] {redaction.redact_rich_text(finding.describe())}")
    if not allowed:
        console.print(
            f"[red]All targets blocked by local deny rules.[/red] Set "
            f"{target_safety.ENV_ALLOW_DENIED}=1 to override."
        )
        raise typer.Exit(1)
    console.print(
        f"[yellow]{len(denied)} target(s) blocked, continuing with {len(allowed)}.[/yellow] "
        f"Set {target_safety.ENV_ALLOW_DENIED}=1 to override."
    )
    return allowed


def _malformed_source(source: str) -> NoReturn:
    console.print(f"[red]Invalid target data:[/red] malformed {source} response")
    raise typer.Exit(1)


def _is_wildcard(value: str) -> bool:
    return any(value.startswith(p) for p in _WILDCARD_PREFIXES)


def _resolve_targets(
    client: api.VardrMapClient,
    engagement_id: str,
    scope: bool,
    from_recon: bool,
    target: str | None,
    targets_file: Path | None,
    status_code: int | None,
    limit: int,
    apply_local_policy: bool = True,
) -> list[str]:
    """Collect targets, optionally applying the interactive local policy layer.

    Direct commands and pipelines use the default so warnings and local deny
    rules are presented immediately. The unattended queue passes ``False`` and
    lets its journal-aware lifecycle validate, screen, and audit exactly once.
    """

    def finalize(values: list[str]) -> list[str]:
        return _safe(values) if apply_local_policy else values

    if target:
        return finalize([target])

    if targets_file:
        if not targets_file.exists():
            console.print(f"[red]File not found:[/red] {targets_file}")
            raise typer.Exit(1)
        try:
            if targets_file.stat().st_size > MAX_TARGET_FILE_BYTES:
                raise TargetValidationError(
                    f"target file exceeds {MAX_TARGET_FILE_BYTES // 1024**2} MiB"
                )
            lines = targets_file.read_text().splitlines()
        except (OSError, TargetValidationError) as exc:
            console.print(f"[red]Could not read target file:[/red] {exc}")
            raise typer.Exit(1) from exc
        return finalize(lines)

    if scope:
        raw = client.scope(engagement_id)
        if not isinstance(raw, dict):
            _malformed_source("scope")
        in_scope = raw.get("in", [])
        if not isinstance(in_scope, list):
            _malformed_source("scope")
        resolved, skipped = [], []
        for item in in_scope:
            if not isinstance(item, dict):
                _malformed_source("scope")
            val = item.get("value", "")
            if not isinstance(val, str):
                _malformed_source("scope")
            if _is_wildcard(val):
                skipped.append(val)
            else:
                resolved.append(val)
        if skipped:
            console.print(
                "[yellow]Skipping wildcards (run subfinder first to enumerate hosts):[/yellow]"
            )
            for s in skipped:
                console.print(f"  [dim]skip:[/dim] {s}")
        return finalize(resolved)

    if from_recon:
        items = client.recon(engagement_id, limit=limit, status_code=status_code)
        if not isinstance(items, list):
            _malformed_source("recon")
        targets = []
        for item in items:
            if not isinstance(item, dict):
                _malformed_source("recon")
            val = item.get("url") or item.get("host")
            if isinstance(val, str):
                targets.append(val)
        return finalize(targets)

    console.print(
        "[red]No target source specified.[/red] Use --scope, --from-recon, --target, or --targets."
    )
    raise typer.Exit(1)
