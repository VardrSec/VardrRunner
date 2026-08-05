"""
Target resolution — turn a target source (scope, recon, inline, or file) into a
concrete list of targets.

This lives in its own module (rather than in `commands/run.py`) so both the direct
`run` commands and the tool handlers can share it without an import cycle.
"""

from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import api

console = Console()

# Wildcard prefixes we refuse to scan directly (enumerate with subfinder first).
_WILDCARD_PREFIXES = ("*.", "*")


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
) -> list[str]:
    """Collect the target list from the chosen source."""
    if target:
        return [target]

    if targets_file:
        if not targets_file.exists():
            console.print(f"[red]File not found:[/red] {targets_file}")
            raise typer.Exit(1)
        return [line.strip() for line in targets_file.read_text().splitlines() if line.strip()]

    if scope:
        raw = client.scope(engagement_id)
        in_scope = raw.get("in", [])
        resolved, skipped = [], []
        for item in in_scope:
            val = item.get("value", "")
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
        return resolved

    if from_recon:
        items = client.recon(engagement_id, limit=limit, status_code=status_code)
        targets = []
        for item in items:
            val = item.get("url") or item.get("host")
            if val:
                targets.append(val)
        return targets

    console.print(
        "[red]No target source specified.[/red] Use --scope, --from-recon, --target, or --targets."
    )
    raise typer.Exit(1)
