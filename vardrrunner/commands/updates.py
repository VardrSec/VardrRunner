"""Check whether a newer VardrRunner release is available."""

from __future__ import annotations

import json

import typer
from rich.console import Console

from vardrrunner import redaction, updates

console = Console()


def check(force: bool = False, as_json: bool = False) -> None:
    try:
        status = updates.check(force=force)
    except updates.UpdateCheckError as exc:
        console.print(f"[red]Update check failed:[/red] {redaction.redact_rich_exception(exc)}")
        raise typer.Exit(1) from exc
    if as_json:
        console.print_json(json.dumps(status.payload()))
        return
    if status.update_available:
        console.print(
            f"[yellow]Update available:[/yellow] {status.current} → {status.latest}\n"
            "Run `pipx upgrade vardrrunner` or `uv tool upgrade vardrrunner`."
        )
    else:
        console.print(f"[green]Up to date.[/green] VardrRunner {status.current}")
    source = "cache" if status.from_cache else "registry"
    console.print(f"[dim]Checked {status.checked_at} via {source}.[/dim]")
