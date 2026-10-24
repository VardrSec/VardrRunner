"""Check for, and install, a newer VardrRunner release."""

from __future__ import annotations

import json

import typer
from rich.console import Console

from vardrrunner import redaction, updates

console = Console()


def _fresh_status() -> updates.UpdateStatus:
    # An explicit command always asks the registry: a 24-hour cache once answered
    # "Up to date" hours after a release.
    try:
        return updates.check(force=True)
    except updates.UpdateCheckError as exc:
        console.print(f"[red]Update check failed:[/red] {redaction.redact_rich_exception(exc)}")
        raise typer.Exit(1) from exc


def check(as_json: bool = False) -> None:
    status = _fresh_status()
    if as_json:
        console.print_json(json.dumps(status.payload()))
        return
    if status.update_available:
        console.print(updates.notice(status))
    else:
        console.print(f"[green]Up to date.[/green] VardrRunner {status.current}")
    source = "cache" if status.from_cache else "registry"
    console.print(f"[dim]Checked {status.checked_at} via {source}.[/dim]")


def upgrade() -> None:
    """Install the newest release in the foreground, with the installer this copy came from."""
    status = _fresh_status()
    if not status.update_available:
        console.print(f"[green]Up to date.[/green] VardrRunner {status.current}")
        return
    argv = updates.upgrade_argv()
    if argv is None:
        console.print(
            f"Update available: {status.current} → {status.latest}. This install can't be "
            f"upgraded from inside VardrRunner; run {updates.upgrade_command()}."
        )
        raise typer.Exit(1)
    console.print(f"Updating VardrRunner {status.current} → {status.latest}…")
    result = updates.run_upgrade(argv)
    if result.returncode != 0:
        output = redaction.redact_rich_text((result.stdout + result.stderr).strip())
        console.print(f"[red]Update failed[/red] (exit {result.returncode}).\n{output}")
        raise typer.Exit(result.returncode)
    installed = updates.installed_version()
    if installed is None:
        console.print("[green]Updated.[/green] Run `vardrrunner --version` to confirm.")
    elif installed != status.latest:
        # The installer exited 0 without installing the release, e.g. pinned to an old spec.
        output = redaction.redact_rich_text((result.stdout + result.stderr).strip())
        console.print(
            f"[yellow]The installer finished, but VardrRunner is still {installed}, "
            f"not {status.latest}.[/yellow] Run {updates.upgrade_command()} yourself.\n{output}"
        )
        raise typer.Exit(1)
    else:
        console.print(f"[green]Updated to VardrRunner {installed}.[/green]")
