"""Install and inspect VardrRunner as a per-user background service."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import config, identity, redaction, service
from vardrrunner.journal import Journal

console = Console()


def _plan(env_file: Path | None = None):
    try:
        return service.build_plan(env_file=env_file)
    except service.ServiceError as exc:
        console.print(f"[red]Service unavailable:[/red] {redaction.redact_rich_exception(exc)}")
        raise typer.Exit(1) from exc


def _preflight() -> None:
    """Refuse installation that would enter a restart loop immediately."""
    try:
        config.require_auth()
        Journal(config.journal_file())
        identity.load_or_create()
    except Exception as exc:
        console.print(
            f"[red]Service preflight failed:[/red] {redaction.redact_rich_exception(exc)}"
        )
        raise typer.Exit(1) from exc


def install(env_file: Path | None = None, start: bool = True, dry_run: bool = False) -> None:
    plan = _plan(env_file)
    if dry_run:
        console.print(f"Service kind: {plan.kind}")
        if plan.definition_path:
            console.print(f"Definition: {plan.definition_path}")
        for command in (
            *plan.install_commands,
            *((plan.start_command,) if start and plan.start_command else ()),
        ):
            console.print("  " + " ".join(redaction.redact_rich_text(part) for part in command))
        return
    _preflight()
    try:
        service.install(plan, start=start)
    except (OSError, service.ServiceError) as exc:
        console.print(f"[red]Service install failed:[/red] {redaction.redact_rich_exception(exc)}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Installed {plan.kind} service.[/green]")
    if plan.kind == "systemd-user":
        console.print(
            "[yellow]Boot without login requires user lingering:[/yellow] "
            "ask an administrator to run `loginctl enable-linger <user>`."
        )


def uninstall() -> None:
    plan = _plan()
    try:
        service.uninstall(plan)
    except (OSError, service.ServiceError) as exc:
        console.print(
            f"[red]Service uninstall failed:[/red] {redaction.redact_rich_exception(exc)}"
        )
        raise typer.Exit(1) from exc
    console.print(f"[green]Removed {plan.kind} service.[/green]")


def show_status() -> None:
    plan = _plan()
    try:
        running, detail = service.status(plan)
    except service.ServiceError as exc:
        console.print(f"[red]Service status failed:[/red] {redaction.redact_rich_exception(exc)}")
        raise typer.Exit(1) from exc
    label = "active" if running else "not active"
    color = "green" if running else "yellow"
    console.print(f"[{color}]{label}[/{color}] · {plan.kind}")
    if detail:
        console.print(redaction.redact_rich_text(detail))
