"""Reject startup installation and retain legacy service cleanup."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import redaction, service

console = Console()


def _plan():
    try:
        return service.build_plan()
    except service.ServiceError as exc:
        console.print(f"[red]Service unavailable:[/red] {redaction.redact_rich_exception(exc)}")
        raise typer.Exit(1) from exc


def install(
    env_file: Path | None = None,
    start: bool = True,
    dry_run: bool = False,
    run_jobs: bool = False,
) -> None:
    console.print(
        "[red]Startup services are no longer supported.[/red] "
        "Install the program with `pipx install vardrrunner`; run scans explicitly with "
        "`vardrrunner run <tool>` or `vardrrunner jobs run`. "
        "To remove an older startup service, use `vardrrunner service uninstall`."
    )
    raise typer.Exit(2)


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
