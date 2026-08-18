"""Inspect and label this runner installation."""

from __future__ import annotations

import typer
from rich.console import Console

from vardrrunner import identity, redaction

console = Console()


def show() -> None:
    try:
        current = identity.load_or_create()
    except identity.IdentityError as exc:
        console.print(
            f"[red]Runner identity unavailable:[/red] {redaction.redact_rich_exception(exc)}"
        )
        raise typer.Exit(1) from exc
    console.print(f"Runner ID: [bold]{current.runner_id}[/bold]")
    console.print(f"Name: {redaction.redact_rich_text(current.name)}")
    console.print(f"Hostname: {redaction.redact_rich_text(current.hostname)}")


def set_name(name: str) -> None:
    try:
        current = identity.rename(name)
    except identity.IdentityError as exc:
        console.print(
            f"[red]Could not update runner name:[/red] {redaction.redact_rich_exception(exc)}"
        )
        raise typer.Exit(1) from exc
    console.print(f"[green]Runner name set:[/green] {redaction.redact_rich_text(current.name)}")
