"""Explicit local metadata commands; workspace presence grants no authority."""

import json
from dataclasses import asdict

import typer
from rich.console import Console

from vardrrunner import config
from vardrrunner.journal import Journal, JournalError
from vardrrunner.workspaces import WorkspaceError, Workspaces, validate_id, validate_name

console = Console()


def create(name: str) -> None:
    try:
        validate_name(name)
        record = Workspaces(Journal(config.journal_file())).create(name)
    except (OSError, JournalError, WorkspaceError):
        console.print("[red]Cannot create workspace; check its name and local journal.[/red]")
        raise typer.Exit(1) from None
    console.print_json(json.dumps(asdict(record)))


def show(workspace_id: str) -> None:
    try:
        validate_id(workspace_id)
        path = config.journal_file()
        # Inspecting an absent workspace must not initialize a new journal.
        if not path.is_file():
            raise WorkspaceError("Workspace not found")
        record = Workspaces(Journal(path)).get(workspace_id)
        if record is None:
            raise WorkspaceError("Workspace not found")
    except (OSError, JournalError, WorkspaceError):
        console.print("[red]Cannot read workspace; check its ID and local journal.[/red]")
        raise typer.Exit(1) from None
    console.print_json(json.dumps(asdict(record)))
