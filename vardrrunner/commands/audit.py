"""Inspect and export the sanitized local execution journal."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import config, manifests, redaction
from vardrrunner.journal import Journal, JournalError, RunRecord

console = Console()


def _payload(record: RunRecord) -> dict[str, Any]:
    data = asdict(record)
    data["phase"] = record.phase.value
    return redaction.redact(data)


def _store() -> Journal:
    try:
        return Journal(config.journal_file())
    except (OSError, JournalError) as exc:
        console.print(
            f"[red]Cannot open execution journal:[/red] {redaction.redact_rich_exception(exc)}"
        )
        raise typer.Exit(1) from exc


def list_runs(since: str | None = None, limit: int = 100, as_json: bool = False) -> None:
    records = _store().list(since=since, limit=limit)
    if as_json:
        console.print_json(json.dumps([_payload(record) for record in records]))
        return
    if not records:
        console.print("[dim]No journaled runs.[/dim]")
        return
    table = Table(title="Execution Audit")
    table.add_column("Run")
    table.add_column("Job")
    table.add_column("Tool")
    table.add_column("Phase")
    table.add_column("Started")
    table.add_column("Status")
    for record in records:
        table.add_row(
            record.run_id[:10],
            redaction.redact_text(record.job_id)[:10],
            record.tool,
            record.phase.value,
            record.started_at[:19],
            record.status,
        )
    console.print(table)


def show_run(run_id: str) -> None:
    record = _store().get(run_id)
    if record is None:
        console.print(f"[red]Run not found:[/red] {redaction.redact_rich_text(run_id)}")
        raise typer.Exit(1)
    console.print_json(json.dumps(_payload(record), indent=2, sort_keys=True))


def export_runs(output: Path, since: str | None = None, limit: int = 10_000) -> None:
    records = _store().list(since=since, limit=limit)
    document = {
        "audit_schema_version": 1,
        "run_count": len(records),
        "runs": [_payload(record) for record in records],
    }
    try:
        manifests.write_atomic_json(output, document)
    except OSError as exc:
        console.print(f"[red]Could not export audit:[/red] {redaction.redact_rich_exception(exc)}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Exported {len(records)} run(s)[/green] to {output}")
