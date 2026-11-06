"""Fixed-JSON CLI facade for explicit, offline existing-worker inspection."""

from __future__ import annotations

import json

import typer

from vardrrunner.authorization.worker_inspection import inspect_worker_state


def worker_state(
    *,
    journal: str,
    identity: str,
    runner_id: str,
    runtime_id: str,
    runtime_sha256: str,
    admission_sha256: str,
) -> None:
    document = inspect_worker_state(
        journal=journal,
        identity=identity,
        runner_id=runner_id,
        runtime_id=runtime_id,
        runtime_sha256=runtime_sha256,
        admission_sha256=admission_sha256,
    )
    typer.echo(json.dumps(document, sort_keys=True, separators=(",", ":")))
    if document["status"] == "held":
        raise typer.Exit(1)
