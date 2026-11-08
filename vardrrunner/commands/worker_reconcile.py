"""Explicit bounded original-key worker reconciliation; no job or PID action."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from vardrrunner import api, config
from vardrrunner.authorization import worker_reconciliation as worker
from vardrrunner.authorization.codec import require
from vardrrunner.authorization.worker_inspection import inspect_worker_state
from vardrrunner.journal import Journal


def worker_reconcile(
    *,
    journal: str,
    identity: str,
    runner_id: str,
    runtime_id: str,
    runtime_sha256: str,
    admission_sha256: str,
) -> None:
    selected = dict(
        journal=journal,
        identity=identity,
        runner_id=runner_id,
        runtime_id=runtime_id,
        runtime_sha256=runtime_sha256,
        admission_sha256=admission_sha256,
    )
    result, candidate, _ = worker.select_candidate(**selected)
    if candidate is not None:
        key = None
        try:
            # Binding/schema/identity and the unique original run are already
            # validated. Keep the existing environment/keychain/plaintext policy.
            url, key = config.require_auth()
            client = api.VardrMapClient(url, key)
            require(client.base == candidate.origin, "configured_origin_required")
            store = Journal.open_existing(
                Path(journal), expected_identity=candidate.journal_identity
            )
            state = worker.reconcile_candidate(
                store,
                candidate,
                runner_id,
                lambda body: client.managed_post(
                    f"/jobs/{candidate.job_id}/managed/observation", body
                ),
            )
            audit = inspect_worker_state(
                **selected, expected_journal_identity=candidate.journal_identity
            )
            result = worker.finish(candidate, state, audit)
        except Exception:
            result = worker.document(
                "held", reason="original_reconciliation_unavailable", binding=result["binding"]
            )
        finally:
            key = None
    typer.echo(json.dumps(result, sort_keys=True, separators=(",", ":")))
    if result["status"] == "held":
        raise typer.Exit(1)
