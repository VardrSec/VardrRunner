"""Explicit authenticated observation and local managed metadata retirement."""

from __future__ import annotations

import json

import typer

from vardrrunner import api, config, identity
from vardrrunner.authorization import observations
from vardrrunner.authorization.codec import identifier, require
from vardrrunner.authorization.reconciliation import local_holds, reconcile_managed
from vardrrunner.journal import Journal


def reconcile_managed_run(*, run_id: str) -> None:
    """No execution, uploads, server mutation, PID action or capability recovery."""
    try:
        identifier(run_id)
        require(identity.identity_file().is_file(), "original_runner_required")
        runner_id = identity.load_or_create().runner_id
        url, key = config.require_auth()
        client = api.VardrMapClient(url, key)
        journal = Journal(config.journal_file())
        root, _ = observations.original(journal, run_id, runner_id)
        require(client.base == root["origin"], "configured_origin_required")

        def inspect(body: dict) -> dict:
            return client.managed_post(f"/jobs/{root['job_id']}/managed/observation", body)

        state = reconcile_managed(journal, run_id, runner_id, inspect)
        holds = local_holds(journal)
        print(json.dumps({"state": state, "remaining_local_holds": holds}, sort_keys=True))
        if not state.startswith(("terminal_", "local_preclaim_retired")) or holds:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception:
        print("managed_reconciliation_held")
        raise typer.Exit(1) from None
