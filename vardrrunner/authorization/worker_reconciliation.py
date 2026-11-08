"""One original worker-run reconciliation; no history guessing or execution."""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vardrrunner.identity import IdentityError, read_existing
from vardrrunner.journal import (
    Journal,
    JournalError,
    audit_rows,
    journal_connection,
    journal_path_identity,
)

from . import observations, worker_persistent
from . import worker_inspection as inspection
from .codec import AuthorizationError, decoded, encoded, identifier, require
from .persistent_codec import wire_sequence64
from .reconciliation import reconcile_managed
from .worker_binding import claim_association

SCHEMA = "vardr.worker-reconciliation/1"
_STATES = frozenset(
    {
        "terminal_runtime_unbound_retired",
        "terminal_runtime_preclaim_retired",
        "terminal_preclaim_parent_retired",
        "terminal_host_exit_observed",
        "terminal_failed_completion_observed",
        "terminal_receipt_observed",
        "terminal_stop_receipt_observed",
        "local_preclaim_retired",
        "held_no_retirement_receipt",
        "held_no_terminal_receipt",
        "held_no_receipt",
        "held_result_observed",
        "held_no_stop_receipt",
    }
)


@dataclass(frozen=True)
class Candidate:
    """Private immutable original association, not an execution capability."""

    run_id: str
    runtime_sequence: str
    association: bytes = field(repr=False)
    origin: str = field(repr=False)
    job_id: str
    journal_identity: tuple[int, int] = field(repr=False)
    preclaim_cohort: tuple[str, ...] | None = field(default=None, repr=False)


def document(
    status: str,
    *,
    reason: str | None = None,
    complete: bool = False,
    binding: dict | None = None,
    audit: dict | None = None,
    candidate: Candidate | None = None,
    state: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": status,
        "reason": reason,
        "complete": complete,
        "binding": binding,
        "selected_run_id": candidate.run_id if candidate is not None else None,
        "selected_sequence": candidate.runtime_sequence if candidate is not None else None,
        "reconciliation_state": state if state in _STATES else None,
        "remaining_local_holds": audit["global_holds"] if complete and audit is not None else None,
        "retirement_receipt_sha256": audit["retirement_receipt_sha256"]
        if complete and audit is not None
        else None,
    }


def _preclaim_anchor(con, snapshot, budget) -> tuple[str, tuple[str, ...]]:
    runtime, _, holds, counts, ids = snapshot
    require(holds == 0, "preclaim_parent0_global_holds")
    anchor, cohort = worker_persistent.preclaim_parent_anchor(
        con, runtime["runtime_id"], checkpoint=budget.check
    )
    require(
        ids == cohort
        and counts
        == {
            "attempts": 0,
            "selections": len(cohort),
            "associated_runs": len(cohort),
            "associated_claims": len(cohort),
        },
        "preclaim_parent0_associations",
    )
    return anchor, tuple(cohort)


def _check_preclaim_candidate(con, candidate: Candidate, link: dict, budget) -> None:
    con.set_progress_handler(budget.progress, 1000)
    binding = {
        key: link[key] for key in ("runner_id", "runtime_id", "runtime_sha256", "admission_sha256")
    }
    snapshot = inspection._worker_snapshot(con, binding, budget)
    anchor, cohort = _preclaim_anchor(con, snapshot, budget)
    require(
        anchor == candidate.run_id and cohort == candidate.preclaim_cohort,
        "preclaim_parent0_anchor_changed",
    )
    require(
        encoded(claim_association(con, candidate.run_id)) == candidate.association,
        "original_worker_association_required",
    )
    budget.check()


def select_candidate(
    *,
    journal: str,
    identity: str,
    runner_id: str,
    runtime_id: str,
    runtime_sha256: str,
    admission_sha256: str,
) -> tuple[dict, Candidate | None, dict]:
    """Select one structural original run in the existing read-only audit snapshot.

    A terminal/held document returns no candidate. No credentials, constructor,
    migration, API request or arbitrary limited history list is consulted.
    """
    binding = None
    try:
        binding = inspection._selection(
            journal, identity, runner_id, runtime_id, runtime_sha256, admission_sha256
        )
    except (AuthorizationError, TypeError, ValueError):
        return document("held", reason="selection_invalid"), None, {}
    budget = inspection._Budget()
    try:
        budget.check()
        saved = read_existing(Path(identity))
        require(saved.runner_id == binding["runner_id"], "original_runner_required")
        budget.check()
        original_identity = journal_path_identity(Path(journal))
        with journal_connection(
            Path(journal), readonly=True, expected_identity=original_identity
        ) as con:
            con.row_factory = sqlite3.Row
            con.set_progress_handler(budget.progress, 1000)
            con.execute("BEGIN")
            try:
                snapshot = inspection._worker_snapshot(con, binding, budget)
                runtime, _, _, _, ids = snapshot
                audit = inspection._audit_document(con, binding, budget, *snapshot)
                if audit["status"] in {"retired", "empty_unissued"}:
                    status = "already_retired" if audit["status"] == "retired" else "empty_unissued"
                    return (
                        document(status, complete=True, binding=binding, audit=audit),
                        None,
                        audit,
                    )
                if runtime["state"] == "retired":
                    return (
                        document(
                            "held",
                            reason="global_holds_remain",
                            complete=True,
                            binding=binding,
                            audit=audit,
                        ),
                        None,
                        audit,
                    )
                pending = list(
                    audit_rows(
                        con.execute(
                            "SELECT * FROM managed_persistent_selections WHERE runtime_id=? AND state='selected'",
                            (runtime_id,),
                        ),
                        budget.check,
                    )
                )
                if len(pending) > 1:
                    return (
                        document(
                            "held",
                            reason="ambiguous_pending_selection",
                            complete=True,
                            binding=binding,
                            audit=audit,
                        ),
                        None,
                        audit,
                    )
                preclaim_cohort = None
                if pending:
                    selected = pending[0]
                elif runtime["last_sequence"] > 0:
                    selected = con.execute(
                        "SELECT * FROM managed_persistent_attempts WHERE runtime_id=? AND runtime_sequence=?",
                        (runtime_id, runtime["last_sequence"]),
                    ).fetchone()
                    require(selected is not None, "worker_persistent_history_changed")
                else:
                    anchor, preclaim_cohort = _preclaim_anchor(con, snapshot, budget)
                    selected = con.execute(
                        "SELECT * FROM managed_persistent_selections WHERE run_id=?", (anchor,)
                    ).fetchone()
                    require(selected is not None, "preclaim_parent0_anchor_changed")
                run_id = selected["run_id"]
                require(
                    type(run_id) is str and re.fullmatch(r"[0-9a-f]{32}", run_id) is not None,
                    "original_local_run_required",
                )
                require(run_id in ids, "original_worker_association_required")
                link = claim_association(con, run_id)
                require(
                    link is not None and link["schema"] == "vardr.worker-claim-association/3",
                    "original_worker_association_required",
                )
                assert link is not None
                require(
                    all(link[key] == binding[key] for key in binding),
                    "original_worker_association_required",
                )
                sequence = wire_sequence64(selected["runtime_sequence"], minimum=1)
                require(
                    link["runtime_sequence"] == sequence, "original_worker_association_required"
                )
                identifier(link["job_id"])
                candidate = Candidate(
                    run_id,
                    sequence,
                    encoded(link),
                    link["origin"],
                    link["job_id"],
                    original_identity,
                    preclaim_cohort=preclaim_cohort,
                )
                budget.check()
                return (
                    document(
                        "selected", complete=True, binding=binding, audit=audit, candidate=candidate
                    ),
                    candidate,
                    audit,
                )
            finally:
                con.rollback()
    except inspection.InspectionExpired:
        reason = "inspection_budget_exhausted"
    except IdentityError:
        reason = "identity_unavailable"
    except (JournalError, OSError, sqlite3.Error):
        reason = (
            "inspection_budget_exhausted"
            if time.monotonic() >= budget.deadline
            else "journal_unavailable"
        )
    except (AuthorizationError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
        reason = "state_inconsistent"
    return document("held", reason=reason, binding=binding), None, {}


def reconcile_candidate(
    journal: Journal, candidate: Candidate, runner_id: str, inspect: Callable[[dict], dict]
) -> str:
    """Use the unchanged original-key observation route at most once.

    Existing source/transaction guards retain the original observations. The
    explicit association is rechecked before local preclaim retirement and each
    original observation; an original credential cannot be retargeted.
    """
    link = decoded(candidate.association, 8192)
    require(type(link) is dict and link["runner_id"] == runner_id, "original_runner_required")
    calls = 0
    preclaim_parent = candidate.preclaim_cohort is not None

    def original_observation(body: dict) -> dict:
        nonlocal calls
        expected = {
            key: link[key]
            for key in (
                "origin",
                "runner_id",
                "plan_sha256",
                "case_sha256",
                "association_sha256",
                "runtime_id",
                "runtime_sha256",
                "admission_sha256",
                "runtime_sequence",
            )
        }
        require(encoded(body) == encoded(expected), "original_worker_association_required")
        require(calls == 0, "worker_observation_already_attempted")
        if preclaim_parent:
            budget = inspection._Budget()
            with journal._connection() as con:
                con.execute("BEGIN")
                _check_preclaim_candidate(con, candidate, link, budget)
        calls += 1
        return inspect(body)

    if preclaim_parent:
        # Existing observation RECORD rechecks its original source and never
        # releases a hold. Only the following full transaction may retire parent0.
        reply = observations.observe(journal, candidate.run_id, runner_id, original_observation)
        budget = inspection._Budget()
        with journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            _check_preclaim_candidate(con, candidate, link, budget)
            observed = con.execute(
                "SELECT snapshot FROM managed_claim_observations WHERE run_id=?",
                (candidate.run_id,),
            ).fetchone()
            require(
                observed is not None and observed["snapshot"] == encoded(reply).decode(),
                "preclaim_parent0_observation_changed",
            )
            worker_persistent.retire_preclaim_parent_observation(
                con, candidate.run_id, reply["runtime_retirement"], checkpoint=budget.check
            )
        return "terminal_preclaim_parent_retired"

    state = reconcile_managed(
        journal,
        candidate.run_id,
        runner_id,
        original_observation,
        expected_association=candidate.association,
    )
    require(state in _STATES, "worker_reconciliation_state")
    return state


def finish(candidate: Candidate, state: str, audit: dict) -> dict:
    """Only a fresh complete retired audit with zero global holds succeeds."""
    success = (
        state in _STATES
        and state.startswith("terminal_")
        and audit["status"] == "retired"
        and audit["complete"] is True
        and audit["global_holds"] == 0
    )
    return document(
        "reconciled" if success else "held",
        reason=None if success else "post_reconciliation_held",
        complete=audit["complete"],
        binding=audit["binding"],
        audit=audit,
        candidate=candidate,
        state=state,
    )
