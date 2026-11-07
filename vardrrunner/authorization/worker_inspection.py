"""Explicit offline inspection of an existing persistent-worker journal.

This supplies facts for a host lifecycle review, never execution or retirement
authority. SQLite's ordinary read-only WAL handling remains in use.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from vardrrunner.identity import IdentityError, read_existing
from vardrrunner.journal import (
    SCHEMA_VERSION,
    Journal,
    JournalError,
    audit_rows,
    journal_connection,
)

from . import worker_persistent
from .codec import AuthorizationError, digest, encoded, fields, require
from .persistent_codec import sequence64
from .reconciliation import local_holds_connection
from .worker_admission import _uuid, hash_value
from .worker_binding import claim_association

SCHEMA = "vardr.worker-state-audit/1"
BOOTSTRAP_SCHEMA = "vardr.worker-bootstrap-audit/1"
INSPECTION_SECONDS = 30.0
_PERSISTENT_COLUMNS = {
    "managed_persistent_incarnations": {
        "runtime_id",
        "runtime_sha256",
        "admission_sha256",
        "admission_snapshot",
        "max_attempts",
        "last_sequence",
        "history_head",
        "active_sequence",
        "state",
        "retirement",
    },
    "managed_persistent_attempts": {
        "runtime_id",
        "runtime_sequence",
        "previous_sequence",
        "runtime_sha256",
        "admission_sha256",
        "run_id",
        "binding",
        "claim_link",
        "state",
        "completion",
        "native_done_sha256",
        "release_intent",
        "release_ack",
        "retirement",
        "retired_from_state",
    },
    "managed_persistent_selections": {
        "run_id",
        "runtime_id",
        "runtime_sequence",
        "runtime_sha256",
        "admission_sha256",
        "claim_link",
        "state",
        "retirement",
        "retired_from_state",
    },
}
_RUN_COLUMNS = {
    "run_id",
    "job_id",
    "backend_url",
    "engagement_id",
    "job_type",
    "tool",
    "job_schema_version",
    "target_source",
    "target_count",
    "command_profile",
    "phase",
    "pid",
    "run_dir",
    "artifact_path",
    "artifact_sha256",
    "artifact_size",
    "manifest_path",
    "last_event",
    "upload_state",
    "started_at",
    "claimed_at",
    "completed_at",
    "status",
    "failure_category",
    "failure_reason",
    "warnings_json",
    "updated_at",
}
_OPTIONAL_COLUMNS = {
    "managed_claim_intents": {
        "run_id",
        "backend",
        "job",
        "owner",
        "state",
        "plan_sha256",
        "case_sha256",
        "tool_sha256",
        "association_sha256",
        "utc_anchor",
        "mono_anchor",
        "issuer",
        "contract",
        "attempt",
        "fence",
        "approval_sha256",
        "authority_sha256",
        "consumption_sent",
        "consumption_acknowledged",
    },
    "managed_result_intents": {
        "run_id",
        "binding",
        "artifact_sha256",
        "artifact_size",
        "case_sha256",
        "receipt_sha256",
        "outcome",
        "state",
        "finish_sent",
    },
    "managed_stop_intents": {
        "run_id",
        "binding",
        "outcome",
        "cause",
        "receipt_sha256",
        "state",
        "observed_pid",
    },
    "managed_claim_observations": {"run_id", "snapshot", "observed_at"},
    "authorization_contracts": {
        "issuer",
        "contract",
        "approval",
        "ordinal",
        "job",
        "attempt",
        "fence",
        "consumed",
    },
    "authorization_fences": {"issuer", "job", "fence"},
    "managed_runtime_bindings": {
        "runtime_id",
        "runtime_sha256",
        "run_id",
        "binding",
        "state",
        "claim_link",
    },
    "managed_worker_incarnations": {
        "runtime_id",
        "runtime_sha256",
        "max_attempts",
        "last_sequence",
        "active_sequence",
        "state",
        "retirement",
    },
    "managed_worker_attempts": {
        "runtime_id",
        "runtime_sequence",
        "runtime_sha256",
        "run_id",
        "binding",
        "claim_link",
        "state",
        "completion",
        "native_done_sha256",
        "release_intent",
        "release_ack",
        "retirement",
        "retired_from_state",
    },
}
_RETIREMENT_FIELDS = {
    "schema",
    "runtime_id",
    "runtime_sha256",
    "admission_sha256",
    "origin",
    "runner_id",
    "enrollment_id",
    "runtime_sequence",
    "last_sequence",
    "binding",
    "attempt_receipt",
    "report_sha256",
    "retired",
    "receipt_sha256",
}
_ASSOCIATIONS = {
    "managed_persistent_attempts": "SELECT * FROM managed_persistent_attempts WHERE runtime_id=?",
    "managed_persistent_selections": "SELECT * FROM managed_persistent_selections WHERE runtime_id=?",
    "managed_runtime_bindings": "SELECT * FROM managed_runtime_bindings WHERE runtime_id=?",
    "managed_worker_attempts": "SELECT * FROM managed_worker_attempts WHERE runtime_id=?",
}


_BOOTSTRAP_HISTORY_SQL = {
    "managed_runtime_bindings": "SELECT 1 FROM managed_runtime_bindings LIMIT 1",
    "managed_worker_incarnations": "SELECT 1 FROM managed_worker_incarnations LIMIT 1",
    "managed_worker_attempts": "SELECT 1 FROM managed_worker_attempts LIMIT 1",
    "managed_persistent_incarnations": "SELECT 1 FROM managed_persistent_incarnations LIMIT 1",
    "managed_persistent_attempts": "SELECT 1 FROM managed_persistent_attempts LIMIT 1",
    "managed_persistent_selections": "SELECT 1 FROM managed_persistent_selections LIMIT 1",
}


class InspectionExpired(RuntimeError):
    """A cooperative inspection deadline was reached; no partial zero is usable."""


class _Budget:
    def __init__(self) -> None:
        self.deadline = time.monotonic() + INSPECTION_SECONDS

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise InspectionExpired

    def progress(self) -> int:
        return int(time.monotonic() >= self.deadline)


def _held(reason: str, binding: dict | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "held",
        "reason": reason,
        "complete": False,
        "binding": binding,
        "parent": None,
        "counts": None,
        "retirement_receipt_sha256": None,
        "global_holds": None,
    }


def _tables(con: sqlite3.Connection, budget: _Budget) -> set[str]:
    return {
        row[0]
        for row in audit_rows(
            con.execute("SELECT name FROM sqlite_master WHERE type='table'"), budget.check
        )
    }


def _journal_schema(con: sqlite3.Connection, tables: set[str], budget: _Budget) -> None:
    require(con.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION, "inspection_schema")
    require("runs" in tables, "inspection_schema")
    # Fixed source identifiers only; no caller-selected SQL or schema migration.
    expected = {
        "runs": _RUN_COLUMNS,
        **{name: columns for name, columns in _PERSISTENT_COLUMNS.items() if name in tables},
        **{name: columns for name, columns in _OPTIONAL_COLUMNS.items() if name in tables},
    }
    for table, columns in expected.items():
        actual = {
            row[1] for row in audit_rows(con.execute(f"PRAGMA table_info({table})"), budget.check)
        }
        require(actual == columns, "inspection_schema")
    require(con.execute("PRAGMA foreign_key_check").fetchone() is None, "inspection_associations")


def _schema(con: sqlite3.Connection, tables: set[str], budget: _Budget) -> None:
    require({"runs", *_PERSISTENT_COLUMNS} <= tables, "inspection_schema")
    _journal_schema(con, tables, budget)


def _associations(
    con: sqlite3.Connection, tables: set[str], binding: dict, budget: _Budget
) -> tuple[dict[str, int], list[str]]:
    selected: dict[str, set[str]] = {}
    for table, query in _ASSOCIATIONS.items():
        ids: set[str] = set()
        if table in tables:
            for row in audit_rows(con.execute(query, (binding["runtime_id"],)), budget.check):
                # A v3 parent never adopts a v1/v2 association with a reused ID.
                require(table in _PERSISTENT_COLUMNS, "inspection_associations")
                require(
                    all(
                        row[key] == binding[key]
                        for key in ("runtime_id", "runtime_sha256", "admission_sha256")
                    ),
                    "inspection_associations",
                )
                require(row["run_id"] not in ids, "inspection_associations")
                ids.add(row["run_id"])
        selected[table] = ids
    if "managed_worker_incarnations" in tables:
        require(
            con.execute(
                "SELECT 1 FROM managed_worker_incarnations WHERE runtime_id=?",
                (binding["runtime_id"],),
            ).fetchone()
            is None,
            "inspection_associations",
        )
    ids = set().union(*selected.values())
    runs = claims = 0
    for run_id in audit_rows(sorted(ids), budget.check):
        row = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        require(row is not None, "inspection_associations")
        Journal._record(row)  # Preserve the existing original RunRecord validation.
        runs += 1
        require("managed_claim_intents" in tables, "inspection_associations")
        claim = con.execute(
            "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
        ).fetchone()
        require(claim is not None, "inspection_associations")
        claims += 1
        link = claim_association(con, run_id)
        require(
            link is not None and all(link[key] == binding[key] for key in binding),
            "inspection_associations",
        )
    return {
        "attempts": len(selected["managed_persistent_attempts"]),
        "selections": len(selected["managed_persistent_selections"]),
        "associated_runs": runs,
        "associated_claims": claims,
    }, sorted(ids)


def _retirement(
    con: sqlite3.Connection, runtime: sqlite3.Row, admission: Any, ids: list[str], budget: _Budget
) -> str:
    receipt = fields(worker_persistent._document(runtime["retirement"]), _RETIREMENT_FIELDS)
    require(
        receipt["schema"] == "vardr.worker-retirement/3" and receipt["retired"] is True,
        "inspection_retirement",
    )
    require(
        all(
            receipt[key] == getattr(admission, key)
            for key in (
                "runtime_id",
                "runtime_sha256",
                "admission_sha256",
                "runner_id",
                "origin",
                "enrollment_id",
            )
        ),
        "inspection_retirement",
    )
    retired_last = sequence64(receipt["last_sequence"])
    unacknowledged_first_claim = False
    hash_value(receipt["report_sha256"])
    expected = digest(
        encoded({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    )
    require(hash_value(receipt["receipt_sha256"]) == expected, "inspection_retirement")
    anchored = False
    for run_id in audit_rows(ids, budget.check):
        selection = con.execute(
            "SELECT * FROM managed_persistent_selections WHERE run_id=?", (run_id,)
        ).fetchone()
        if selection["retirement"] == runtime["retirement"]:
            link = claim_association(con, run_id)
            require(link is not None, "inspection_retirement")
            assert link is not None
            snapshot = worker_persistent.retirement_snapshot(con, run_id, link, receipt)
            anchored = True
            # A lost first claim reply leaves a selection, never a local ACK/attempt.
            # The original /4 observation proves Map issued that exact claim.
            if (
                len(ids) == 1
                and runtime["last_sequence"] == 0
                and runtime["history_head"] is runtime["active_sequence"] is None
                and selection["state"] == "physical_retirement_observed"
                and selection["retired_from_state"] == "selected"
                and selection["runtime_sequence"] == 1
                and link["runtime_sequence"] == receipt["runtime_sequence"] == "1"
                and retired_last == 1
                and snapshot["claim"] is not None
                and snapshot["claim"]["consumed"] is False
                and con.execute(
                    "SELECT 1 FROM managed_persistent_attempts WHERE runtime_id=? LIMIT 1",
                    (runtime["runtime_id"],),
                ).fetchone()
                is None
            ):
                unacknowledged_first_claim = True
        elif selection["state"] == "preclaim_retired" and selection["retirement"] is None:
            observed = con.execute(
                "SELECT snapshot FROM managed_claim_observations WHERE run_id=?", (run_id,)
            ).fetchone()
            if observed is not None:
                snapshot = worker_persistent._document(observed["snapshot"], 16384)
                if snapshot.get("runtime_retirement") is not None and encoded(
                    snapshot["runtime_retirement"]
                ) == encoded(receipt):
                    worker_persistent.preclaim_parent_retirement_snapshot(con, run_id, receipt)
                    anchored = True
    require(
        anchored and (retired_last == runtime["last_sequence"] or unacknowledged_first_claim),
        "inspection_retirement",
    )
    return expected


def _selection(
    journal: str,
    identity: str,
    runner_id: str,
    runtime_id: str,
    runtime_sha256: str,
    admission_sha256: str,
) -> dict[str, str]:
    """The existing six explicit selection validators; no storage/defaults."""
    binding = {
        "runner_id": _uuid(runner_id),
        "runtime_id": _uuid(runtime_id),
        "runtime_sha256": hash_value(runtime_sha256),
        "admission_sha256": hash_value(admission_sha256),
    }
    require(
        all(
            type(value) is str and 0 < len(value) <= 4096 and "\x00" not in value
            for value in (journal, identity)
        ),
        "inspection_selection",
    )
    return binding


def _worker_snapshot(con: sqlite3.Connection, binding: dict, budget: _Budget):
    """Reuse the complete same-connection worker audit for two explicit callers."""
    tables = _tables(con, budget)
    _schema(con, tables, budget)
    runtime = worker_persistent.parent(con, binding["runtime_id"])
    admission = worker_persistent._admission(runtime["admission_snapshot"])
    require(
        all(getattr(admission, key) == value for key, value in binding.items()),
        "inspection_binding",
    )
    holds = local_holds_connection(con, checkpoint=budget.check, strict=True)
    counts, ids = _associations(con, tables, binding, budget)
    return runtime, admission, holds, counts, ids


def _audit_document(con, binding, budget, runtime, admission, holds, counts, ids):
    """Build the unchanged closed worker-state/1 document from its snapshot."""
    retired = runtime["state"] == "retired"
    retirement = _retirement(con, runtime, admission, ids, budget) if retired else None
    empty = (
        runtime["state"] == "idle"
        and runtime["last_sequence"] == 0
        and runtime["history_head"] is None
        and runtime["active_sequence"] is None
        and runtime["retirement"] is None
        and not any(counts.values())
    )
    if retired:
        require(runtime["active_sequence"] is None, "inspection_retirement")
    budget.check()
    success = holds == 0 and (retired or empty)
    return {
        "schema": SCHEMA,
        "status": ("retired" if retired else "empty_unissued") if success else "held",
        "reason": None if success else ("local_holds" if holds else "runtime_unretired"),
        "complete": True,
        "binding": binding,
        "parent": {
            "state": runtime["state"],
            "last_sequence": str(runtime["last_sequence"]),
            "head_sequence": str(runtime["history_head"])
            if runtime["history_head"] is not None
            else None,
            "active_sequence": str(runtime["active_sequence"])
            if runtime["active_sequence"] is not None
            else None,
        },
        "counts": counts,
        "retirement_receipt_sha256": retirement,
        "global_holds": holds,
    }


@contextmanager
def _read_snapshot(
    path: Path, budget: _Budget, expected_identity: tuple[int, int] | None = None
) -> Iterator[sqlite3.Connection]:
    guard = {} if expected_identity is None else {"expected_identity": expected_identity}
    with journal_connection(path, readonly=True, **guard) as con:
        con.row_factory = sqlite3.Row
        con.set_progress_handler(budget.progress, 1000)
        con.execute("BEGIN")
        try:
            yield con
        finally:
            con.rollback()


def inspect_worker_state(
    *,
    journal: str,
    identity: str,
    runner_id: str,
    runtime_id: str,
    runtime_sha256: str,
    admission_sha256: str,
    expected_journal_identity: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Inspect explicit existing state in one read-only transaction, with fixed output."""
    binding = None
    try:
        binding = _selection(
            journal, identity, runner_id, runtime_id, runtime_sha256, admission_sha256
        )
    except (AuthorizationError, TypeError, ValueError):
        return _held("selection_invalid")

    budget = _Budget()
    try:
        budget.check()
        saved_identity = read_existing(Path(identity))
        require(saved_identity.runner_id == binding["runner_id"], "inspection_identity")
        budget.check()
        with _read_snapshot(Path(journal), budget, expected_journal_identity) as con:
            snapshot = _worker_snapshot(con, binding, budget)
            return _audit_document(con, binding, budget, *snapshot)
    except InspectionExpired:
        return _held("inspection_budget_exhausted", binding)
    except IdentityError:
        return _held("identity_unavailable", binding)
    except (JournalError, OSError, sqlite3.Error):
        # Progress cancellation and busy/locked/schema errors never become partial 0.
        reason = (
            "inspection_budget_exhausted"
            if time.monotonic() >= budget.deadline
            else "journal_unavailable"
        )
        return _held(reason, binding)
    except (AuthorizationError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return _held("state_inconsistent", binding)


def _bootstrap_document(
    runner_id: str | None,
    reason: str | None,
    *,
    history: bool | None = None,
    holds: int | None = None,
) -> dict[str, Any]:
    return {
        "schema": BOOTSTRAP_SCHEMA,
        "status": "clear" if reason is None else "held",
        "reason": reason,
        "complete": history is not None and holds is not None,
        "runner_id": runner_id,
        "worker_history": history,
        "global_holds": holds,
    }


def _exists_without_following(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def inspect_worker_bootstrap(*, journal: str, identity: str, runner_id: str) -> dict[str, Any]:
    """Read current installed state before a first worker; never infer a fresh install."""
    try:
        runner_id = _uuid(runner_id)
        require(
            all(
                type(value) is str and 0 < len(value) <= 4096 and "\x00" not in value
                for value in (journal, identity)
            ),
            "bootstrap_selection",
        )
        db, selected = Path(journal), Path(identity)
        require(
            db.is_absolute()
            and selected.is_absolute()
            and db.parent == selected.parent
            and db != selected
            and ".." not in db.parts
            and ".." not in selected.parts,
            "bootstrap_selection",
        )
    except (AuthorizationError, TypeError, ValueError):
        return _bootstrap_document(None, "selection_invalid")

    budget = _Budget()
    try:
        budget.check()
        saved = read_existing(selected)
        require(saved.runner_id == runner_id, "inspection_identity")
        budget.check()
        try:
            info = db.lstat()
        except FileNotFoundError:
            sidecars = [db.with_name(db.name + suffix) for suffix in ("-wal", "-shm", "-journal")]
            require(
                not any(_exists_without_following(path) for path in sidecars), "bootstrap_sidecar"
            )
            require(
                read_existing(selected) == saved
                and not _exists_without_following(db)
                and not any(_exists_without_following(path) for path in sidecars),
                "bootstrap_changed",
            )
            budget.check()
            return _bootstrap_document(runner_id, "journal_not_initialized")
        original_identity = (info.st_dev, info.st_ino)
        with _read_snapshot(db, budget, original_identity) as con:
            tables = _tables(con, budget)
            _journal_schema(con, tables, budget)
            require(
                not any(
                    table.startswith(("managed_worker_", "managed_runtime_", "managed_persistent_"))
                    for table in tables - _BOOTSTRAP_HISTORY_SQL.keys()
                ),
                "bootstrap_history_schema",
            )
            holds = local_holds_connection(con, checkpoint=budget.check, strict=True)
            # Identifiers are from this fixed source allowlist, never CLI inputs.
            history = any(
                con.execute(_BOOTSTRAP_HISTORY_SQL[table]).fetchone() is not None
                for table in sorted(_BOOTSTRAP_HISTORY_SQL.keys() & tables)
            )
            require(read_existing(selected) == saved, "bootstrap_identity_changed")
            budget.check()
        reason = "worker_history_present" if history else "local_holds" if holds else None
        return _bootstrap_document(runner_id, reason, history=history, holds=holds)
    except InspectionExpired:
        return _bootstrap_document(runner_id, "inspection_budget_exhausted")
    except IdentityError:
        return _bootstrap_document(runner_id, "identity_unavailable")
    except (JournalError, OSError, sqlite3.Error):
        reason = (
            "inspection_budget_exhausted"
            if time.monotonic() >= budget.deadline
            else "journal_unavailable"
        )
        return _bootstrap_document(runner_id, reason)
    except (AuthorizationError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return _bootstrap_document(runner_id, "state_inconsistent")
