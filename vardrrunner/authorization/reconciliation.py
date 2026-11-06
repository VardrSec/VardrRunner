"""Explicit local metadata retirement; never constructs execution capabilities."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable

from vardrrunner.journal import TERMINAL_PHASES, Journal, Phase, utc_now

from . import observations, results, stops
from .codec import AuthorizationError, encoded, require
from .worker_binding import (
    claim_association,
    retire_incarnation_observation,
    sequence_holds,
)

_ROW_SQL = {
    "runs": "SELECT * FROM runs WHERE run_id=?",
    "managed_claim_intents": "SELECT * FROM managed_claim_intents WHERE run_id=?",
    "managed_result_intents": "SELECT * FROM managed_result_intents WHERE run_id=?",
    "managed_stop_intents": "SELECT * FROM managed_stop_intents WHERE run_id=?",
    "managed_claim_observations": "SELECT * FROM managed_claim_observations WHERE run_id=?",
}
_INTENT_ROWS_SQL = {
    "managed_result_intents": "SELECT * FROM managed_result_intents",
    "managed_stop_intents": "SELECT * FROM managed_stop_intents",
}
_RETIRE_SQL = {
    "managed_result_intents": "UPDATE managed_result_intents SET state=? WHERE run_id=?",
    "managed_stop_intents": "UPDATE managed_stop_intents SET state=? WHERE run_id=?",
}


def _table(con, name: str) -> bool:
    return (
        con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
        is not None
    )


def _row(con, table: str, run_id: str):
    if not _table(con, table):
        return None
    return con.execute(_ROW_SQL[table], (run_id,)).fetchone()


def retire_preclaim(journal: Journal, run_id: str) -> str:
    """Only the durable marker written before invoking any claim RPC qualifies."""
    with journal._connection() as con:
        con.execute("BEGIN IMMEDIATE")
        claim = _row(con, "managed_claim_intents", run_id)
        run = _row(con, "runs", run_id)
        require(
            claim is not None
            and run is not None
            and claim["state"] in {"denied_before_rpc", "preclaim_retired"}
            and all(claim[key] is None for key in ("issuer", "contract", "attempt", "fence"))
            and claim["consumption_sent"] == claim["consumption_acknowledged"] == 0
            and (claim["backend"], claim["job"]) == (run["backend_url"], run["job_id"])
            and run["pid"] is None
            and run["artifact_sha256"] is None,
            "preclaim_retirement_not_proven",
        )
        require(
            _row(con, "managed_result_intents", run_id) is None
            and _row(con, "managed_stop_intents", run_id) is None,
            "preclaim_retirement_not_proven",
        )
        if _table(con, "authorization_contracts"):
            require(
                con.execute(
                    "SELECT 1 FROM authorization_contracts WHERE job=? AND consumed=1",
                    (run["job_id"],),
                ).fetchone()
                is None,
                "preclaim_retirement_active_ledger",
            )
        if claim["state"] == "preclaim_retired":
            require(
                run["phase"] == Phase.FAILED.value
                and run["failure_reason"] == "local_preclaim_denied_before_rpc",
                "preclaim_retirement_changed",
            )
            return "local_preclaim_retired"
        require(Phase(run["phase"]) not in TERMINAL_PHASES, "preclaim_retirement_changed")
        con.execute(
            "UPDATE managed_claim_intents SET state='preclaim_retired' WHERE run_id=?",
            (run_id,),
        )
        instant = utc_now()
        con.execute(
            "UPDATE runs SET phase=?,status='not_claimed',failure_reason='local_preclaim_denied_before_rpc',completed_at=?,last_event='managed_preclaim_retired',updated_at=? WHERE run_id=?",
            (Phase.FAILED.value, instant, instant, run_id),
        )
    return "local_preclaim_retired"


def retire_reserve_conflict(journal, run_id, invocation, origin, job_id):
    """Source-only cleanup immediately after the specific pre-RPC unique conflict."""
    with journal._connection() as con:
        con.execute("BEGIN IMMEDIATE")
        run = _row(con, "runs", run_id)
        previous = con.execute(
            "SELECT * FROM managed_claim_intents WHERE backend=? AND job=?", (origin, job_id)
        ).fetchone()
        require(
            run is not None
            and previous is not None
            and previous["run_id"] != run_id
            and _row(con, "managed_claim_intents", run_id) is None
            and run["phase"] == Phase.DISCOVERED.value
            and (run["backend_url"], run["job_id"]) == (origin, job_id)
            and json.loads(run["command_profile"]).get("managed_invocation") == invocation
            and run["pid"] is None
            and run["artifact_sha256"] is None
            and _row(con, "managed_result_intents", run_id) is None
            and _row(con, "managed_stop_intents", run_id) is None,
            "reserve_conflict_retirement_not_proven",
        )
        old_run = _row(con, "runs", previous["run_id"])
        require(
            old_run is not None and Phase(old_run["phase"]) in TERMINAL_PHASES,
            "reserve_conflict_retirement_not_proven",
        )
        if _table(con, "authorization_contracts"):
            require(
                con.execute(
                    "SELECT 1 FROM authorization_contracts WHERE job=? AND consumed=1", (job_id,)
                ).fetchone()
                is None,
                "reserve_conflict_retirement_active_ledger",
            )
        instant = utc_now()
        con.execute(
            "UPDATE runs SET phase=?,status='not_claimed',failure_reason='local_claim_tombstone_exists',completed_at=?,last_event='managed_duplicate_claim_retired',updated_at=? WHERE run_id=?",
            (Phase.FAILED.value, instant, instant, run_id),
        )


def _host_exit(reply: dict) -> bool:
    stop = reply["stop"]
    return (
        type(stop) is dict
        and stop.get("cause") == "observed_exit"
        and stop.get("outcome") == "failed"
        and reply["execution_state"] == "failed"
        and reply["capacity_reserved"] is False
        and reply["result"] is None
        and reply["completion"] is None
    )


def _failed_completion(reply: dict) -> bool:
    return (
        type(reply["completion"]) is dict
        and reply["completion"].get("outcome") == "failed"
        and type(reply["result"]) is dict
        and reply["stop"] is None
        and reply["claim"]["consumed"] is True
        and reply["execution_state"] == "failed"
        and reply["capacity_reserved"] is False
    )


def _unbound_runtime(reply: dict) -> bool:
    return type(reply.get("runtime_retirement")) is dict and reply["claim"] is None


def _sequence_retirement_metadata(con, run_id: str, reply: dict) -> None:
    """Keep physical retirement separate from DONE/release acknowledgements."""
    if (
        reply["schema"]
        not in {"vardr.managed-claim-observation/3", "vardr.managed-claim-observation/4"}
        or reply["runtime_retirement"] is None
    ):
        return
    require(con.in_transaction, "worker_retirement_transaction_required")
    claim = _row(con, "managed_claim_intents", run_id)
    run = _row(con, "runs", run_id)
    observed = _row(con, "managed_claim_observations", run_id)
    require(
        claim is not None
        and run is not None
        and observed is not None
        and observed["snapshot"] == encoded(reply).decode()
        and run["pid"] is None
        and Phase(run["phase"]) in TERMINAL_PHASES,
        "worker_retirement_source_changed",
    )
    association = claim_association(con, run_id)
    require(
        association is not None
        and association["schema"]
        in {"vardr.worker-claim-association/2", "vardr.worker-claim-association/3"},
        "worker_retirement_source_changed",
    )
    assert association is not None
    root = {
        "origin": run["backend_url"],
        "job_id": run["job_id"],
        "runner_id": association["runner_id"],
        **{key: claim[key] for key in ("plan_sha256", "case_sha256", "association_sha256")},
    }
    observations.validate(reply, root, dict(claim), association)
    retire_incarnation_observation(con, run_id, reply["runtime_retirement"])


def _unbound_source(con, run, claim, reply):
    """A retired exact incarnation fences late claims; absence alone never does."""
    association = claim_association(con, run["run_id"])
    require(
        association is not None
        and _unbound_runtime(reply)
        and claim["state"]
        in {
            "claim_in_flight",
            "claim_unknown",
            "reply_or_binding_unknown",
            "runtime_unbound_retired",
        }
        and all(
            claim[key] is None
            for key in (
                "issuer",
                "contract",
                "attempt",
                "fence",
                "approval_sha256",
                "authority_sha256",
            )
        )
        and claim["consumption_sent"] == claim["consumption_acknowledged"] == 0
        and run["pid"] is None
        and all(run[key] is None for key in ("artifact_path", "artifact_sha256", "artifact_size"))
        and run["upload_state"] == "not_started"
        and _row(con, "managed_result_intents", run["run_id"]) is None
        and _row(con, "managed_stop_intents", run["run_id"]) is None,
        "unbound_retirement_source_changed",
    )
    if _table(con, "authorization_contracts"):
        require(
            con.execute(
                "SELECT 1 FROM authorization_contracts WHERE job=?", (claim["job"],)
            ).fetchone()
            is None,
            "unbound_retirement_ledger_conflict",
        )
    return association


def _retire_unbound_runtime(journal, run_id, root, source, before, reply):
    with journal._connection() as con:
        con.execute("BEGIN IMMEDIATE")
        claim = _row(con, "managed_claim_intents", run_id)
        run = _row(con, "runs", run_id)
        observed = _row(con, "managed_claim_observations", run_id)
        require(
            claim is not None
            and run is not None
            and dict(claim) == source
            and journal._record(run) == before
            and observed is not None
            and observed["snapshot"] == encoded(reply).decode(),
            "unbound_retirement_source_changed",
        )
        association = _unbound_source(con, run, claim, reply)
        observations.validate(reply, root, dict(claim), association)
        closed = claim["state"] == "runtime_unbound_retired"
        require(
            (
                closed
                and run["phase"] == Phase.FAILED.value
                and run["status"] == "not_claimed"
                and run["failure_reason"] == "not_claimed_by_retired_runtime"
                and run["last_event"] == "managed_runtime_unbound_receipt"
            )
            or (not closed and Phase(run["phase"]) not in TERMINAL_PHASES),
            "unbound_retirement_foreign_terminal",
        )
        warning = {
            "code": "runtime_unbound_retirement",
            "runtime_id": association["runtime_id"],
            "receipt_sha256": reply["runtime_retirement"]["receipt_sha256"],
        }
        warnings = json.loads(run["warnings_json"])
        require(type(warnings) is list, "unbound_retirement_audit_state")
        if closed:
            require(warning in warnings, "unbound_retirement_audit_state")
        else:
            warnings.append(warning)
        con.execute(
            "UPDATE managed_claim_intents SET state='runtime_unbound_retired' WHERE run_id=?",
            (run_id,),
        )
        instant = utc_now()
        con.execute(
            "UPDATE runs SET phase=?,status='not_claimed',failure_reason='not_claimed_by_retired_runtime',completed_at=?,last_event='managed_runtime_unbound_receipt',warnings_json=?,updated_at=? WHERE run_id=?",
            (
                Phase.FAILED.value,
                run["completed_at"] or instant,
                encoded(warnings).decode(),
                instant,
                run_id,
            ),
        )
        _sequence_retirement_metadata(con, run_id, reply)
    return "terminal_runtime_unbound_retired"


def _original_result(con, run, claim, reply) -> None:
    """A different server outcome never rewrites the original upload intent."""
    intent = _row(con, "managed_result_intents", run["run_id"])
    require(
        intent is not None
        and intent["outcome"] == "completed"
        and json.loads(intent["binding"]) == observations.binding(reply)
        and intent["case_sha256"] == claim["case_sha256"]
        and (run["artifact_sha256"], run["artifact_size"])
        == (intent["artifact_sha256"], intent["artifact_size"])
        and type(intent["artifact_size"]) is int
        and intent["artifact_size"] > 0
        and claim["consumption_sent"] == 1,
        "failed_completion_original_artifact_required",
    )
    results.check_result(reply["result"], dict(intent))
    results.check_completion(reply["completion"], {**dict(intent), "outcome": "failed"})


def _native_closed(table, intent, claim, run, contracts) -> bool:
    binding = json.loads(intent["binding"])
    require(set(binding) == results.BINDING, "local_terminal_binding")
    if (
        (
            binding["origin"],
            binding["job_id"],
            binding["contract_id"],
            binding["attempt_id"],
            binding["fence"],
        )
        != (claim["backend"], claim["job"], claim["contract"], claim["attempt"], claim["fence"])
        or claim["consumption_acknowledged"] != 1
        or not any(
            row["issuer"] == claim["issuer"]
            and row["contract"] == claim["contract"]
            and (row["job"], row["attempt"], row["fence"])
            == (claim["job"], claim["attempt"], claim["fence"])
            and row["consumed"] == 2
            for row in contracts
        )
    ):
        return False
    if table == "managed_result_intents":
        return (
            intent["outcome"] in {"completed", "failed"}
            and intent["case_sha256"] == claim["case_sha256"]
            and intent["receipt_sha256"]
            == results.receipt(binding, intent["artifact_sha256"], intent["case_sha256"])
            and (run["artifact_sha256"], run["artifact_size"])
            == (intent["artifact_sha256"], intent["artifact_size"])
            and run["pid"] is None
            and run["phase"]
            == (Phase.DONE.value if intent["outcome"] == "completed" else Phase.FAILED.value)
            and run["last_event"] == "managed_completion_receipt"
        )
    return (
        intent["cause"] in stops.CAUSES
        and intent["outcome"]
        == ("cancelled" if intent["cause"] in stops.CANCEL_CAUSES else "failed")
        and intent["receipt_sha256"] == stops.stop_hash(binding, intent["outcome"], intent["cause"])
        and run["phase"]
        == (Phase.STOP_WORK.value if intent["outcome"] == "cancelled" else Phase.FAILED.value)
        and run["pid"] == intent["observed_pid"]
        and run["failure_reason"] == intent["cause"]
        and run["last_event"] == "managed_stop_receipt"
    )


def _retire_observed_terminal(journal, run_id, root, source, before, reply):
    failed_result = _failed_completion(reply)
    require(_host_exit(reply) or failed_result, "host_retirement_receipt_required")
    state = "failed_completion_observed" if failed_result else "host_exit_observed"
    reason = "observed_failed_completion" if failed_result else "observed_exit"
    event = "managed_failed_completion_receipt" if failed_result else "managed_host_exit_receipt"
    warning = "server_failed_completion" if failed_result else "host_observed_exit"
    retired = "server_retired" if failed_result else "host_retired"
    with journal._connection() as con:
        con.execute("BEGIN IMMEDIATE")
        claim = _row(con, "managed_claim_intents", run_id)
        run = _row(con, "runs", run_id)
        observed = _row(con, "managed_claim_observations", run_id)
        require(
            claim is not None
            and run is not None
            and dict(claim) == source
            and journal._record(run) == before
            and observed is not None
            and observed["snapshot"] == encoded(reply).decode(),
            "host_retirement_source_changed",
        )
        observations.validate(reply, root, dict(claim), claim_association(con, run_id))
        if failed_result:
            _original_result(con, run, claim, reply)
        require(
            claim["consumption_sent"] in (0, 1)
            and claim["consumption_acknowledged"] in (0, 1)
            and claim["consumption_acknowledged"] <= claim["consumption_sent"],
            "host_retirement_source_changed",
        )
        require(
            run["pid"] is None or (type(run["pid"]) is int and run["pid"] > 0),
            "host_retirement_source_changed",
        )
        if Phase(run["phase"]) in TERMINAL_PHASES:
            require(
                claim["state"] == state
                and run["phase"] == Phase.FAILED.value
                and run["failure_reason"] == reason
                and run["pid"] is None,
                "host_retirement_foreign_terminal",
            )
        for table in ("managed_result_intents", "managed_stop_intents"):
            intent = _row(con, table, run_id)
            if intent is not None:
                require(intent["state"] != "terminal", "host_retirement_native_conflict")
                con.execute(_RETIRE_SQL[table], (retired, run_id))
        ledger = None
        if claim["contract"] is not None and _table(con, "authorization_contracts"):
            ledger = con.execute(
                "SELECT * FROM authorization_contracts WHERE issuer=? AND contract=?",
                (claim["issuer"], claim["contract"]),
            ).fetchone()
            if ledger is not None:
                require(
                    (ledger["job"], ledger["attempt"], ledger["fence"])
                    == (claim["job"], claim["attempt"], claim["fence"])
                    and ledger["consumed"] in (0, 1, 2),
                    "host_retirement_ledger_binding",
                )
                con.execute(
                    "UPDATE authorization_contracts SET consumed=2 WHERE issuer=? AND contract=?",
                    (claim["issuer"], claim["contract"]),
                )
        require(
            not claim["consumption_sent"] or ledger is not None,
            "host_retirement_ledger_missing",
        )
        warnings = json.loads(run["warnings_json"])
        require(type(warnings) is list, "host_retirement_audit_state")
        receipt = reply["result" if failed_result else "stop"]["receipt_sha256"]
        if claim["state"] != state:
            warnings.append(
                {
                    "code": warning,
                    "receipt_sha256": receipt,
                    "previous_pid": run["pid"],
                }
            )
        else:
            require(
                any(
                    type(row) is dict
                    and row.get("code") == warning
                    and row.get("receipt_sha256") == receipt
                    for row in warnings
                ),
                "host_retirement_audit_state",
            )
        con.execute("UPDATE managed_claim_intents SET state=? WHERE run_id=?", (state, run_id))
        instant = utc_now()
        con.execute(
            "UPDATE runs SET phase=?,pid=NULL,status='failed',failure_reason=?,completed_at=?,last_event=?,warnings_json=?,updated_at=? WHERE run_id=?",
            (
                Phase.FAILED.value,
                reason,
                run["completed_at"] or instant,
                event,
                encoded(warnings).decode(),
                instant,
                run_id,
            ),
        )
        _sequence_retirement_metadata(con, run_id, reply)
    return "terminal_" + state


def reconcile_managed(
    journal: Journal, run_id: str, runner_id: str, inspect: Callable[[dict], dict]
) -> str:
    root, source = observations.original(journal, run_id, runner_id)
    before = journal.get(run_id)
    if source["state"] in {"denied_before_rpc", "preclaim_retired"}:
        status = retire_preclaim(journal, run_id)
        with journal._connection() as con:
            association = claim_association(con, run_id)
            selection = (
                con.execute(
                    "SELECT * FROM managed_persistent_selections WHERE run_id=?", (run_id,)
                ).fetchone()
                if association is not None
                and association["schema"] == "vardr.worker-claim-association/3"
                else None
            )
        if selection is None or selection["state"] == "preclaim_retired":
            return status
        require(
            selection["state"] == "selected"
            or (
                selection["state"] == "physical_retirement_observed"
                and selection["retired_from_state"] == "selected"
            ),
            "worker_selection_preclaim_conflict",
        )
        # A restart cannot recover the caller's lost "epoch never entered"
        # knowledge. Only a new original-key physical observation closes it.
        root, source = observations.original(journal, run_id, runner_id)
        before = journal.get(run_id)
        reply = observations.observe(journal, run_id, runner_id, inspect)
        if reply["runtime_retirement"] is None:
            return "held_no_retirement_receipt"
        with journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            claim = _row(con, "managed_claim_intents", run_id)
            run = _row(con, "runs", run_id)
            observed = _row(con, "managed_claim_observations", run_id)
            require(
                claim is not None
                and run is not None
                and dict(claim) == source
                and journal._record(run) == before
                and observed is not None
                and observed["snapshot"] == encoded(reply).decode(),
                "worker_selection_source_changed",
            )
            _sequence_retirement_metadata(con, run_id, reply)
        return "terminal_runtime_preclaim_retired"
    reply = observations.observe(journal, run_id, runner_id, inspect)
    if _unbound_runtime(reply):
        return _retire_unbound_runtime(journal, run_id, root, source, before, reply)
    if _host_exit(reply):
        return _retire_observed_terminal(journal, run_id, root, source, before, reply)
    if reply["stop"] is not None:
        status = observations.reconcile_stop(journal, run_id, runner_id, lambda _: reply)
    elif reply["result"] is not None:
        if (
            _failed_completion(reply)
            and results.ResultStore(journal).get(run_id)["outcome"] == "completed"
        ):
            return _retire_observed_terminal(journal, run_id, root, source, before, reply)
        status = observations.reconcile_result(journal, run_id, runner_id, lambda _: reply)
    else:
        return "held_no_terminal_receipt"
    if (
        status.startswith("terminal_")
        and reply["schema"]
        in {"vardr.managed-claim-observation/3", "vardr.managed-claim-observation/4"}
        and reply["runtime_retirement"] is not None
    ):
        with journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            _sequence_retirement_metadata(con, run_id, reply)
    return status


def local_holds(journal: Journal) -> int:
    """A conservative snapshot, never permission to execute or clear a fence."""
    holds: set[tuple] = {("run", run.run_id) for run in journal.unfinished()}
    with journal._connection() as con:
        claims = (
            con.execute("SELECT * FROM managed_claim_intents").fetchall()
            if _table(con, "managed_claim_intents")
            else []
        )
        contracts = (
            con.execute("SELECT * FROM authorization_contracts").fetchall()
            if _table(con, "authorization_contracts")
            else []
        )
        for row in contracts:
            if row["consumed"] not in (0, 2):
                holds.add(("ledger", row["issuer"], row["contract"]))
        for claim in claims:
            run = _row(con, "runs", claim["run_id"])
            if run is None or Phase(run["phase"]) not in TERMINAL_PHASES:
                holds.add(("run", claim["run_id"]))
                continue
            state = claim["state"]
            if state == "preclaim_retired":
                valid = (
                    run["failure_reason"] == "local_preclaim_denied_before_rpc"
                    and run["phase"] == Phase.FAILED.value
                    and run["pid"] is None
                    and (claim["backend"], claim["job"]) == (run["backend_url"], run["job_id"])
                    and all(
                        claim[key] is None for key in ("issuer", "contract", "attempt", "fence")
                    )
                    and claim["consumption_sent"] == claim["consumption_acknowledged"] == 0
                )
            elif state == "runtime_unbound_retired":
                observed = _row(con, "managed_claim_observations", claim["run_id"])
                valid = observed is not None
                if valid:
                    snapshot = json.loads(observed["snapshot"])
                    root = {
                        "origin": claim["backend"],
                        "job_id": claim["job"],
                        "runner_id": snapshot["runner_id"],
                        **{
                            key: claim[key]
                            for key in ("plan_sha256", "case_sha256", "association_sha256")
                        },
                    }
                    try:
                        association = _unbound_source(con, run, claim, snapshot)
                        observations.validate(snapshot, root, dict(claim), association)
                        valid = (
                            run["phase"] == Phase.FAILED.value
                            and run["status"] == "not_claimed"
                            and run["failure_reason"] == "not_claimed_by_retired_runtime"
                            and run["last_event"] == "managed_runtime_unbound_receipt"
                            and {
                                "code": "runtime_unbound_retirement",
                                "runtime_id": association["runtime_id"],
                                "receipt_sha256": snapshot["runtime_retirement"]["receipt_sha256"],
                            }
                            in json.loads(run["warnings_json"])
                        )
                    except AuthorizationError:
                        valid = False
            elif state in {"host_exit_observed", "failed_completion_observed"}:
                failed_result = state == "failed_completion_observed"
                reason = "observed_failed_completion" if failed_result else "observed_exit"
                event = (
                    "managed_failed_completion_receipt"
                    if failed_result
                    else "managed_host_exit_receipt"
                )
                warning = "server_failed_completion" if failed_result else "host_observed_exit"
                retired = "server_retired" if failed_result else "host_retired"
                observed = _row(con, "managed_claim_observations", claim["run_id"])
                valid = (
                    observed is not None and run["failure_reason"] == reason and run["pid"] is None
                )
                if valid:
                    snapshot = json.loads(observed["snapshot"])
                    root = {
                        "origin": claim["backend"],
                        "job_id": claim["job"],
                        "runner_id": snapshot["runner_id"],
                        **{
                            key: claim[key]
                            for key in ("plan_sha256", "case_sha256", "association_sha256")
                        },
                    }
                    try:
                        observations.validate(
                            snapshot, root, dict(claim), claim_association(con, claim["run_id"])
                        )
                        if failed_result:
                            _original_result(con, run, claim, snapshot)
                        valid = (
                            (
                                _failed_completion(snapshot)
                                if failed_result
                                else _host_exit(snapshot)
                            )
                            and (run["backend_url"], run["job_id"])
                            == (claim["backend"], claim["job"])
                            and run["phase"] == Phase.FAILED.value
                            and run["last_event"] == event
                            and any(
                                type(row) is dict
                                and row.get("code") == warning
                                and row.get("receipt_sha256")
                                == snapshot["result" if failed_result else "stop"]["receipt_sha256"]
                                for row in json.loads(run["warnings_json"])
                            )
                            and all(
                                (intent := _row(con, table, claim["run_id"])) is None
                                or intent["state"] == retired
                                for table in ("managed_result_intents", "managed_stop_intents")
                            )
                            and (
                                not claim["consumption_sent"]
                                or any(
                                    row["issuer"] == claim["issuer"]
                                    and row["contract"] == claim["contract"]
                                    and row["consumed"] == 2
                                    for row in contracts
                                )
                            )
                        )
                    except AuthorizationError:
                        valid = False
            else:
                valid = False
                for table in ("managed_result_intents", "managed_stop_intents"):
                    intent = _row(con, table, claim["run_id"])
                    if intent is not None and intent["state"] == "terminal":
                        valid = _native_closed(table, intent, claim, run, contracts)
                        if valid:
                            break
            if not valid:
                holds.add(("run", claim["run_id"]))
        for table in ("managed_result_intents", "managed_stop_intents"):
            if _table(con, table):
                for intent in con.execute(_INTENT_ROWS_SQL[table]):
                    if not any(row["run_id"] == intent["run_id"] for row in claims):
                        holds.add(("intent", intent["run_id"]))
        fences = (
            con.execute("SELECT * FROM authorization_fences").fetchall()
            if _table(con, "authorization_fences")
            else []
        )
        for row in contracts:
            if not any(
                fence["issuer"] == row["issuer"]
                and fence["job"] == row["job"]
                and fence["fence"] >= row["fence"]
                for fence in fences
            ):
                holds.add(("fence", row["issuer"], row["job"]))
        for fence in fences:
            if (
                type(fence["fence"]) is not int
                or fence["fence"] < 1
                or any(
                    row["issuer"] == fence["issuer"]
                    and row["job"] == fence["job"]
                    and row["fence"] > fence["fence"]
                    for row in contracts
                )
            ):
                holds.add(("fence", fence["issuer"], fence["job"]))
        try:
            pending_sequences = sequence_holds(con)
        except (AuthorizationError, sqlite3.Error):
            holds.add(("sequence", "inconsistent_audit_state"))
            pending_sequences = 0
        from .worker_persistent import persistent_holds

        try:
            pending_persistent = persistent_holds(con, full=True)
        except (AuthorizationError, sqlite3.Error):
            holds.add(("persistent", "inconsistent_audit_state"))
            pending_persistent = 0
    return len(holds) + pending_sequences + pending_persistent
