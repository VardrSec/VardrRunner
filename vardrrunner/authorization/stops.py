"""Explicit owned stop receipts, sourced only from confirmed native stop decisions."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable

from vardrrunner.journal import Journal, Phase, utc_now

from .codec import AuthorizationError, digest, encoded, fields, integer, require
from .results import BINDING

CANCEL_CAUSES = frozenset({"local_emergency_stop", "remote_stop_requested"})
FAIL_CAUSES = frozenset(
    {
        "control_cap_unavailable",
        "control_lease_expired",
        "authorization_deadline",
        "tool_timeout",
        "descendants_after_tool_exit",
    }
)
CAUSES = CANCEL_CAUSES | FAIL_CAUSES


def stop_hash(binding: dict, outcome: str, cause: str) -> str:
    return digest(
        encoded(
            {
                "schema": "vardr.managed-stop/1",
                **binding,
                "outcome": outcome,
                "cause": cause,
                "termination_confirmed": True,
            }
        )
    )


class StopStore:
    def __init__(self, journal: Journal):
        self.journal = journal
        with journal._connection() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS managed_stop_intents (
                run_id TEXT PRIMARY KEY, binding TEXT NOT NULL, outcome TEXT NOT NULL,
                cause TEXT NOT NULL, receipt_sha256 TEXT NOT NULL, state TEXT NOT NULL,
                observed_pid INTEGER)""")

    def get(self, run_id: str) -> dict:
        with self.journal._connection() as con:
            row = con.execute(
                "SELECT * FROM managed_stop_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            require(row is not None, "managed_stop_intent_missing")
            claim = con.execute(
                "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        result = dict(row)
        binding = fields(json.loads(result["binding"]), BINDING)
        integer(binding["fence"], 1)
        require(
            claim is not None
            and run is not None
            and (claim["contract"], claim["attempt"], claim["fence"])
            == (binding["contract_id"], binding["attempt_id"], binding["fence"])
            and (run["backend_url"], run["job_id"]) == (binding["origin"], binding["job_id"])
            and claim["consumption_acknowledged"] == 1
            and run["pid"] == result["observed_pid"]
            and result["cause"] in CAUSES
            and result["outcome"] == ("cancelled" if result["cause"] in CANCEL_CAUSES else "failed")
            and result["receipt_sha256"] == stop_hash(binding, result["outcome"], result["cause"]),
            "managed_stop_intent_binding",
        )
        return result

    def reserve(self, handle, binding: dict, outcome: str, cause: str) -> dict:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            claim = con.execute(
                "SELECT * FROM managed_claim_intents WHERE run_id=?", (handle.run_id,)
            ).fetchone()
            run = con.execute("SELECT * FROM runs WHERE run_id=?", (handle.run_id,)).fetchone()
            require(
                claim is not None
                and claim["owner"] == handle._owner
                and claim["consumption_acknowledged"] == 1
                and (claim["contract"], claim["attempt"], claim["fence"])
                == (binding["contract_id"], binding["attempt_id"], binding["fence"]),
                "managed_stop_not_owned",
            )
            require(
                run is not None
                and run["phase"] == Phase.EXECUTING.value
                and run["artifact_sha256"] is None
                and (run["backend_url"], run["job_id"]) == (binding["origin"], binding["job_id"]),
                "managed_stop_not_confirmed",
            )
            try:
                con.execute(
                    "INSERT INTO managed_stop_intents (run_id,binding,outcome,cause,receipt_sha256,state,observed_pid) VALUES (?,?,?,?,?,'stop_in_flight',?)",
                    (
                        handle.run_id,
                        encoded(binding).decode(),
                        outcome,
                        cause,
                        stop_hash(binding, outcome, cause),
                        run["pid"],
                    ),
                )
            except sqlite3.IntegrityError:
                raise AuthorizationError("managed_stop_already_attempted") from None
            con.execute(
                "UPDATE runs SET phase=?,last_event='managed_stop_send',updated_at=? WHERE run_id=?",
                (Phase.FINALIZING.value, utc_now(), handle.run_id),
            )
        return self.get(handle.run_id)

    def close(self, run_id: str, expected: dict) -> None:
        binding = json.loads(expected["binding"])
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT * FROM managed_stop_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            claim = con.execute(
                "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            require(
                row is not None
                and all(
                    row[k] == expected[k]
                    for k in ("binding", "outcome", "cause", "receipt_sha256", "observed_pid")
                )
                and claim is not None
                and (claim["contract"], claim["attempt"], claim["fence"])
                == (binding["contract_id"], binding["attempt_id"], binding["fence"])
                and run is not None
                and run["pid"] == expected["observed_pid"],
                "managed_stop_changed",
            )
            count = con.execute(
                "UPDATE authorization_contracts SET consumed=2 WHERE issuer=? AND contract=? AND attempt=? AND fence=? AND consumed IN (1,2)",
                (claim["issuer"], claim["contract"], claim["attempt"], claim["fence"]),
            ).rowcount
            require(count == 1, "managed_stop_not_owned")
            con.execute(
                "UPDATE managed_stop_intents SET state='terminal' WHERE run_id=?", (run_id,)
            )
            con.execute(
                "UPDATE runs SET phase=?,status=?,failure_reason=?,completed_at=?,last_event='managed_stop_receipt',updated_at=? WHERE run_id=?",
                (
                    Phase.STOP_WORK.value
                    if expected["outcome"] == "cancelled"
                    else Phase.FAILED.value,
                    expected["outcome"],
                    expected["cause"],
                    utc_now(),
                    utc_now(),
                    run_id,
                ),
            )


def check_receipt(reply: dict, expected: dict) -> None:
    binding = json.loads(expected["binding"])
    fields(reply, BINDING | {"schema", "outcome", "cause", "receipt_sha256", "capacity_reserved"})
    integer(reply["fence"], 1)
    require(
        reply
        == {
            "schema": "vardr.managed-stop-receipt/1",
            **binding,
            "outcome": expected["outcome"],
            "cause": expected["cause"],
            "receipt_sha256": expected["receipt_sha256"],
            "capacity_reserved": False,
        }
        and reply["capacity_reserved"] is False,
        "managed_stop_receipt_binding",
    )


def report(handle, send: Callable[[dict], dict]) -> None:
    require(
        handle._confirmed_stop is not None and handle._returned_artifact is None,
        "known_native_stop_required",
    )
    outcome, cause = handle._confirmed_stop
    binding = {k: handle.gate.binding[k] for k in BINDING - {"contract_sha256"}}
    binding["contract_sha256"] = digest(encoded(handle.gate.envelope))
    store = StopStore(handle.store.journal)
    expected = store.reserve(handle, binding, outcome, cause)
    try:
        reply = send(
            {
                **handle.gate.request,
                "contract_sha256": binding["contract_sha256"],
                "outcome": outcome,
                "cause": cause,
                "termination_confirmed": True,
            }
        )
    except Exception:
        raise AuthorizationError("managed_stop_outcome_unknown") from None
    check_receipt(reply, expected)
    store.close(handle.run_id, expected)


def reconcile(journal: Journal, run_id: str, inspect: Callable[[dict], dict]) -> str:
    store = StopStore(journal)
    expected = store.get(run_id)
    binding = json.loads(expected["binding"])
    try:
        reply = inspect({k: binding[k] for k in BINDING - {"job_id"}})
    except Exception:
        raise AuthorizationError("managed_stop_observation_unavailable") from None
    fields(reply, BINDING | {"schema", "consumed", "capacity_reserved", "execution_state", "stop"})
    integer(reply["fence"], 1)
    require(
        reply["schema"] == "vardr.managed-stop-observation/1"
        and all(reply[k] == v for k, v in binding.items())
        and reply["consumed"] is True
        and type(reply["capacity_reserved"]) is bool
        and type(reply["execution_state"]) is str
        and reply["execution_state"]
        in {"active", "uncertain", "cancel_requested", "completed", "failed", "cancelled"},
        "managed_stop_observation_binding",
    )
    if reply["stop"] is None:
        require(expected["state"] != "terminal", "terminal_stop_receipt_missing")
        return "held_no_stop_receipt"
    check_receipt(reply["stop"], expected)
    require(
        reply["execution_state"] == expected["outcome"] and reply["capacity_reserved"] is False,
        "managed_stop_observation_binding",
    )
    store.close(run_id, expected)
    return "terminal_stop_receipt_observed"
