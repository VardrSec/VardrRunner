"""Capability-free authenticated receipt observation; never resumes managed work."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable

from vardrrunner.journal import Journal, utc_now

from . import results, stops
from .codec import AuthorizationError, encoded, fields, identifier, integer, require

ROOT = {"origin", "job_id", "runner_id", "plan_sha256", "case_sha256", "association_sha256"}
CLAIM = {
    "contract_id",
    "attempt_id",
    "fence",
    "contract_sha256",
    "consumed",
    "authority_revision",
    "authority_sha256",
}
STATES = {"active", "cancel_requested", "uncertain", "completed", "failed", "cancelled"}


def hash_value(value) -> str:
    require(
        type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value),
        "invalid_observation_hash",
    )
    return value


def original(journal: Journal, run_id: str, runner_id: str) -> tuple[dict, dict]:
    try:
        identifier(runner_id)
    except AuthorizationError:
        raise AuthorizationError("original_runner_required") from None
    try:
        with journal._connection() as con:
            row = con.execute(
                "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    except sqlite3.Error:
        raise AuthorizationError("claim_observation_state_unavailable") from None
    require(
        row is not None
        and run is not None
        and (row["backend"], row["job"]) == (run["backend_url"], run["job_id"]),
        "claim_observation_not_bound",
    )
    claim = dict(row)
    root = {
        "origin": run["backend_url"],
        "job_id": run["job_id"],
        "runner_id": runner_id,
        **{k: hash_value(claim[k]) for k in ("plan_sha256", "case_sha256", "association_sha256")},
    }
    return root, claim


def binding(reply: dict) -> dict:
    require(reply["claim"] is not None, "claim_not_observed")
    return {k: reply[k] for k in ("origin", "job_id", "runner_id")} | {
        k: reply["claim"][k] for k in ("contract_id", "attempt_id", "fence", "contract_sha256")
    }


def validate(reply: dict, root: dict, original_claim: dict) -> None:
    fields(
        reply,
        ROOT
        | {
            "schema",
            "claim",
            "execution_state",
            "capacity_reserved",
            "result",
            "completion",
            "stop",
        },
    )
    require(
        reply["schema"] == "vardr.managed-claim-observation/1"
        and all(reply[k] == v for k, v in root.items())
        and type(reply["capacity_reserved"]) is bool,
        "claim_observation_binding",
    )
    claim = reply["claim"]
    if claim is None:
        require(
            reply["execution_state"] is None
            and reply["capacity_reserved"] is False
            and all(reply[k] is None for k in ("result", "completion", "stop"))
            and original_claim["contract"] is None,
            "inconsistent_claim_absence",
        )
        require(len(encoded(reply)) <= 16384, "observation_size")
        return
    fields(claim, CLAIM)
    for key in ("contract_id", "attempt_id"):
        identifier(claim[key])
    for key in ("contract_sha256", "authority_sha256"):
        hash_value(claim[key])
    integer(claim["fence"], 1)
    integer(claim["authority_revision"])
    require(
        type(claim["consumed"]) is bool
        and type(reply["execution_state"]) is str
        and reply["execution_state"] in STATES,
        "invalid_observed_claim",
    )
    if original_claim["contract"] is not None:
        require(
            (
                original_claim["contract"],
                original_claim["attempt"],
                original_claim["fence"],
                original_claim["authority_sha256"],
            )
            == (
                claim["contract_id"],
                claim["attempt_id"],
                claim["fence"],
                claim["authority_sha256"],
            ),
            "original_claim_changed",
        )
    stopped = reply["stop"]
    retired_exit = (
        type(stopped) is dict
        and stopped.get("cause") == "observed_exit"
        and stopped.get("outcome") == "failed"
        and reply["execution_state"] == "failed"
        and reply["capacity_reserved"] is False
        and reply["result"] is None
        and reply["completion"] is None
    )
    require(
        claim["consumed"]
        or all(reply[k] is None for k in ("result", "completion", "stop"))
        or retired_exit,
        "inconsistent_observed_consumption",
    )
    association = binding(reply)
    result, completion, stop = reply["result"], reply["completion"], reply["stop"]
    if result is not None:
        fields(result, results.RESULT_FIELDS)
        artifact = hash_value(result["artifact_sha256"])
        record = {
            "binding": encoded(association).decode(),
            "artifact_sha256": artifact,
            "case_sha256": root["case_sha256"],
            "receipt_sha256": results.receipt(association, artifact, root["case_sha256"]),
        }
        results.check_result(result, record)
    if completion is not None:
        require(result is not None and type(completion) is dict, "completion_without_result")
        outcome = completion.get("outcome")
        require(
            type(outcome) is str and outcome in {"completed", "failed", "cancelled"},
            "invalid_observed_completion",
        )
        results.check_completion(
            completion,
            {
                "binding": encoded(association).decode(),
                "receipt_sha256": result["receipt_sha256"],
                "outcome": outcome,
            },
        )
        require(
            reply["execution_state"] == outcome and reply["capacity_reserved"] is False,
            "inconsistent_observed_completion",
        )
    if stop is not None:
        require(
            type(stop) is dict
            and type(stop.get("cause")) is str
            and stop["cause"] in stops.RECEIPT_CAUSES,
            "invalid_observed_stop",
        )
        outcome = "cancelled" if stop["cause"] in stops.CANCEL_CAUSES else "failed"
        stops.check_receipt(
            stop,
            {
                "binding": encoded(association).decode(),
                "outcome": outcome,
                "cause": stop["cause"],
                "receipt_sha256": stops.stop_hash(association, outcome, stop["cause"]),
            },
        )
        require(
            result is None
            and completion is None
            and reply["execution_state"] == outcome
            and reply["capacity_reserved"] is False,
            "inconsistent_observed_stop",
        )
    require(len(encoded(reply)) <= 16384, "observation_size")


class ObservationStore:
    def __init__(self, journal: Journal):
        self.journal = journal
        with journal._connection() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS managed_claim_observations (
                run_id TEXT PRIMARY KEY, snapshot TEXT NOT NULL, observed_at TEXT NOT NULL)""")

    def record(self, run_id: str, root: dict, reply: dict) -> None:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            claim = con.execute(
                "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            require(
                claim is not None
                and run is not None
                and (claim["backend"], claim["job"]) == (root["origin"], root["job_id"])
                and (run["backend_url"], run["job_id"]) == (root["origin"], root["job_id"])
                and all(
                    claim[k] == root[k]
                    for k in ("plan_sha256", "case_sha256", "association_sha256")
                ),
                "observation_source_changed",
            )
            if claim["contract"] is not None:
                require(
                    reply["claim"] is not None
                    and (
                        claim["contract"],
                        claim["attempt"],
                        claim["fence"],
                        claim["authority_sha256"],
                    )
                    == (
                        reply["claim"]["contract_id"],
                        reply["claim"]["attempt_id"],
                        reply["claim"]["fence"],
                        reply["claim"]["authority_sha256"],
                    ),
                    "observation_source_changed",
                )
            previous = con.execute(
                "SELECT snapshot FROM managed_claim_observations WHERE run_id=?", (run_id,)
            ).fetchone()
            if previous is not None:
                old = json.loads(previous[0])
                if old["claim"] is not None:
                    require(
                        reply["claim"] is not None
                        and all(old["claim"][k] == reply["claim"][k] for k in CLAIM - {"consumed"})
                        and (not old["claim"]["consumed"] or reply["claim"]["consumed"]),
                        "observed_claim_regressed",
                    )
                for key in ("result", "completion", "stop"):
                    require(
                        old[key] is None or old[key] == reply[key], "observed_receipt_regressed"
                    )
            con.execute(
                "INSERT INTO managed_claim_observations (run_id,snapshot,observed_at) VALUES (?,?,?) ON CONFLICT(run_id) DO UPDATE SET snapshot=excluded.snapshot,observed_at=excluded.observed_at",
                (run_id, encoded(reply).decode(), utc_now()),
            )


def observe(journal: Journal, run_id: str, runner_id: str, inspect: Callable[[dict], dict]) -> dict:
    """Explicit observation only; absence or unconsumed state never permits a retry."""
    root, claim = original(journal, run_id, runner_id)
    try:
        reply = inspect({k: v for k, v in root.items() if k != "job_id"})
    except Exception:
        raise AuthorizationError("claim_observation_unavailable") from None
    validate(reply, root, claim)
    ObservationStore(journal).record(run_id, root, reply)
    return reply


def reconcile_result(
    journal: Journal, run_id: str, runner_id: str, inspect: Callable[[dict], dict]
) -> str:
    expected = results.ResultStore(journal).get(run_id)
    require(json.loads(expected["binding"])["runner_id"] == runner_id, "original_runner_required")
    reply = observe(journal, run_id, runner_id, inspect)
    association = binding(reply)
    adapted = {
        "schema": "vardr.managed-reconciliation/1",
        **association,
        "consumed": reply["claim"]["consumed"],
        "execution_state": reply["execution_state"],
        "capacity_reserved": reply["capacity_reserved"],
        "result": reply["result"],
        "completion": reply["completion"],
    }
    return results.reconcile(journal, run_id, lambda _: adapted)


def reconcile_stop(
    journal: Journal, run_id: str, runner_id: str, inspect: Callable[[dict], dict]
) -> str:
    expected = stops.StopStore(journal).get(run_id)
    require(json.loads(expected["binding"])["runner_id"] == runner_id, "original_runner_required")
    reply = observe(journal, run_id, runner_id, inspect)
    association = binding(reply)
    adapted = {
        "schema": "vardr.managed-stop-observation/1",
        **association,
        "consumed": reply["claim"]["consumed"],
        "execution_state": reply["execution_state"],
        "capacity_reserved": reply["capacity_reserved"],
        "stop": reply["stop"],
    }
    return stops.reconcile(journal, run_id, lambda _: adapted)
