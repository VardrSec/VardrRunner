"""Capability-free authenticated receipt observation; never resumes managed work."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable

from vardrrunner.journal import Journal, utc_now

from . import results, stops
from .codec import (
    AuthorizationError,
    decoded,
    digest,
    encoded,
    fields,
    identifier,
    integer,
    require,
)
from .persistent_codec import sequence64
from .worker_binding import CLAIM_ASSOCIATION, claim_association

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
RUNTIME_RETIREMENT = {
    "schema",
    "runtime_id",
    "runtime_sha256",
    "origin",
    "runner_id",
    "enrollment_id",
    "report_sha256",
    "bound",
    "retired",
    "receipt_sha256",
}
SEQUENCE_RETIREMENT = (RUNTIME_RETIREMENT - {"bound"}) | {
    "runtime_sequence",
    "last_sequence",
    "binding",
    "attempt_receipt",
}
OBSERVATION = ROOT | {
    "schema",
    "claim",
    "execution_state",
    "capacity_reserved",
    "result",
    "completion",
    "stop",
}


def _runtime_sequence(association: dict) -> int | None:
    if association.get("schema") == "vardr.worker-claim-association/1":
        return None
    if association.get("schema") == "vardr.worker-claim-association/3":
        fields(association, CLAIM_ASSOCIATION | {"runtime_sequence", "admission_sha256"})
        hash_value(association["runtime_sha256"])
        hash_value(association["admission_sha256"])
        return sequence64(association["runtime_sequence"], minimum=1)
    require(
        association.get("schema") == "vardr.worker-claim-association/2",
        "runtime_observation_association",
    )
    return integer(association.get("runtime_sequence"), 1, 32)


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


def _runtime_retirement(reply: dict, root: dict, association: dict) -> None:
    require(
        all(association[k] == value for k, value in root.items()),
        "runtime_observation_association",
    )
    receipt = reply["runtime_retirement"]
    if receipt is None:
        return
    sequence = _runtime_sequence(association)
    if sequence is not None:
        _sequence_retirement(
            reply,
            association,
            receipt,
            sequence,
            persistent=association["schema"] == "vardr.worker-claim-association/3",
        )
        return
    fields(receipt, RUNTIME_RETIREMENT)
    for key in ("report_sha256", "runtime_sha256", "receipt_sha256"):
        hash_value(receipt[key])
    require(
        receipt["schema"] == "vardr.worker-unbound-retirement/1"
        and all(
            receipt[k] == association[k]
            for k in ("runtime_id", "runtime_sha256", "origin", "runner_id", "enrollment_id")
        )
        and receipt["bound"] is False
        and receipt["retired"] is True
        and receipt["receipt_sha256"]
        == digest(encoded({k: v for k, v in receipt.items() if k != "receipt_sha256"}))
        and reply["claim"] is None,
        "runtime_retirement_receipt_binding",
    )


def _sequence_retirement(
    reply: dict, association: dict, receipt: dict, sequence: int, *, persistent: bool = False
) -> None:
    """Physical retirement is distinct from any historical job's terminal ACK."""
    fields(receipt, SEQUENCE_RETIREMENT | ({"admission_sha256"} if persistent else set()))
    for key in ("report_sha256", "runtime_sha256", "receipt_sha256"):
        hash_value(receipt[key])
    last = (
        sequence64(receipt["last_sequence"])
        if persistent
        else integer(receipt["last_sequence"], 0, 32)
    )
    if persistent:
        require(
            hash_value(receipt["admission_sha256"]) == association["admission_sha256"],
            "runtime_retirement_admission_binding",
        )
    require(
        receipt["schema"]
        == ("vardr.worker-retirement/3" if persistent else "vardr.worker-retirement/2")
        and all(
            receipt[k] == association[k]
            for k in ("runtime_id", "runtime_sha256", "origin", "runner_id", "enrollment_id")
        )
        and receipt["retired"] is True
        and receipt["receipt_sha256"]
        == digest(encoded({k: v for k, v in receipt.items() if k != "receipt_sha256"})),
        "runtime_retirement_receipt_binding",
    )
    require(
        last < sequence if reply["claim"] is None else last >= sequence,
        "runtime_retirement_sequence_binding",
    )
    active = receipt["runtime_sequence"]
    nested, terminal = receipt["binding"], receipt["attempt_receipt"]
    if active is None:
        require(nested is None and terminal is None, "runtime_retirement_sequence_binding")
        return
    active_number = sequence64(active, minimum=1) if persistent else integer(active, 1, 32)
    require(active_number == last, "runtime_retirement_sequence_binding")
    fields(nested, results.BINDING)
    require(
        all(nested[k] == association[k] for k in ("origin", "runner_id")),
        "runtime_retirement_sequence_binding",
    )
    for key in ("job_id", "runner_id", "contract_id", "attempt_id"):
        identifier(nested[key])
    integer(nested["fence"], 1)
    hash_value(nested["contract_sha256"])
    require(type(terminal) is dict, "runtime_retirement_sequence_binding")
    hash_value(terminal.get("receipt_sha256"))
    outcome = terminal.get("outcome")
    require(
        type(outcome) is str and outcome in {"completed", "failed", "cancelled"},
        "runtime_retirement_sequence_binding",
    )
    if terminal.get("schema") == "vardr.managed-stop-receipt/1":
        cause = terminal.get("cause")
        require(type(cause) is str and cause in stops.RECEIPT_CAUSES, "invalid_observed_stop")
        expected_outcome = "cancelled" if cause in stops.CANCEL_CAUSES else "failed"
        stops.check_receipt(
            terminal,
            {
                "binding": encoded(nested).decode(),
                "outcome": expected_outcome,
                "cause": cause,
                "receipt_sha256": stops.stop_hash(nested, expected_outcome, cause),
            },
        )
    else:
        results.check_completion(
            terminal,
            {
                "binding": encoded(nested).decode(),
                "outcome": outcome,
                "receipt_sha256": terminal["receipt_sha256"],
            },
        )
    if active_number == sequence:
        fields(reply["claim"], CLAIM)
        require(
            nested == binding(reply) and terminal in (reply["completion"], reply["stop"]),
            "runtime_retirement_sequence_binding",
        )


def validate(
    reply: dict, root: dict, original_claim: dict, runtime_association: dict | None = None
) -> None:
    sequence = _runtime_sequence(runtime_association) if runtime_association is not None else None
    persistent = (
        runtime_association is not None
        and runtime_association["schema"] == "vardr.worker-claim-association/3"
    )
    fields(
        reply,
        OBSERVATION
        | ({"runtime_retirement"} if runtime_association is not None else set())
        | ({"runtime_id", "runtime_sha256", "runtime_sequence"} if sequence is not None else set())
        | ({"admission_sha256"} if persistent else set()),
    )
    require(
        reply["schema"]
        == (
            "vardr.managed-claim-observation/4"
            if persistent
            else "vardr.managed-claim-observation/3"
            if sequence is not None
            else "vardr.managed-claim-observation/2"
            if runtime_association is not None
            else "vardr.managed-claim-observation/1"
        )
        and all(reply[k] == v for k, v in root.items())
        and type(reply["capacity_reserved"]) is bool,
        "claim_observation_binding",
    )
    if sequence is not None:
        require(
            runtime_association is not None
            and (
                sequence64(reply["runtime_sequence"], minimum=1)
                if persistent
                else integer(reply["runtime_sequence"], 1, 32)
            )
            == sequence
            and all(
                reply[key] == runtime_association[key]
                for key in (
                    "runtime_id",
                    "runtime_sha256",
                    *(["admission_sha256"] if persistent else []),
                )
            ),
            "runtime_observation_association",
        )
    if runtime_association is not None:
        _runtime_retirement(reply, root, runtime_association)
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

    def record(
        self, run_id: str, root: dict, reply: dict, runtime_association: dict | None = None
    ) -> None:
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
            require(
                claim_association(con, run_id) == runtime_association,
                "runtime_observation_source_changed",
            )
            validate(reply, root, dict(claim), runtime_association)
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
                old = decoded(previous[0].encode(), 16384)
                require(
                    type(old) is dict and encoded(old).decode() == previous[0],
                    "observed_snapshot_noncanonical",
                )
                schemas = {
                    "vardr.managed-claim-observation/1": OBSERVATION,
                    "vardr.managed-claim-observation/2": OBSERVATION | {"runtime_retirement"},
                    "vardr.managed-claim-observation/3": OBSERVATION
                    | {"runtime_retirement", "runtime_id", "runtime_sha256", "runtime_sequence"},
                    "vardr.managed-claim-observation/4": OBSERVATION
                    | {
                        "runtime_retirement",
                        "runtime_id",
                        "runtime_sha256",
                        "runtime_sequence",
                        "admission_sha256",
                    },
                }
                require(
                    type(old.get("schema")) is str and old["schema"] in schemas,
                    "observed_snapshot_schema",
                )
                fields(old, schemas[old["schema"]])
                require(all(old[key] == root[key] for key in ROOT), "observed_root_regressed")
                require(
                    encoded(
                        {
                            key: old[key]
                            for key in (
                                "runtime_id",
                                "runtime_sha256",
                                "runtime_sequence",
                                "admission_sha256",
                            )
                            if key in old
                        }
                    )
                    == encoded(
                        {
                            key: reply.get(key)
                            for key in (
                                "runtime_id",
                                "runtime_sha256",
                                "runtime_sequence",
                                "admission_sha256",
                            )
                            if key in old
                        }
                    ),
                    "observed_runtime_association_regressed",
                )
                if old["claim"] is not None:
                    fields(old["claim"], CLAIM)
                    require(type(old["claim"]["consumed"]) is bool, "observed_claim_regressed")
                    require(
                        reply["claim"] is not None
                        and encoded({key: old["claim"][key] for key in CLAIM - {"consumed"}})
                        == encoded({key: reply["claim"][key] for key in CLAIM - {"consumed"}})
                        and (not old["claim"]["consumed"] or reply["claim"]["consumed"]),
                        "observed_claim_regressed",
                    )
                for key in ("result", "completion", "stop"):
                    require(
                        old[key] is None or encoded(old[key]) == encoded(reply[key]),
                        "observed_receipt_regressed",
                    )
                require(
                    old.get("runtime_retirement") is None
                    or encoded(old["runtime_retirement"])
                    == encoded(reply.get("runtime_retirement")),
                    "observed_runtime_retirement_regressed",
                )
            con.execute(
                "INSERT INTO managed_claim_observations (run_id,snapshot,observed_at) VALUES (?,?,?) ON CONFLICT(run_id) DO UPDATE SET snapshot=excluded.snapshot,observed_at=excluded.observed_at",
                (run_id, encoded(reply).decode(), utc_now()),
            )


def observe(journal: Journal, run_id: str, runner_id: str, inspect: Callable[[dict], dict]) -> dict:
    """Explicit observation only; absence or unconsumed state never permits a retry."""
    root, claim = original(journal, run_id, runner_id)
    with journal._connection() as con:
        association = claim_association(con, run_id)
    request = {k: v for k, v in root.items() if k != "job_id"}
    if association is not None:
        if association["schema"] == "vardr.worker-claim-association/3":
            require(association["runner_id"] == runner_id, "original_runner_required")
        request.update({k: association[k] for k in ("runtime_id", "runtime_sha256")})
        sequence = _runtime_sequence(association)
        if sequence is not None:
            request["runtime_sequence"] = association["runtime_sequence"]
            if association["schema"] == "vardr.worker-claim-association/3":
                request["admission_sha256"] = association["admission_sha256"]
    try:
        reply = inspect(request)
    except Exception:
        raise AuthorizationError("claim_observation_unavailable") from None
    validate(reply, root, claim, association)
    ObservationStore(journal).record(run_id, root, reply, association)
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
