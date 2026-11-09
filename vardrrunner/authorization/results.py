"""Explicit managed result finalization and read-only reconciliation; no recovery RPCs."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path

from vardrrunner.journal import Journal, Phase, utc_now

from .codec import AuthorizationError, decoded, digest, encoded, fields, integer, require

BINDING = {"origin", "job_id", "runner_id", "contract_id", "attempt_id", "fence", "contract_sha256"}
RESULT_FIELDS = BINDING | {
    "schema",
    "artifact_sha256",
    "case_sha256",
    "receipt_sha256",
    "evidence_created",
    "scan_items_created",
}


def _artifact_bytes(path: Path, maximum: int) -> bytes:
    """Read bounded regular single-link bytes; check leaf identity around open/read."""

    def identity(info):
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not getattr(info, "st_file_attributes", 0) & 0x400
            and 0 < info.st_size <= maximum,
            "managed_partial_file",
        )
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

    try:
        before = identity(path.lstat())
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags | getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "rb") as stream:
            require(identity(os.fstat(stream.fileno())) == before, "managed_partial_changed")
            data = stream.read(maximum + 1)
            require(identity(os.fstat(stream.fileno())) == before, "managed_partial_changed")
        require(identity(path.lstat()) == before, "managed_partial_changed")
        require(len(data) == before[2], "managed_partial_changed")
        return data
    except OSError:
        raise AuthorizationError("managed_partial_unavailable") from None


def _cancel_checkpoint(raw: dict, case: dict) -> None:
    """Promote only an already-read checkpoint inside the confirmed-stop lane."""
    identities = [identity["id"] for identity in case["identities"]]
    expected = {row["identity_id"]: row["decision"] for row in case["expected_access"]}
    require(
        raw["findings"] == []
        and [row.get("identity_id") for row in raw["executions"]] == identities
        and [row.get("identity_id") for row in raw["assessments"]] == identities,
        "managed_checkpoint_binding",
    )
    for index, (execution, assessment) in enumerate(
        zip(raw["executions"], raw["assessments"], strict=True)
    ):
        require(
            type(assessment.get("execution_index")) is int
            and assessment["execution_index"] == index
            and assessment.get("expected_access") == expected.get(identities[index]),
            "managed_checkpoint_binding",
        )
        if execution.get("error") == "execution_in_progress":
            require(
                type(execution.get("status_code")) is int
                and execution["status_code"] == 0
                and execution.get("observed_outcome") == "error"
                and assessment.get("source") == "none"
                and (
                    assessment.get("decision") == "inconclusive"
                    and assessment.get("reason") == "execution_in_progress"
                    or assessment.get("decision") == "skipped"
                    and expected.get(identities[index]) in {None, "skip"}
                    and assessment.get("reason") in {"no_expectation", "explicit_skip"}
                ),
                "managed_checkpoint_pending",
            )
            execution["error"] = "execution_cancelled"
        if assessment.get("reason") == "execution_in_progress":
            require(
                assessment.get("decision") == "inconclusive" and assessment.get("source") == "none",
                "managed_checkpoint_pending",
            )
            assessment["reason"] = (
                "execution_error"
                if execution.get("error") == "execution_cancelled"
                else "execution_cancelled"
            )
    raw["error"] = "execution_cancelled"


def retain_stopped_artifact(handle, directory: Path) -> None:
    """Stage existing Gate bytes only after the trusted native confirmed-stop path."""
    from .stops import CAUSES

    require(
        handle._confirmed_stop is not None
        and handle._confirmed_stop[1] in CAUSES
        and handle._returned_artifact is None,
        "known_native_stop_required",
    )
    maximum = min(512000, handle._artifact_limit, handle.gate.permission["max_artifact_bytes"])
    raw = decoded(_artifact_bytes(directory / "vardrgate_result.json", maximum), maximum)
    # Reuse the shared strict JSON/case binding; Map remains the result validator
    # and assessment engine. The fixed marker never supplies termination proof.
    require(
        type(raw) is dict
        and raw.get("test_case_id") == handle.gate.case["id"]
        and type(raw.get("error")) is str
        and raw["error"] in {"execution_cancelled", "execution_in_progress"}
        and set(raw)
        <= {"test_case_id", "executions", "findings", "assessments", "preflight", "error"}
        and all(
            type(raw.get(key)) is list and all(type(row) is dict for row in raw[key])
            for key in ("executions", "findings", "assessments")
        )
        and (
            "preflight" not in raw
            or (
                type(raw["preflight"]) is list
                and all(type(row) is dict for row in raw["preflight"])
            )
        ),
        "managed_partial_result",
    )
    if raw["error"] == "execution_in_progress":
        _cancel_checkpoint(raw, handle.gate.case)
    raw["case_hash"] = handle.gate.plan["case_hash"]
    from vardrrunner import manifests

    raw["provenance"] = manifests.evidence_provenance(
        handle.gate.case,
        raw["case_hash"],
        {
            "vardrgate_api_test": {
                "sha256": handle.gate.plan["tool_sha256"],
                "version": "unknown",
                "hash_basis": "approved_plan_not_observed",
            }
        },
    )
    data = encoded(raw)
    require(len(data) <= maximum, "managed_artifact_size")
    output = directory / "vardrgate_stopped_result.json"
    # Keep the original atomic Gate file untouched. Publish a completed private
    # copy without replacing an existing destination on either supported OS.
    with tempfile.TemporaryDirectory(prefix=".stopped-result-", dir=directory) as temporary:
        staged = Path(temporary) / "artifact.json"
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            os.rename(staged, output)  # Windows rename refuses an existing name.
        else:
            os.link(staged, output)  # Atomic no-replace publication on POSIX.
    require(_artifact_bytes(output, maximum) == data, "managed_partial_changed")
    record = handle.store.journal.transition(
        handle.run_id,
        Phase.ARTIFACT_READY,
        pid=None,
        artifact_path=str(output),
        artifact_sha256=digest(data),
        artifact_size=len(data),
        status="stopped_artifact_held",
        failure_reason=handle._confirmed_stop[1],
        last_event="managed_stopped_artifact_not_uploaded",
    )
    handle._returned_artifact = (output, record.artifact_sha256 or "", record.artifact_size or 0)


def receipt(binding: dict, artifact_sha256: str, case_sha256: str) -> str:
    return digest(
        encoded(
            {
                "schema": "vardr.managed-result/1",
                **binding,
                "artifact_sha256": artifact_sha256,
                "case_sha256": case_sha256,
            }
        )
    )


class ResultStore:
    def __init__(self, journal: Journal):
        self.journal = journal
        with journal._connection() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS managed_result_intents (
                run_id TEXT PRIMARY KEY, binding TEXT NOT NULL, artifact_sha256 TEXT NOT NULL,
                artifact_size INTEGER NOT NULL, case_sha256 TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL, outcome TEXT NOT NULL,
                state TEXT NOT NULL, finish_sent INTEGER NOT NULL DEFAULT 0)""")

    def get(self, run_id: str) -> dict:
        with self.journal._connection() as con:
            row = con.execute(
                "SELECT * FROM managed_result_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            require(row is not None, "managed_result_intent_missing")
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
            and (run["backend_url"], run["job_id"], run["artifact_sha256"], run["artifact_size"])
            == (
                binding["origin"],
                binding["job_id"],
                result["artifact_sha256"],
                result["artifact_size"],
            )
            and claim["case_sha256"] == result["case_sha256"]
            and result["receipt_sha256"]
            == receipt(binding, result["artifact_sha256"], result["case_sha256"])
            and result["outcome"] in {"completed", "failed"},
            "managed_result_intent_binding",
        )
        return result

    def reserve(self, handle, binding: dict, artifact_sha256: str, size: int, outcome: str) -> dict:
        case_hash = handle.gate.plan["case_hash"]
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
                and claim["state"] == "consume_acknowledged",
                "managed_result_not_owned",
            )
            require(
                (claim["contract"], claim["attempt"], claim["fence"])
                == (binding["contract_id"], binding["attempt_id"], binding["fence"])
                and run is not None
                and (run["backend_url"], run["job_id"]) == (binding["origin"], binding["job_id"]),
                "managed_result_not_owned",
            )
            require(
                run is not None
                and run["phase"] == Phase.ARTIFACT_READY.value
                and run["pid"] is None
                and run["artifact_sha256"] == artifact_sha256
                and run["artifact_size"] == size
                and claim["case_sha256"] == case_hash,
                "managed_artifact_binding",
            )
            try:
                con.execute(
                    "INSERT INTO managed_result_intents (run_id,binding,artifact_sha256,artifact_size,case_sha256,receipt_sha256,outcome,state) VALUES (?,?,?,?,?,?,?,'result_in_flight')",
                    (
                        handle.run_id,
                        encoded(binding).decode(),
                        artifact_sha256,
                        size,
                        case_hash,
                        receipt(binding, artifact_sha256, case_hash),
                        outcome,
                    ),
                )
            except sqlite3.IntegrityError:
                raise AuthorizationError("managed_result_already_attempted") from None
            con.execute(
                "UPDATE runs SET phase=?,upload_state='in_progress',last_event='managed_result_send',updated_at=? WHERE run_id=?",
                (Phase.UPLOADING.value, utc_now(), handle.run_id),
            )
        return self.get(handle.run_id)

    def result_ack(
        self, run_id: str, *, observed: bool = False, expected_association: bytes | None = None
    ) -> None:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            if expected_association is not None:
                from .observations import require_worker_association

                require_worker_association(con, run_id, expected_association)
            row = con.execute(
                "SELECT state FROM managed_result_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            require(row is not None and row[0] != "terminal", "managed_result_state")
            if not observed:
                require(row[0] == "result_in_flight", "managed_result_state")
            con.execute(
                "UPDATE managed_result_intents SET state=? WHERE run_id=?",
                ("result_observed" if observed else "result_acknowledged", run_id),
            )
            con.execute(
                "UPDATE runs SET phase=?,upload_state='succeeded',last_event='managed_result_receipt',updated_at=? WHERE run_id=?",
                (Phase.FINALIZING.value, utc_now(), run_id),
            )

    def finish_send(self, run_id: str) -> None:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            count = con.execute(
                "UPDATE managed_result_intents SET state='finish_in_flight',finish_sent=1 WHERE run_id=? AND state='result_acknowledged' AND finish_sent=0",
                (run_id,),
            ).rowcount
            require(count == 1, "managed_finish_already_attempted")

    def close(
        self, run_id: str, expected: dict, *, expected_association: bytes | None = None
    ) -> None:
        binding = json.loads(expected["binding"])
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            if expected_association is not None:
                from .observations import require_worker_association

                require_worker_association(con, run_id, expected_association)
            row = con.execute(
                "SELECT * FROM managed_result_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            claim = con.execute(
                "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            require(
                row is not None
                and all(
                    row[k] == expected[k]
                    for k in ("binding", "artifact_sha256", "receipt_sha256", "outcome")
                ),
                "managed_result_changed",
            )
            require(
                claim is not None
                and (claim["contract"], claim["attempt"], claim["fence"])
                == (binding["contract_id"], binding["attempt_id"], binding["fence"]),
                "managed_completion_owner",
            )
            require(
                run is not None
                and run["pid"] is None
                and run["artifact_sha256"] == expected["artifact_sha256"],
                "managed_artifact_binding",
            )
            changed = con.execute(
                "UPDATE authorization_contracts SET consumed=2 WHERE issuer=? AND contract=? AND attempt=? AND fence=? AND consumed IN (1,2)",
                (claim["issuer"], claim["contract"], claim["attempt"], claim["fence"]),
            ).rowcount
            require(changed == 1, "managed_completion_owner")
            con.execute(
                "UPDATE managed_result_intents SET state='terminal' WHERE run_id=?", (run_id,)
            )
            completed = expected["outcome"] == "completed"
            con.execute(
                "UPDATE runs SET phase=?,status=?,completed_at=?,last_event='managed_completion_receipt',updated_at=? WHERE run_id=?",
                (
                    Phase.DONE.value if completed else Phase.FAILED.value,
                    "done" if completed else "failed",
                    utc_now(),
                    utc_now(),
                    run_id,
                ),
            )


def check_result(reply: dict, record: dict) -> None:
    fields(reply, RESULT_FIELDS)
    binding = json.loads(record["binding"])
    integer(reply["fence"], 1)
    integer(reply["evidence_created"], 0, 200)
    integer(reply["scan_items_created"], 0, 500)
    require(
        reply["schema"] == "vardr.managed-result-receipt/1"
        and all(reply[k] == v for k, v in binding.items())
        and all(
            reply[k] == record[k] for k in ("artifact_sha256", "case_sha256", "receipt_sha256")
        ),
        "managed_result_receipt_binding",
    )


def check_completion(reply: dict, record: dict) -> None:
    binding = json.loads(record["binding"])
    fields(reply, BINDING | {"schema", "receipt_sha256", "outcome", "capacity_reserved"})
    integer(reply["fence"], 1)
    require(
        reply
        == {
            "schema": "vardr.managed-completion/1",
            **binding,
            "receipt_sha256": record["receipt_sha256"],
            "outcome": record["outcome"],
            "capacity_reserved": False,
        }
        and reply["capacity_reserved"] is False,
        "managed_completion_binding",
    )


def finalize(handle, submit: Callable[[dict], dict], finish: Callable[[dict], dict]) -> dict:
    """One explicit call after normal native return; no retry after any ambiguity."""
    require(handle._returned_artifact is not None, "known_native_return_required")
    output, expected_hash, expected_size = handle._returned_artifact
    require(output.is_file() and not output.is_symlink(), "managed_artifact_binding")
    require(
        output.stat().st_size
        == expected_size
        <= min(512000, handle._artifact_limit, handle.gate.permission["max_artifact_bytes"]),
        "managed_artifact_size",
    )
    if handle._confirmed_stop is not None:
        data = _artifact_bytes(output, expected_size)
    else:
        with output.open("rb") as stream:
            data = stream.read(expected_size + 1)
    require(
        len(data) == expected_size and digest(data) == expected_hash, "managed_artifact_changed"
    )
    raw = decoded(data, 512000)
    require(
        type(raw) is dict and raw.get("case_hash") == handle.gate.plan["case_hash"],
        "result_case_binding",
    )
    require(raw.get("error") != "execution_in_progress", "managed_checkpoint_not_final")
    preflight = raw.get("preflight") or []
    require(
        type(preflight) is list and all(type(p) is dict for p in preflight),
        "invalid_preflight_result",
    )
    outcome = (
        "failed"
        if handle._confirmed_stop is not None
        or raw.get("error") == "execution_cancelled"
        or any(p.get("status") != "passed" for p in preflight)
        else "completed"
    )
    gate = handle.gate
    binding = {k: gate.binding[k] for k in BINDING - {"contract_sha256"}}
    binding["contract_sha256"] = digest(encoded(gate.envelope))
    store = ResultStore(handle.store.journal)
    record = store.reserve(handle, binding, expected_hash, expected_size, outcome)
    request = {**gate.request, "contract_sha256": binding["contract_sha256"]}
    try:
        reply = submit(
            {**request, "artifact": data.decode("utf-8"), "artifact_sha256": expected_hash}
        )
    except Exception:
        raise AuthorizationError("managed_result_outcome_unknown") from None
    check_result(reply, record)
    store.result_ack(handle.run_id)
    store.finish_send(handle.run_id)
    try:
        reply = finish(
            {
                **request,
                "receipt_sha256": record["receipt_sha256"],
                "outcome": outcome,
                "termination_confirmed": True,
            }
        )
    except Exception:
        raise AuthorizationError("managed_finish_outcome_unknown") from None
    check_completion(reply, record)
    store.close(handle.run_id, record)
    return decoded(encoded(reply))  # Only the validated, durably accepted canonical ACK.


def reconcile(
    journal: Journal,
    run_id: str,
    inspect: Callable[[dict], dict],
    *,
    expected_association: bytes | None = None,
) -> str:
    """Explicit authenticated observation; the callback supplies its own capability.

    Only public binding is sent. No capability, execution proof or retry right is
    reconstructed from journal contents; missing/nonterminal receipts stay held.
    """
    store = ResultStore(journal)
    record = store.get(run_id)
    binding = json.loads(record["binding"])
    public = {k: binding[k] for k in BINDING - {"job_id"}}
    try:
        reply = inspect(public)
    except Exception:
        raise AuthorizationError("managed_reconciliation_unavailable") from None
    fields(
        reply,
        BINDING
        | {"schema", "consumed", "capacity_reserved", "execution_state", "result", "completion"},
    )
    integer(reply["fence"], 1)
    require(
        reply["schema"] == "vardr.managed-reconciliation/1"
        and all(reply[k] == v for k, v in binding.items())
        and reply["consumed"] is True
        and type(reply["capacity_reserved"]) is bool
        and type(reply["execution_state"]) is str
        and reply["execution_state"]
        in {"active", "uncertain", "cancel_requested", "completed", "failed", "cancelled"},
        "managed_reconciliation_binding",
    )
    if reply["result"] is None:
        require(record["state"] != "terminal", "terminal_receipt_missing")
        require(reply["completion"] is None, "completion_without_result")
        return "held_no_receipt"
    check_result(reply["result"], record)
    if reply["completion"] is None:
        require(record["state"] != "terminal", "terminal_receipt_missing")
        if record["state"] != "terminal":
            if expected_association is None:
                store.result_ack(run_id, observed=True)
            else:
                store.result_ack(run_id, observed=True, expected_association=expected_association)
        return "held_result_observed"
    check_completion(reply["completion"], record)
    require(
        reply["capacity_reserved"] is False and reply["execution_state"] == record["outcome"],
        "managed_reconciliation_binding",
    )
    if expected_association is None:
        store.close(run_id, record)
    else:
        store.close(run_id, record, expected_association=expected_association)
    return "terminal_receipt_observed"
