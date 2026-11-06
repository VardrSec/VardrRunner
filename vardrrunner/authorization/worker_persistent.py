"""Append-only persistent-worker metadata in the existing execution journal.

These records preserve one-send fences and associations. They grant no launch,
permission renewal, process-stop proof or right to retry an unknown mutation.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from vardrrunner.journal import Journal, Phase, normalize_backend_url

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
from .persistent_codec import MAX_SEQUENCE, sequence64, wire_sequence64
from .results import BINDING, _artifact_bytes, check_completion
from .worker_admission import Admission, _uuid, hash_value
from .worker_binding import CLAIM_ASSOCIATION, WorkerStore

PERSISTENT_BINDING = BINDING | {
    "runtime_id",
    "runtime_sha256",
    "admission_sha256",
    "runtime_sequence",
}
ATTEMPT_STATES = {
    "claim_prepared",
    "bind_in_flight",
    "bound",
    "completion_acknowledged",
    "done_acknowledged",
    "release_in_flight",
    "released",
    "physical_retirement_observed",
}
_PENDING = {
    "runs": "phase NOT IN ('done','failed','interrupted','stop_work','skipped')",
    "managed_claim_intents": "state NOT IN ('persistent_released','preclaim_retired','runtime_unbound_retired','host_exit_observed','failed_completion_observed','consume_acknowledged')",
    "managed_result_intents": "state NOT IN ('terminal','server_retired','host_retired')",
    "managed_stop_intents": "state NOT IN ('terminal','server_retired','host_retired')",
    "authorization_contracts": "consumed NOT IN (0,2)",
}


def _indexes(con: sqlite3.Connection) -> None:
    # Names/predicates are fixed source constants, never caller SQL. Partial
    # indexes contain unresolved rows rather than the healthy job history.
    for table, predicate in _PENDING.items():
        if con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone():
            if table == "authorization_contracts":
                con.execute(
                    f"CREATE INDEX IF NOT EXISTS persistent_pending_contracts ON {table}(issuer,contract) WHERE {predicate}"
                )
            else:
                con.execute(
                    f"CREATE INDEX IF NOT EXISTS persistent_pending_{table} ON {table}(run_id) WHERE {predicate}"
                )


def _document(raw: str, maximum: int = 8192) -> dict:
    require(type(raw) is str, "worker_persistent_document")
    value = decoded(raw.encode(), maximum)
    require(type(value) is dict and encoded(value).decode() == raw, "worker_persistent_document")
    return value


def _admission(raw: str) -> Admission:
    value = _document(raw)
    require(value.get("schema") == "vardr.worker-admission/3", "worker_persistent_admission")
    result = Admission.parse(value, now=datetime.now(timezone.utc))
    require(getattr(result, "mode", None) == "persistent", "worker_persistent_admission")
    return result


def check_binding(binding: dict) -> int:
    fields(binding, PERSISTENT_BINDING)
    _uuid(binding["runtime_id"])
    for key in ("runtime_sha256", "admission_sha256", "contract_sha256"):
        hash_value(binding[key])
    for key in ("runner_id", "job_id", "contract_id", "attempt_id"):
        identifier(binding[key])
    integer(binding["fence"], 1)
    require(
        type(binding["origin"]) is str
        and normalize_backend_url(binding["origin"]) == binding["origin"],
        "worker_persistent_binding",
    )
    return sequence64(binding["runtime_sequence"], minimum=1)


def parent(con: sqlite3.Connection, runtime_id: str) -> sqlite3.Row:
    row = con.execute(
        "SELECT * FROM managed_persistent_incarnations WHERE runtime_id=?", (runtime_id,)
    ).fetchone()
    require(row is not None, "worker_persistent_runtime_missing")
    admission = _admission(row["admission_snapshot"])
    require(
        admission.runtime_id == row["runtime_id"]
        and admission.runtime_sha256 == row["runtime_sha256"]
        and getattr(admission, "admission_sha256", None) == row["admission_sha256"]
        and admission.max_attempts == row["max_attempts"],
        "worker_persistent_runtime_changed",
    )
    last = integer(row["last_sequence"], 0, MAX_SEQUENCE)
    require(row["state"] in {"idle", "active", "retired"}, "worker_persistent_runtime_changed")
    if last == 0:
        require(
            row["history_head"] is None and row["active_sequence"] is None,
            "worker_persistent_history_changed",
        )
    else:
        require(row["history_head"] == last, "worker_persistent_history_changed")
        head = con.execute(
            "SELECT * FROM managed_persistent_attempts WHERE runtime_id=? AND runtime_sequence=?",
            (runtime_id, last),
        ).fetchone()
        require(
            head is not None
            and head["runtime_sha256"] == row["runtime_sha256"]
            and head["admission_sha256"] == row["admission_sha256"]
            and head["previous_sequence"] == (None if last == 1 else last - 1),
            "worker_persistent_history_changed",
        )
        if row["state"] == "idle":
            require(
                head["state"] == "released"
                and head["release_ack"]
                == head["release_intent"]
                == encoded(release_document(head)).decode(),
                "worker_persistent_projection_changed",
            )
        elif row["state"] == "active":
            require(
                head["state"] not in {"released", "physical_retirement_observed"},
                "worker_persistent_projection_changed",
            )
    if row["state"] == "idle":
        require(row["active_sequence"] is None, "worker_persistent_projection_changed")
    elif row["state"] == "active":
        require(last > 0 and row["active_sequence"] == last, "worker_persistent_projection_changed")
    require(
        (row["state"] == "retired") == (row["retirement"] is not None),
        "worker_persistent_retirement_changed",
    )
    return row


def association(con: sqlite3.Connection, run_id: str) -> dict | None:
    """Read one original v3 link without creating or migrating any storage."""
    if not con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_persistent_attempts'"
    ).fetchone():
        return None
    row = con.execute(
        "SELECT * FROM managed_persistent_attempts WHERE run_id=?", (run_id,)
    ).fetchone()
    if row is None:
        return None
    for table in ("managed_runtime_bindings", "managed_worker_attempts"):
        if con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone():
            require(
                not con.execute(f"SELECT 1 FROM {table} WHERE run_id=?", (run_id,)).fetchone(),
                "worker_claim_association_changed",
            )
    runtime = parent(con, row["runtime_id"])
    link = fields(
        _document(row["claim_link"]), CLAIM_ASSOCIATION | {"runtime_sequence", "admission_sha256"}
    )
    require(
        link["schema"] == "vardr.worker-claim-association/3"
        and sequence64(link["runtime_sequence"], minimum=1) == row["runtime_sequence"]
        and row["state"] in ATTEMPT_STATES
        and all(
            link[key] == row[key] == runtime[key]
            for key in ("runtime_id", "runtime_sha256", "admission_sha256")
        ),
        "worker_claim_association_changed",
    )
    admission = _admission(runtime["admission_snapshot"])
    require(
        link["runner_id"] == admission.runner_id
        and link["enrollment_id"] == admission.enrollment_id
        and link["origin"] == admission.origin,
        "worker_claim_association_changed",
    )
    claim = con.execute("SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)).fetchone()
    run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    require(claim is not None and run is not None, "worker_claim_association_changed")
    # Journal.begin uses its existing human-readable JSON encoding here.
    profile = decoded(run["command_profile"].encode(), 32768)
    require(type(profile) is dict, "worker_claim_association_changed")
    require(
        (link["origin"], link["job_id"])
        == (claim["backend"], claim["job"])
        == (run["backend_url"], run["job_id"])
        and all(
            hash_value(link[key]) == claim[key] == profile.get(key)
            for key in ("plan_sha256", "case_sha256", "association_sha256")
        ),
        "worker_claim_association_changed",
    )
    if row["binding"] is None:
        require(
            row["state"] == "claim_prepared"
            or (
                row["state"] == "physical_retirement_observed"
                and row["retired_from_state"] == "claim_prepared"
            ),
            "worker_claim_association_changed",
        )
    else:
        binding = _document(row["binding"])
        check_binding(binding)
        require(
            all(
                binding[key] == link[key]
                for key in (
                    "runtime_id",
                    "runtime_sha256",
                    "admission_sha256",
                    "runtime_sequence",
                    "origin",
                    "runner_id",
                    "job_id",
                )
            )
            and (binding["contract_id"], binding["attempt_id"], binding["fence"])
            == (claim["contract"], claim["attempt"], claim["fence"]),
            "worker_claim_association_changed",
        )
    return link


class PersistentStore:
    """Selected-row, append-only v3 journal; finite v1/v2 tables stay intact."""

    def __init__(self, journal: Journal):
        self.journal = journal
        with journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("""CREATE TABLE IF NOT EXISTS managed_persistent_incarnations (
                runtime_id TEXT PRIMARY KEY, runtime_sha256 TEXT NOT NULL,
                admission_sha256 TEXT NOT NULL, admission_snapshot TEXT NOT NULL,
                max_attempts INTEGER, last_sequence INTEGER NOT NULL DEFAULT 0,
                history_head INTEGER, active_sequence INTEGER, state TEXT NOT NULL,
                retirement TEXT,
                CHECK(typeof(last_sequence)='integer' AND last_sequence BETWEEN 0 AND 9223372036854775807),
                CHECK(max_attempts IS NULL OR (typeof(max_attempts)='integer' AND max_attempts BETWEEN 1 AND 9223372036854775807)),
                CHECK((last_sequence=0 AND history_head IS NULL) OR (last_sequence>0 AND history_head IS NOT NULL AND typeof(history_head)='integer' AND history_head=last_sequence)),
                CHECK(active_sequence IS NULL OR (active_sequence=last_sequence AND last_sequence>0)),
                CHECK(state IN ('idle','active','retired')),
                CHECK((state='idle' AND active_sequence IS NULL AND retirement IS NULL) OR (state='active' AND active_sequence IS NOT NULL AND active_sequence=last_sequence AND retirement IS NULL) OR (state='retired' AND active_sequence IS NULL AND retirement IS NOT NULL)),
                FOREIGN KEY(runtime_id,history_head) REFERENCES managed_persistent_attempts(runtime_id,runtime_sequence),
                FOREIGN KEY(runtime_id,active_sequence) REFERENCES managed_persistent_attempts(runtime_id,runtime_sequence))""")
            con.execute("""CREATE TABLE IF NOT EXISTS managed_persistent_attempts (
                runtime_id TEXT NOT NULL, runtime_sequence INTEGER NOT NULL,
                previous_sequence INTEGER, runtime_sha256 TEXT NOT NULL,
                admission_sha256 TEXT NOT NULL, run_id TEXT NOT NULL UNIQUE,
                binding TEXT, claim_link TEXT NOT NULL, state TEXT NOT NULL,
                completion TEXT, native_done_sha256 TEXT, release_intent TEXT,
                release_ack TEXT, retirement TEXT, retired_from_state TEXT,
                PRIMARY KEY(runtime_id,runtime_sequence),
                CHECK(typeof(runtime_sequence)='integer' AND runtime_sequence BETWEEN 1 AND 9223372036854775807),
                CHECK((runtime_sequence=1 AND previous_sequence IS NULL) OR (runtime_sequence>1 AND previous_sequence IS NOT NULL AND typeof(previous_sequence)='integer' AND previous_sequence=runtime_sequence-1)),
                FOREIGN KEY(runtime_id) REFERENCES managed_persistent_incarnations(runtime_id),
                FOREIGN KEY(run_id) REFERENCES runs(run_id),
                FOREIGN KEY(runtime_id,previous_sequence) REFERENCES managed_persistent_attempts(runtime_id,runtime_sequence))""")
            con.execute(
                "CREATE INDEX IF NOT EXISTS managed_persistent_state ON managed_persistent_attempts(state,runtime_id,runtime_sequence)"
            )
            _indexes(con)

    def reserve_runtime(
        self,
        runtime_id: str,
        runtime_sha256: str,
        maximum: int | None,
        *,
        admission_sha256: str,
        admission_snapshot: dict,
    ) -> None:
        raw = encoded(admission_snapshot).decode()
        admission = _admission(raw)
        require(
            admission.runtime_id == runtime_id
            and admission.runtime_sha256 == runtime_sha256
            and getattr(admission, "admission_sha256", None) == admission_sha256
            and admission.max_attempts == maximum,
            "worker_persistent_admission",
        )
        try:
            with self.journal._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                con.execute(
                    "INSERT INTO managed_persistent_incarnations(runtime_id,runtime_sha256,admission_sha256,admission_snapshot,max_attempts,state) VALUES(?,?,?,?,?,'idle')",
                    (runtime_id, runtime_sha256, admission_sha256, raw, maximum),
                )
                parent(con, runtime_id)
        except sqlite3.IntegrityError:
            raise AuthorizationError("worker_runtime_already_invoked") from None

    def prepare_claim(
        self,
        con: sqlite3.Connection,
        run_id: str,
        *,
        runtime_id: str,
        runtime_sha256: str,
        runtime_sequence: int,
        runner_id: str,
        enrollment_id: str,
        admission_sha256: str,
    ) -> None:
        require(con.in_transaction, "worker_claim_transaction_required")
        _indexes(con)
        sequence = integer(runtime_sequence, 1, MAX_SEQUENCE)
        runtime = parent(con, runtime_id)
        admission = _admission(runtime["admission_snapshot"])
        require(
            runtime["state"] == "idle"
            and runtime["active_sequence"] is None
            and runtime["last_sequence"] == sequence - 1
            and runtime["runtime_sha256"] == runtime_sha256
            and runtime["admission_sha256"] == admission_sha256
            and admission.runner_id == runner_id
            and admission.enrollment_id == enrollment_id
            and (runtime["max_attempts"] is None or sequence <= runtime["max_attempts"]),
            "worker_sequence_not_next",
        )
        if runtime["last_sequence"]:
            previous = con.execute(
                "SELECT * FROM managed_persistent_attempts WHERE runtime_id=? AND runtime_sequence=?",
                (runtime_id, runtime["last_sequence"]),
            ).fetchone()
            require(previous is not None, "worker_persistent_history_changed")
            _validate_attempt(con, previous)
        claim = con.execute(
            "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
        ).fetchone()
        run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        require(
            claim is not None
            and run is not None
            and claim["state"] == "claim_in_flight"
            and all(claim[key] is None for key in ("issuer", "contract", "attempt", "fence"))
            and claim["consumption_sent"] == claim["consumption_acknowledged"] == 0
            and run["phase"] == Phase.CLAIMING.value
            and run["pid"] is None
            and run["artifact_sha256"] is None
            and run["last_event"] == "managed_claim_send_reserved",
            "worker_claim_source_not_prepared",
        )
        link = {
            "schema": "vardr.worker-claim-association/3",
            "runtime_id": runtime_id,
            "runtime_sha256": runtime_sha256,
            "admission_sha256": admission_sha256,
            "runtime_sequence": wire_sequence64(sequence, minimum=1),
            "runner_id": runner_id,
            "enrollment_id": enrollment_id,
            "origin": claim["backend"],
            "job_id": claim["job"],
            **{key: claim[key] for key in ("plan_sha256", "case_sha256", "association_sha256")},
        }
        con.execute(
            "INSERT INTO managed_persistent_attempts(runtime_id,runtime_sequence,previous_sequence,runtime_sha256,admission_sha256,run_id,claim_link,state) VALUES(?,?,?,?,?,?,?,'claim_prepared')",
            (
                runtime_id,
                sequence,
                None if sequence == 1 else sequence - 1,
                runtime_sha256,
                admission_sha256,
                run_id,
                encoded(link).decode(),
            ),
        )
        changed = con.execute(
            "UPDATE managed_persistent_incarnations SET last_sequence=?,history_head=?,active_sequence=?,state='active' WHERE runtime_id=? AND state='idle' AND active_sequence IS NULL AND last_sequence=? AND retirement IS NULL",
            (sequence, sequence, sequence, runtime_id, sequence - 1),
        ).rowcount
        require(changed == 1 and association(con, run_id) == link, "worker_sequence_not_next")

    def prepare_binding(self, run_id: str, binding: dict) -> None:
        check_binding(binding)
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            WorkerStore._claim(con, run_id, binding)
            link = association(con, run_id)
            require(
                link is not None
                and all(
                    binding[key] == link[key]
                    for key in (
                        "runtime_id",
                        "runtime_sha256",
                        "admission_sha256",
                        "runtime_sequence",
                        "origin",
                        "runner_id",
                        "job_id",
                    )
                ),
                "worker_claim_association_changed",
            )
            changed = con.execute(
                "UPDATE managed_persistent_attempts SET binding=?,state='bind_in_flight' WHERE run_id=? AND state='claim_prepared' AND binding IS NULL",
                (encoded(binding).decode(), run_id),
            ).rowcount
            require(changed == 1, "worker_runtime_binding_already_attempted")

    def acknowledge_binding(self, run_id: str, binding: dict, reply: dict) -> None:
        check_binding(binding)
        expected = {"schema": "vardr.worker-runtime-binding/3", **binding, "bound": True}
        require(encoded(reply) == encoded(expected), "worker_runtime_binding_ack")
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            WorkerStore._claim(con, run_id, binding)
            association(con, run_id)
            changed = con.execute(
                "UPDATE managed_persistent_attempts SET state='bound' WHERE run_id=? AND state='bind_in_flight' AND binding=?",
                (run_id, encoded(binding).decode()),
            ).rowcount
            require(changed == 1, "worker_runtime_binding_changed")

    def completion(self, run_id: str, acknowledgement: dict) -> None:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            result = con.execute(
                "SELECT * FROM managed_result_intents WHERE run_id=?", (run_id,)
            ).fetchone()
            run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            require(
                result is not None
                and result["state"] == "terminal"
                and result["outcome"] in {"completed", "failed"}
                and result["finish_sent"] == 1
                and run is not None
                and run["pid"] is None
                and run["failure_reason"] is None
                and run["last_event"] == "managed_completion_receipt"
                and run["phase"]
                == (Phase.DONE.value if result["outcome"] == "completed" else Phase.FAILED.value),
                "worker_normal_completion_required",
            )
            if con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='local_stop_requests'"
            ).fetchone():
                require(
                    not con.execute(
                        "SELECT 1 FROM local_stop_requests WHERE run_id=?", (run_id,)
                    ).fetchone(),
                    "worker_normal_completion_required",
                )
            if con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_stop_intents'"
            ).fetchone():
                require(
                    not con.execute(
                        "SELECT 1 FROM managed_stop_intents WHERE run_id=?", (run_id,)
                    ).fetchone(),
                    "worker_normal_completion_required",
                )
            check_completion(acknowledgement, dict(result))
            data = _artifact_bytes(
                Path(run["artifact_path"]), integer(run["artifact_size"], 1, 512000)
            )
            artifact = decoded(data, 512000)
            require(
                digest(data) == result["artifact_sha256"] == run["artifact_sha256"]
                and type(artifact) is dict
                and artifact.get("case_hash") == result["case_sha256"]
                and (
                    "error" not in artifact
                    or (
                        type(artifact["error"]) is str
                        and artifact["error"] != "execution_cancelled"
                    )
                ),
                "worker_normal_completion_required",
            )
            association(con, run_id)
            row = con.execute(
                "SELECT * FROM managed_persistent_attempts WHERE run_id=?", (run_id,)
            ).fetchone()
            require(
                row is not None and row["binding"] is not None, "worker_runtime_binding_missing"
            )
            binding = _document(row["binding"])
            require(
                all(acknowledgement[key] == binding[key] for key in BINDING),
                "worker_completion_binding",
            )
            changed = con.execute(
                "UPDATE managed_persistent_attempts SET completion=?,state='completion_acknowledged' WHERE run_id=? AND state='bound' AND completion IS NULL",
                (encoded(acknowledgement).decode(), run_id),
            ).rowcount
            require(changed == 1, "worker_completion_already_attempted")

    def done(self, run_id: str, native_done_sha256: str) -> None:
        hash_value(native_done_sha256)
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            association(con, run_id)
            changed = con.execute(
                "UPDATE managed_persistent_attempts SET native_done_sha256=?,state='done_acknowledged' WHERE run_id=? AND state='completion_acknowledged' AND native_done_sha256 IS NULL",
                (native_done_sha256, run_id),
            ).rowcount
            require(changed == 1, "worker_done_already_attempted")

    def prepare_release(self, run_id: str) -> dict:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            association(con, run_id)
            row = con.execute(
                "SELECT * FROM managed_persistent_attempts WHERE run_id=?", (run_id,)
            ).fetchone()
            require(row is not None and row["state"] == "done_acknowledged", "worker_done_required")
            public = release_document(row)
            changed = con.execute(
                "UPDATE managed_persistent_attempts SET release_intent=?,state='release_in_flight' WHERE run_id=? AND state='done_acknowledged' AND release_intent IS NULL",
                (encoded(public).decode(), run_id),
            ).rowcount
            require(changed == 1, "worker_release_already_attempted")
            return public

    def acknowledge_release(self, run_id: str, acknowledgement: dict) -> None:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            association(con, run_id)
            row = con.execute(
                "SELECT * FROM managed_persistent_attempts WHERE run_id=?", (run_id,)
            ).fetchone()
            require(
                row is not None and row["state"] == "release_in_flight", "worker_release_not_sent"
            )
            expected = release_document(row)
            require(
                encoded(expected).decode() == row["release_intent"]
                and encoded(acknowledgement) == encoded(expected),
                "worker_release_ack",
            )
            changed = con.execute(
                "UPDATE managed_persistent_incarnations SET active_sequence=NULL,state='idle' WHERE runtime_id=? AND runtime_sha256=? AND admission_sha256=? AND active_sequence=? AND last_sequence=? AND state='active' AND retirement IS NULL",
                (
                    row["runtime_id"],
                    row["runtime_sha256"],
                    row["admission_sha256"],
                    row["runtime_sequence"],
                    row["runtime_sequence"],
                ),
            ).rowcount
            require(changed == 1, "worker_sequence_projection_changed")
            con.execute(
                "UPDATE managed_persistent_attempts SET release_ack=?,state='released' WHERE run_id=?",
                (encoded(acknowledgement).decode(), run_id),
            )
            changed = con.execute(
                "UPDATE managed_claim_intents SET state='persistent_released' WHERE run_id=? AND state='consume_acknowledged'",
                (run_id,),
            ).rowcount
            require(changed == 1, "worker_persistent_claim_changed")
            _indexes(con)


def release_document(row) -> dict:
    binding = _document(row["binding"])
    check_binding(binding)
    completion = fields(
        _document(row["completion"]),
        BINDING | {"schema", "receipt_sha256", "outcome", "capacity_reserved"},
    )
    require(
        completion["schema"] == "vardr.managed-completion/1"
        and completion["outcome"] in {"completed", "failed"}
        and completion["capacity_reserved"] is False
        and encoded({key: completion[key] for key in BINDING})
        == encoded({key: binding[key] for key in BINDING}),
        "worker_normal_completion_required",
    )
    hash_value(completion["receipt_sha256"])
    public = {
        "schema": "vardr.worker-idle-release/2",
        **{
            key: binding[key]
            for key in ("runtime_id", "runtime_sha256", "admission_sha256", "runtime_sequence")
        },
        "binding": {key: binding[key] for key in BINDING},
        "terminal_receipt_sha256": digest(encoded(completion)),
        "native_done_sha256": hash_value(row["native_done_sha256"]),
        "released": True,
    }
    public["receipt_sha256"] = digest(encoded(public))
    return public


def retirement_snapshot(con: sqlite3.Connection, run_id: str, link: dict, receipt: dict) -> dict:
    """Recheck the original-key observation on every explicit retirement audit."""
    from .observations import validate

    claim = con.execute("SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)).fetchone()
    observed = con.execute(
        "SELECT snapshot FROM managed_claim_observations WHERE run_id=?", (run_id,)
    ).fetchone()
    require(claim is not None and observed is not None, "worker_retirement_observation_missing")
    snapshot = _document(observed["snapshot"], 16384)
    root = {
        key: link[key]
        for key in (
            "origin",
            "job_id",
            "runner_id",
            "plan_sha256",
            "case_sha256",
            "association_sha256",
        )
    }
    validate(snapshot, root, dict(claim), link)
    require(
        snapshot["schema"] == "vardr.managed-claim-observation/4"
        and encoded(snapshot["runtime_retirement"]) == encoded(receipt),
        "worker_retirement_binding",
    )
    return snapshot


def retire_incarnation_observation(
    con: sqlite3.Connection, run_id: str, runtime_retirement: dict
) -> None:
    """Retain validated physical retirement without inventing a selected job ACK."""
    require(con.in_transaction, "worker_retirement_transaction_required")
    link = association(con, run_id)
    require(link is not None, "worker_retirement_binding")
    assert link is not None
    receipt = fields(
        runtime_retirement,
        {
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
        },
    )
    require(
        receipt["schema"] == "vardr.worker-retirement/3"
        and receipt["retired"] is True
        and all(
            receipt[key] == link[key]
            for key in (
                "runtime_id",
                "runtime_sha256",
                "admission_sha256",
                "origin",
                "runner_id",
                "enrollment_id",
            )
        )
        and receipt["receipt_sha256"]
        == digest(
            encoded({key: value for key, value in receipt.items() if key != "receipt_sha256"})
        ),
        "worker_retirement_binding",
    )
    last = sequence64(receipt["last_sequence"])
    selected = sequence64(link["runtime_sequence"], minimum=1)
    if receipt["runtime_sequence"] is not None:
        sequence64(receipt["runtime_sequence"], minimum=1)
    hash_value(receipt["report_sha256"])
    claim = con.execute("SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)).fetchone()
    row = con.execute(
        "SELECT * FROM managed_persistent_attempts WHERE run_id=?", (run_id,)
    ).fetchone()
    require(claim is not None and row is not None, "worker_retirement_binding")
    snapshot = retirement_snapshot(con, run_id, link, receipt)
    selected_claim = snapshot["claim"]
    if selected_claim is None:
        require(claim["contract"] is None and last < selected, "worker_retirement_binding")
    elif receipt["runtime_sequence"] == link["runtime_sequence"]:
        binding = fields(receipt["binding"], BINDING)
        integer(binding["fence"], 1)
        hash_value(binding["contract_sha256"])
        expected = {
            **{key: link[key] for key in ("origin", "job_id", "runner_id")},
            **{
                key: selected_claim[key]
                for key in ("contract_id", "attempt_id", "fence", "contract_sha256")
            },
        }
        require(encoded(binding) == encoded(expected), "worker_retirement_binding")
        if claim["contract"] is not None:
            require(
                (binding["contract_id"], binding["attempt_id"], binding["fence"])
                == (claim["contract"], claim["attempt"], claim["fence"]),
                "worker_retirement_binding",
            )
        if row["binding"] is not None:
            stored = _document(row["binding"])
            check_binding(stored)
            require(
                encoded(binding) == encoded({key: stored[key] for key in BINDING}),
                "worker_retirement_binding",
            )
    # A later incarnation terminal belongs to its own selected binding. Full /4
    # validation above checks it independently; it never replaces this job's
    # claim, result or stop receipt, nor authorizes another claim.
    canonical = encoded(receipt).decode()
    require(
        row["retirement"] is None or row["retirement"] == canonical,
        "worker_retirement_changed",
    )
    con.execute(
        "UPDATE managed_persistent_attempts SET retired_from_state=CASE WHEN retirement IS NULL THEN state ELSE retired_from_state END,state='physical_retirement_observed',retirement=? WHERE run_id=?",
        (canonical, run_id),
    )
    changed = con.execute(
        "UPDATE managed_persistent_incarnations SET active_sequence=NULL,state='retired',retirement=? WHERE runtime_id=? AND runtime_sha256=? AND admission_sha256=? AND (retirement IS NULL OR retirement=?)",
        (
            canonical,
            link["runtime_id"],
            link["runtime_sha256"],
            link["admission_sha256"],
            canonical,
        ),
    ).rowcount
    require(changed == 1, "worker_retirement_changed")


def _validate_attempt(con: sqlite3.Connection, row: sqlite3.Row) -> None:
    link = association(con, row["run_id"])
    require(link is not None, "worker_claim_association_missing")
    assert link is not None
    stage = (
        row["retired_from_state"]
        if row["state"] == "physical_retirement_observed"
        else row["state"]
    )
    levels = {
        "claim_prepared": 0,
        "bind_in_flight": 1,
        "bound": 2,
        "completion_acknowledged": 3,
        "done_acknowledged": 4,
        "release_in_flight": 5,
        "released": 6,
    }
    require(stage in levels, "worker_persistent_state")
    level = levels[stage]
    for key, minimum in (
        ("binding", 1),
        ("completion", 3),
        ("native_done_sha256", 4),
        ("release_intent", 5),
        ("release_ack", 6),
    ):
        require((row[key] is not None) == (level >= minimum), "worker_persistent_state")
    for key in ("binding", "completion", "release_intent", "release_ack"):
        if row[key] is not None:
            _document(row[key])
    if level >= 3:
        result = con.execute(
            "SELECT * FROM managed_result_intents WHERE run_id=?", (row["run_id"],)
        ).fetchone()
        run = con.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
        require(
            result is not None
            and result["state"] == "terminal"
            and result["outcome"] in {"completed", "failed"}
            and run is not None
            and run["pid"] is None
            and run["failure_reason"] is None
            and run["last_event"] == "managed_completion_receipt"
            and run["phase"]
            == (Phase.DONE.value if result["outcome"] == "completed" else Phase.FAILED.value),
            "worker_normal_completion_required",
        )
        check_completion(_document(row["completion"]), dict(result))
    if level >= 4:
        hash_value(row["native_done_sha256"])
    if level >= 5:
        require(
            row["release_intent"] == encoded(release_document(row)).decode(),
            "worker_release_intent_changed",
        )
    if level >= 6:
        require(
            row["release_ack"] == encoded(release_document(row)).decode(),
            "worker_release_ack_missing",
        )
    if row["state"] == "physical_retirement_observed":
        runtime = parent(con, row["runtime_id"])
        require(
            row["retirement"] is not None and row["retirement"] == runtime["retirement"],
            "worker_retirement_missing",
        )
        retirement_snapshot(con, row["run_id"], link, _document(row["retirement"]))


def persistent_holds(con: sqlite3.Connection, *, full: bool = False) -> int:
    """Pure audit: full at startup/explicit inspection, selected unresolved rows thereafter.

    A caller must complete the existing full legacy audit at startup as well.
    Managed closed records remain immutable; partial indexes avoid materializing
    healthy history on each idle poll. A nonzero count is conservative and may
    represent more than one fence for the same job; it grants no recovery right.
    """
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {"managed_persistent_incarnations", "managed_persistent_attempts"}
    if not required.intersection(tables):
        return 0
    require(required <= tables, "worker_persistent_schema_incomplete")
    held: set[tuple] = set()
    parents = con.execute(
        "SELECT runtime_id FROM managed_persistent_incarnations"
        + ("" if full else " WHERE state!='retired'")
    )
    for selected in parents:
        runtime = parent(con, selected["runtime_id"])
        if runtime["last_sequence"]:
            head = con.execute(
                "SELECT * FROM managed_persistent_attempts WHERE runtime_id=? AND runtime_sequence=?",
                (runtime["runtime_id"], runtime["last_sequence"]),
            ).fetchone()
            require(head is not None, "worker_persistent_history_changed")
            _validate_attempt(con, head)
        if runtime["active_sequence"] is not None:
            held.add((runtime["runtime_id"], runtime["active_sequence"]))
    rows = con.execute(
        "SELECT * FROM managed_persistent_attempts"
        + ("" if full else " WHERE state NOT IN ('released','physical_retirement_observed')")
    )
    for row in rows:
        _validate_attempt(con, row)
        if row["state"] not in {"released", "physical_retirement_observed"}:
            held.add((row["runtime_id"], row["runtime_sequence"]))
    generic = 0
    for table, predicate in _PENDING.items():
        if table in tables:
            # All identifiers and predicates are fixed source constants.
            generic += con.execute(f"SELECT count(*) FROM {table} WHERE {predicate}").fetchone()[0]
    return len(held) + generic
