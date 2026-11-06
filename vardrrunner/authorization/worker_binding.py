"""One-shot worker runtime bindings in the existing journal; no execution rights."""

from __future__ import annotations

import json
import sqlite3

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
from .results import BINDING, check_completion
from .worker_admission import _uuid, hash_value

RUNTIME_BINDING = BINDING | {"runtime_id", "runtime_sha256"}
SEQUENCE_BINDING = RUNTIME_BINDING | {"runtime_sequence"}
CLAIM_ASSOCIATION = {
    "schema",
    "runtime_id",
    "runtime_sha256",
    "enrollment_id",
    "origin",
    "job_id",
    "runner_id",
    "plan_sha256",
    "case_sha256",
    "association_sha256",
}


def claim_association(con: sqlite3.Connection, run_id: str) -> dict | None:
    """Pure read of an original durable link; legacy absence never upgrades it."""
    table = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_runtime_bindings'"
    ).fetchone()
    rows = []
    if table is not None and "claim_link" in {
        row[1] for row in con.execute("PRAGMA table_info(managed_runtime_bindings)")
    }:
        rows.extend(
            con.execute(
                "SELECT * FROM managed_runtime_bindings WHERE run_id=?", (run_id,)
            ).fetchall()
        )
    if con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_worker_attempts'"
    ).fetchone():
        rows.extend(
            con.execute(
                "SELECT * FROM managed_worker_attempts WHERE run_id=?", (run_id,)
            ).fetchall()
        )
    if not rows:
        return None
    require(len(rows) == 1, "worker_claim_association_changed")
    row = rows[0]
    sequenced = "runtime_sequence" in row.keys()
    if row["claim_link"] is None:
        require(row["state"] != "claim_prepared", "worker_claim_association_missing")
        return None
    require(type(row["claim_link"]) is str, "worker_claim_association_changed")
    link = fields(
        decoded(row["claim_link"].encode(), 8192),
        CLAIM_ASSOCIATION | ({"runtime_sequence"} if sequenced else set()),
    )
    require(
        link["schema"]
        == ("vardr.worker-claim-association/2" if sequenced else "vardr.worker-claim-association/1")
        and encoded(link).decode() == row["claim_link"],
        "worker_claim_association_changed",
    )
    if sequenced:
        integer(link["runtime_sequence"], 1, 32)
        require(
            link["runtime_sequence"] == row["runtime_sequence"], "worker_claim_association_changed"
        )
    _uuid(link["runtime_id"])
    for key in ("runtime_sha256", "plan_sha256", "case_sha256", "association_sha256"):
        hash_value(link[key])
    for key in ("runner_id", "job_id", "enrollment_id"):
        identifier(link[key])
    require(
        type(link["origin"]) is str and normalize_backend_url(link["origin"]) == link["origin"],
        "worker_claim_association_changed",
    )
    claim = con.execute("SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)).fetchone()
    run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    require(claim is not None and run is not None, "worker_claim_association_changed")
    profile = decoded(run["command_profile"].encode(), 32768)
    require(
        type(profile) is dict
        and row["runtime_id"] == link["runtime_id"]
        and row["runtime_sha256"] == link["runtime_sha256"]
        and row["state"]
        in (
            {
                "claim_prepared",
                "bind_in_flight",
                "bound",
                "completion_acknowledged",
                "done_acknowledged",
                "release_in_flight",
                "released",
                "physical_retirement_observed",
            }
            if sequenced
            else {"claim_prepared", "bind_in_flight", "bound"}
        )
        and (link["origin"], link["job_id"])
        == (claim["backend"], claim["job"])
        == (run["backend_url"], run["job_id"])
        and all(
            link[key] == claim[key] == profile.get(key)
            for key in ("plan_sha256", "case_sha256", "association_sha256")
        ),
        "worker_claim_association_changed",
    )
    if row["binding"] is None:
        require(
            row["state"] == "claim_prepared"
            or (
                sequenced
                and row["state"] == "physical_retirement_observed"
                and row["retired_from_state"] == "claim_prepared"
            ),
            "worker_claim_association_changed",
        )
    else:
        binding = fields(
            decoded(row["binding"].encode(), 8192),
            SEQUENCE_BINDING if sequenced else RUNTIME_BINDING,
        )
        require(
            all(
                binding[key] == link[key]
                for key in ("runtime_id", "runtime_sha256", "origin", "job_id", "runner_id")
            )
            and (binding["contract_id"], binding["attempt_id"], binding["fence"])
            == (claim["contract"], claim["attempt"], claim["fence"]),
            "worker_claim_association_changed",
        )
        if sequenced:
            integer(binding["runtime_sequence"], 1, 32)
            require(
                binding["runtime_sequence"] == link["runtime_sequence"],
                "worker_claim_association_changed",
            )
    return link


def check_binding_ack(reply: dict, binding: dict) -> None:
    sequenced = "runtime_sequence" in binding
    fields(reply, (SEQUENCE_BINDING if sequenced else RUNTIME_BINDING) | {"schema", "bound"})
    if sequenced:
        integer(reply["runtime_sequence"], 1, 32)
    integer(reply["fence"], 1)
    require(
        reply
        == {
            "schema": "vardr.worker-runtime-binding/2"
            if sequenced
            else "vardr.worker-runtime-binding/1",
            **binding,
            "bound": True,
        }
        and reply["bound"] is True,
        "worker_runtime_binding_ack",
    )


class WorkerStore:
    """Permanent per-admission invocation and bind-send tombstones, never tokens."""

    def __init__(self, journal: Journal):
        self.journal = journal
        with journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("""CREATE TABLE IF NOT EXISTS managed_runtime_bindings (
                runtime_id TEXT PRIMARY KEY, runtime_sha256 TEXT NOT NULL,
                run_id TEXT UNIQUE, binding TEXT, state TEXT NOT NULL, claim_link TEXT)""")
            if "claim_link" not in {
                row[1] for row in con.execute("PRAGMA table_info(managed_runtime_bindings)")
            }:
                con.execute("ALTER TABLE managed_runtime_bindings ADD COLUMN claim_link TEXT")

    def prepare_claim(
        self,
        con: sqlite3.Connection,
        run_id: str,
        *,
        runtime_id: str,
        runtime_sha256: str,
        runner_id: str,
        enrollment_id: str,
    ) -> None:
        """Link before the claim marker's SAME transaction commits; no HTTP/IO."""
        require(con.in_transaction, "worker_claim_transaction_required")
        _uuid(runtime_id)
        hash_value(runtime_sha256)
        identifier(runner_id)
        identifier(enrollment_id)
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
            and run["last_event"] == "managed_claim_send_reserved"
            and run["pid"] is None
            and run["artifact_sha256"] is None,
            "worker_claim_source_not_prepared",
        )
        link = {
            "schema": "vardr.worker-claim-association/1",
            "runtime_id": runtime_id,
            "runtime_sha256": runtime_sha256,
            "enrollment_id": enrollment_id,
            "runner_id": runner_id,
            "origin": claim["backend"],
            "job_id": claim["job"],
            **{key: claim[key] for key in ("plan_sha256", "case_sha256", "association_sha256")},
        }
        changed = con.execute(
            "UPDATE managed_runtime_bindings SET run_id=?,claim_link=?,state='claim_prepared' WHERE runtime_id=? AND runtime_sha256=? AND state='waiting' AND run_id IS NULL AND binding IS NULL AND claim_link IS NULL",
            (run_id, encoded(link).decode(), runtime_id, runtime_sha256),
        ).rowcount
        require(changed == 1, "worker_claim_association_already_attempted")
        require(claim_association(con, run_id) == link, "worker_claim_association_changed")

    def reserve_runtime(self, runtime_id: str, runtime_sha256: str) -> None:
        """A fresh process cannot reuse an admitted incarnation to claim again."""
        try:
            with self.journal._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                con.execute(
                    "INSERT INTO managed_runtime_bindings (runtime_id,runtime_sha256,state) VALUES (?,?,'waiting')",
                    (runtime_id, runtime_sha256),
                )
        except sqlite3.IntegrityError:
            raise AuthorizationError("worker_runtime_already_invoked") from None

    @staticmethod
    def _claim(con: sqlite3.Connection, run_id: str, binding: dict) -> None:
        claim = con.execute(
            "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
        ).fetchone()
        run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        require(
            claim is not None
            and run is not None
            and claim["state"] == "consume_in_flight"
            and claim["consumption_sent"] == 1
            and claim["consumption_acknowledged"] == 0
            and (claim["contract"], claim["attempt"], claim["fence"])
            == (binding["contract_id"], binding["attempt_id"], binding["fence"])
            and (run["backend_url"], run["job_id"]) == (binding["origin"], binding["job_id"])
            and run["phase"] == Phase.EXECUTING.value
            and run["artifact_sha256"] is None,
            "worker_binding_not_consuming",
        )

    def prepare_binding(self, run_id: str, binding: dict) -> None:
        fields(binding, RUNTIME_BINDING)
        try:
            with self.journal._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                invocation = con.execute(
                    "SELECT * FROM managed_runtime_bindings WHERE runtime_id=?",
                    (binding["runtime_id"],),
                ).fetchone()
                require(
                    invocation is not None
                    and invocation["runtime_sha256"] == binding["runtime_sha256"],
                    "worker_runtime_not_invoked",
                )
                self._claim(con, run_id, binding)
                if invocation["state"] == "claim_prepared":
                    link = claim_association(con, run_id)
                    require(
                        link is not None
                        and all(
                            link[key] == binding[key]
                            for key in (
                                "runtime_id",
                                "runtime_sha256",
                                "origin",
                                "job_id",
                                "runner_id",
                            )
                        ),
                        "worker_claim_association_changed",
                    )
                    changed = con.execute(
                        "UPDATE managed_runtime_bindings SET binding=?,state='bind_in_flight' WHERE runtime_id=? AND run_id=? AND state='claim_prepared'",
                        (encoded(binding).decode(), binding["runtime_id"], run_id),
                    ).rowcount
                else:
                    changed = con.execute(
                        "UPDATE managed_runtime_bindings SET run_id=?,binding=?,state='bind_in_flight' WHERE runtime_id=? AND state='waiting' AND run_id IS NULL AND claim_link IS NULL",
                        (run_id, encoded(binding).decode(), binding["runtime_id"]),
                    ).rowcount
                require(changed == 1, "worker_runtime_binding_already_attempted")
        except sqlite3.IntegrityError:
            raise AuthorizationError("worker_runtime_binding_already_attempted") from None

    def acknowledge_binding(self, run_id: str, binding: dict, reply: dict) -> None:
        check_binding_ack(reply, binding)
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            self._claim(con, run_id, binding)
            changed = con.execute(
                "UPDATE managed_runtime_bindings SET state='bound' WHERE run_id=? AND binding=? AND state='bind_in_flight'",
                (run_id, encoded(binding).decode()),
            ).rowcount
            require(changed == 1, "worker_runtime_binding_changed")

    def get(self, run_id: str) -> dict:
        with self.journal._connection() as con:
            row = con.execute(
                "SELECT * FROM managed_runtime_bindings WHERE run_id=?", (run_id,)
            ).fetchone()
        require(row is not None, "worker_runtime_binding_missing")
        result = dict(row)
        fields(json.loads(result["binding"]), RUNTIME_BINDING)
        return result


class SequenceStore:
    """Append-only v2 attempt associations and one active projection; no tokens."""

    def __init__(self, journal: Journal):
        self.journal = journal
        with journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("""CREATE TABLE IF NOT EXISTS managed_worker_incarnations (
                runtime_id TEXT PRIMARY KEY, runtime_sha256 TEXT NOT NULL,
                max_attempts INTEGER NOT NULL, last_sequence INTEGER NOT NULL,
                active_sequence INTEGER, state TEXT NOT NULL, retirement TEXT)""")
            con.execute("""CREATE TABLE IF NOT EXISTS managed_worker_attempts (
                runtime_id TEXT NOT NULL, runtime_sequence INTEGER NOT NULL,
                runtime_sha256 TEXT NOT NULL, run_id TEXT NOT NULL UNIQUE,
                binding TEXT, claim_link TEXT NOT NULL, state TEXT NOT NULL,
                completion TEXT, native_done_sha256 TEXT, release_intent TEXT,
                release_ack TEXT, retirement TEXT, retired_from_state TEXT,
                PRIMARY KEY(runtime_id,runtime_sequence))""")

    def reserve_runtime(self, runtime_id: str, runtime_sha256: str, maximum: int) -> None:
        _uuid(runtime_id)
        hash_value(runtime_sha256)
        integer(maximum, 1, 32)
        try:
            with self.journal._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                con.execute(
                    "INSERT INTO managed_worker_incarnations (runtime_id,runtime_sha256,max_attempts,last_sequence,state) VALUES (?,?,?,0,'idle')",
                    (runtime_id, runtime_sha256, maximum),
                )
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
    ) -> None:
        require(con.in_transaction, "worker_claim_transaction_required")
        _uuid(runtime_id)
        hash_value(runtime_sha256)
        integer(runtime_sequence, 1, 32)
        identifier(runner_id)
        identifier(enrollment_id)
        claim = con.execute(
            "SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)
        ).fetchone()
        run = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        require(
            claim is not None
            and run is not None
            and claim["state"] == "claim_in_flight"
            and all(claim[k] is None for k in ("issuer", "contract", "attempt", "fence"))
            and claim["consumption_sent"] == claim["consumption_acknowledged"] == 0
            and run["phase"] == Phase.CLAIMING.value
            and run["pid"] is None
            and run["artifact_sha256"] is None
            and run["last_event"] == "managed_claim_send_reserved",
            "worker_claim_source_not_prepared",
        )
        link = {
            "schema": "vardr.worker-claim-association/2",
            "runtime_id": runtime_id,
            "runtime_sha256": runtime_sha256,
            "runtime_sequence": runtime_sequence,
            "runner_id": runner_id,
            "enrollment_id": enrollment_id,
            "origin": claim["backend"],
            "job_id": claim["job"],
            **{k: claim[k] for k in ("plan_sha256", "case_sha256", "association_sha256")},
        }
        changed = con.execute(
            "UPDATE managed_worker_incarnations SET active_sequence=?,last_sequence=?,state='active' WHERE runtime_id=? AND runtime_sha256=? AND state='idle' AND active_sequence IS NULL AND last_sequence=? AND max_attempts>=? AND retirement IS NULL",
            (
                runtime_sequence,
                runtime_sequence,
                runtime_id,
                runtime_sha256,
                runtime_sequence - 1,
                runtime_sequence,
            ),
        ).rowcount
        require(changed == 1, "worker_sequence_not_next")
        con.execute(
            "INSERT INTO managed_worker_attempts (runtime_id,runtime_sha256,runtime_sequence,run_id,claim_link,state) VALUES (?,?,?,?,?,'claim_prepared')",
            (runtime_id, runtime_sha256, runtime_sequence, run_id, encoded(link).decode()),
        )
        require(claim_association(con, run_id) == link, "worker_claim_association_changed")

    def prepare_binding(self, run_id: str, binding: dict) -> None:
        fields(binding, SEQUENCE_BINDING)
        integer(binding["runtime_sequence"], 1, 32)
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            WorkerStore._claim(con, run_id, binding)
            link = claim_association(con, run_id)
            require(
                link is not None
                and all(
                    link[k] == binding[k]
                    for k in (
                        "runtime_id",
                        "runtime_sha256",
                        "runtime_sequence",
                        "runner_id",
                        "origin",
                        "job_id",
                    )
                ),
                "worker_claim_association_changed",
            )
            changed = con.execute(
                "UPDATE managed_worker_attempts SET binding=?,state='bind_in_flight' WHERE run_id=? AND state='claim_prepared' AND binding IS NULL",
                (encoded(binding).decode(), run_id),
            ).rowcount
            require(changed == 1, "worker_runtime_binding_already_attempted")

    def acknowledge_binding(self, run_id: str, binding: dict, reply: dict) -> None:
        check_binding_ack(reply, binding)
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            WorkerStore._claim(con, run_id, binding)
            changed = con.execute(
                "UPDATE managed_worker_attempts SET state='bound' WHERE run_id=? AND binding=? AND state='bind_in_flight'",
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
                and result["outcome"] == "completed"
                and result["finish_sent"] == 1
                and run is not None
                and run["phase"] == Phase.DONE.value
                and run["pid"] is None,
                "worker_healthy_completion_required",
            )
            check_completion(acknowledgement, dict(result))
            attempt = con.execute(
                "SELECT * FROM managed_worker_attempts WHERE run_id=?", (run_id,)
            ).fetchone()
            require(
                attempt is not None and attempt["binding"] is not None,
                "worker_runtime_binding_missing",
            )
            binding = decoded(attempt["binding"].encode())
            require(
                all(acknowledgement[k] == binding[k] for k in BINDING), "worker_completion_binding"
            )
            changed = con.execute(
                "UPDATE managed_worker_attempts SET completion=?,state='completion_acknowledged' WHERE run_id=? AND state='bound' AND completion IS NULL",
                (encoded(acknowledgement).decode(), run_id),
            ).rowcount
            require(changed == 1, "worker_completion_already_attempted")

    def done(self, run_id: str, native_done_sha256: str) -> None:
        hash_value(native_done_sha256)
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            changed = con.execute(
                "UPDATE managed_worker_attempts SET native_done_sha256=?,state='done_acknowledged' WHERE run_id=? AND state='completion_acknowledged' AND native_done_sha256 IS NULL",
                (native_done_sha256, run_id),
            ).rowcount
            require(changed == 1, "worker_done_already_attempted")

    def prepare_release(self, run_id: str) -> dict:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT * FROM managed_worker_attempts WHERE run_id=?", (run_id,)
            ).fetchone()
            require(row is not None and row["state"] == "done_acknowledged", "worker_done_required")
            public = _release_document(row)
            changed = con.execute(
                "UPDATE managed_worker_attempts SET release_intent=?,state='release_in_flight' WHERE run_id=? AND state='done_acknowledged' AND release_intent IS NULL",
                (encoded(public).decode(), run_id),
            ).rowcount
            require(changed == 1, "worker_release_already_attempted")
            return public

    def acknowledge_release(self, run_id: str, acknowledgement: dict) -> None:
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT * FROM managed_worker_attempts WHERE run_id=?", (run_id,)
            ).fetchone()
            require(
                row is not None and row["state"] == "release_in_flight", "worker_release_not_sent"
            )
            expected = decoded(row["release_intent"].encode())
            fields(acknowledgement, set(expected))
            integer(acknowledgement["runtime_sequence"], 1, 32)
            require(
                encoded(acknowledgement) == encoded(expected)
                and acknowledgement["released"] is True,
                "worker_release_ack",
            )
            changed = con.execute(
                "UPDATE managed_worker_incarnations SET active_sequence=NULL,state='idle' WHERE runtime_id=? AND runtime_sha256=? AND active_sequence=? AND last_sequence=? AND state='active' AND retirement IS NULL",
                (
                    row["runtime_id"],
                    row["runtime_sha256"],
                    row["runtime_sequence"],
                    row["runtime_sequence"],
                ),
            ).rowcount
            require(changed == 1, "worker_sequence_projection_changed")
            con.execute(
                "UPDATE managed_worker_attempts SET release_ack=?,state='released' WHERE run_id=?",
                (encoded(acknowledgement).decode(), run_id),
            )


def _release_document(row) -> dict:
    binding = fields(decoded(row["binding"].encode()), SEQUENCE_BINDING)
    completion = fields(
        decoded(row["completion"].encode()),
        BINDING | {"schema", "receipt_sha256", "outcome", "capacity_reserved"},
    )
    require(
        completion["schema"] == "vardr.managed-completion/1"
        and completion["outcome"] == "completed"
        and completion["capacity_reserved"] is False
        and all(completion[k] == binding[k] for k in BINDING),
        "worker_healthy_completion_required",
    )
    hash_value(completion["receipt_sha256"])
    public = {
        "schema": "vardr.worker-idle-release/1",
        **{k: binding[k] for k in ("runtime_id", "runtime_sha256", "runtime_sequence")},
        "binding": {k: binding[k] for k in BINDING},
        "terminal_receipt_sha256": digest(encoded(completion)),
        "native_done_sha256": hash_value(row["native_done_sha256"]),
        "released": True,
    }
    public["receipt_sha256"] = digest(encoded(public))
    return public


def _retirement_snapshot(
    con: sqlite3.Connection, run_id: str, association: dict, receipt: dict
) -> dict:
    """Revalidate retained server evidence on every audit; never create proof."""
    from .observations import validate

    claim = con.execute("SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)).fetchone()
    observed = con.execute(
        "SELECT snapshot FROM managed_claim_observations WHERE run_id=?", (run_id,)
    ).fetchone()
    require(claim is not None and observed is not None, "worker_retirement_observation_missing")
    snapshot = decoded(observed["snapshot"].encode())
    root = {
        key: association[key]
        for key in (
            "origin",
            "job_id",
            "runner_id",
            "plan_sha256",
            "case_sha256",
            "association_sha256",
        )
    }
    validate(snapshot, root, dict(claim), association)
    require(
        snapshot["schema"] == "vardr.managed-claim-observation/3"
        and encoded(snapshot["runtime_retirement"]) == encoded(receipt),
        "worker_retirement_binding",
    )
    return snapshot


def sequence_holds(con: sqlite3.Connection) -> int:
    """Pure conservative v2 hold audit, including completed-but-unreleased jobs."""
    tables = {
        row[0]
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('managed_worker_incarnations','managed_worker_attempts')"
        )
    }
    if not tables:
        return 0
    require(len(tables) == 2, "worker_sequence_schema_incomplete")
    attempts = con.execute("SELECT * FROM managed_worker_attempts").fetchall()
    incarnations = {
        row["runtime_id"]: row for row in con.execute("SELECT * FROM managed_worker_incarnations")
    }
    holds = set()
    histories: dict[str, list[sqlite3.Row]] = {}
    for row in attempts:
        histories.setdefault(row["runtime_id"], []).append(row)
        attempt_key = (row["runtime_id"], row["runtime_sequence"])
        incarnation = incarnations.get(row["runtime_id"])
        require(
            incarnation is not None and incarnation["runtime_sha256"] == row["runtime_sha256"],
            "worker_sequence_projection_changed",
        )
        assert incarnation is not None
        association = claim_association(con, row["run_id"])
        require(
            association is not None and association["schema"] == "vardr.worker-claim-association/2",
            "worker_claim_association_missing",
        )
        assert association is not None
        stage = (
            row["retired_from_state"]
            if row["state"] == "physical_retirement_observed"
            else row["state"]
        )
        stages = {
            "claim_prepared": 0,
            "bind_in_flight": 1,
            "bound": 2,
            "completion_acknowledged": 3,
            "done_acknowledged": 4,
            "release_in_flight": 5,
            "released": 6,
        }
        require(stage in stages, "worker_sequence_state")
        level = stages[stage]
        for key, minimum in (
            ("binding", 1),
            ("completion", 3),
            ("native_done_sha256", 4),
            ("release_intent", 5),
            ("release_ack", 6),
        ):
            require((row[key] is not None) == (level >= minimum), "worker_sequence_state")
        for key in ("binding", "completion", "release_intent", "release_ack"):
            if row[key] is not None:
                require(
                    encoded(decoded(row[key].encode())).decode() == row[key],
                    "worker_sequence_noncanonical",
                )
        if level >= 3:
            result = con.execute(
                "SELECT * FROM managed_result_intents WHERE run_id=?", (row["run_id"],)
            ).fetchone()
            run = con.execute("SELECT * FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
            require(
                result is not None
                and result["state"] == "terminal"
                and result["outcome"] == "completed"
                and run is not None
                and run["phase"] == Phase.DONE.value
                and run["pid"] is None,
                "worker_healthy_completion_required",
            )
            check_completion(decoded(row["completion"].encode()), dict(result))
        if level >= 4:
            hash_value(row["native_done_sha256"])
        if level >= 5:
            require(
                row["release_intent"] == encoded(_release_document(row)).decode(),
                "worker_release_intent_changed",
            )
        if level >= 6:
            require(
                row["release_ack"] == encoded(_release_document(row)).decode(),
                "worker_release_ack_missing",
            )
        if row["state"] == "physical_retirement_observed":
            require(
                row["retirement"] is not None and incarnation["retirement"] == row["retirement"],
                "worker_retirement_missing",
            )
            receipt = decoded(row["retirement"].encode())
            _retirement_snapshot(con, row["run_id"], association, receipt)
        elif row["state"] != "released":
            holds.add(attempt_key)
    for runtime_id, row in incarnations.items():
        _uuid(runtime_id)
        hash_value(row["runtime_sha256"])
        maximum = integer(row["max_attempts"], 1, 32)
        last = integer(row["last_sequence"], 0, maximum)
        ordered = sorted(histories.get(runtime_id, []), key=lambda item: item["runtime_sequence"])
        history = [item["runtime_sequence"] for item in ordered]
        require(history == list(range(1, last + 1)), "worker_sequence_history_gap")
        require(
            row["state"] in {"idle", "active", "physical_retirement_observed"},
            "worker_sequence_state",
        )
        if row["state"] == "idle":
            require(
                row["active_sequence"] is None
                and row["retirement"] is None
                and all(item["state"] == "released" for item in ordered),
                "worker_sequence_projection_changed",
            )
        elif row["state"] == "active":
            require(
                last >= 1
                and row["active_sequence"] == last
                and row["retirement"] is None
                and all(
                    item["state"] == "released"
                    for item in ordered
                    if item["runtime_sequence"] < last
                ),
                "worker_sequence_projection_changed",
            )
            active = ordered[-1]
            require(
                active["state"] not in {"released", "physical_retirement_observed"},
                "worker_sequence_projection_changed",
            )
        else:
            require(
                row["active_sequence"] is None and row["retirement"] is not None,
                "worker_retirement_missing",
            )
        if row["active_sequence"] is not None:
            holds.add((runtime_id, row["active_sequence"]))
    return len(holds)


def retire_incarnation_observation(
    con: sqlite3.Connection, run_id: str, runtime_retirement: dict
) -> None:
    """After caller's full /3 validation, retain physical retirement without ACKs."""
    require(con.in_transaction, "worker_retirement_transaction_required")
    association = claim_association(con, run_id)
    if association is None or association["schema"] != "vardr.worker-claim-association/2":
        return
    receipt = fields(
        runtime_retirement,
        {
            "schema",
            "runtime_id",
            "runtime_sha256",
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
        receipt["schema"] == "vardr.worker-retirement/2"
        and receipt["retired"] is True
        and all(
            receipt[k] == association[k]
            for k in ("runtime_id", "runtime_sha256", "origin", "runner_id", "enrollment_id")
        )
        and receipt["receipt_sha256"]
        == digest(encoded({k: v for k, v in receipt.items() if k != "receipt_sha256"})),
        "worker_retirement_binding",
    )
    integer(receipt["last_sequence"], 0, 32)
    hash_value(receipt["report_sha256"])
    claim = con.execute("SELECT * FROM managed_claim_intents WHERE run_id=?", (run_id,)).fetchone()
    require(claim is not None, "worker_retirement_binding")
    snapshot = _retirement_snapshot(con, run_id, association, receipt)
    selected_claim = snapshot["claim"]
    if selected_claim is None:
        require(claim["contract"] is None, "worker_retirement_binding")
        require(
            receipt["last_sequence"] < association["runtime_sequence"], "worker_retirement_binding"
        )
    elif receipt["runtime_sequence"] == association["runtime_sequence"]:
        original = con.execute(
            "SELECT binding FROM managed_worker_attempts WHERE run_id=?", (run_id,)
        ).fetchone()
        require(original is not None, "worker_retirement_binding")
        binding = fields(receipt["binding"], BINDING)
        integer(binding["fence"], 1)
        hash_value(binding["contract_sha256"])
        require(
            binding
            == {
                **{k: association[k] for k in ("origin", "job_id", "runner_id")},
                **{
                    k: selected_claim[k]
                    for k in ("contract_id", "attempt_id", "fence", "contract_sha256")
                },
            },
            "worker_retirement_binding",
        )
        if claim["contract"] is not None:
            require(
                (binding["contract_id"], binding["attempt_id"], binding["fence"])
                == (claim["contract"], claim["attempt"], claim["fence"]),
                "worker_retirement_binding",
            )
        if original["binding"] is not None:
            stored = decoded(original["binding"].encode())
            require(binding == {k: stored[k] for k in BINDING}, "worker_retirement_binding")
    canonical = encoded(receipt).decode()
    row = con.execute("SELECT * FROM managed_worker_attempts WHERE run_id=?", (run_id,)).fetchone()
    require(
        row is not None and (row["retirement"] is None or row["retirement"] == canonical),
        "worker_retirement_changed",
    )
    con.execute(
        "UPDATE managed_worker_attempts SET retired_from_state=CASE WHEN retirement IS NULL THEN state ELSE retired_from_state END,state='physical_retirement_observed',retirement=? WHERE run_id=?",
        (canonical, run_id),
    )
    changed = con.execute(
        "UPDATE managed_worker_incarnations SET active_sequence=NULL,state='physical_retirement_observed',retirement=? WHERE runtime_id=? AND runtime_sha256=? AND (retirement IS NULL OR retirement=?)",
        (canonical, association["runtime_id"], association["runtime_sha256"], canonical),
    ).rowcount
    require(changed == 1, "worker_retirement_changed")
