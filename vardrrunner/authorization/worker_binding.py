"""One-shot worker runtime bindings in the existing journal; no execution rights."""

from __future__ import annotations

import json
import sqlite3

from vardrrunner.journal import Journal, Phase, normalize_backend_url

from .codec import AuthorizationError, decoded, encoded, fields, identifier, integer, require
from .results import BINDING
from .worker_admission import _uuid, hash_value

RUNTIME_BINDING = BINDING | {"runtime_id", "runtime_sha256"}
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
    if table is None:
        return None
    if "claim_link" not in {
        row[1] for row in con.execute("PRAGMA table_info(managed_runtime_bindings)")
    }:
        return None
    rows = con.execute(
        "SELECT * FROM managed_runtime_bindings WHERE run_id=?", (run_id,)
    ).fetchall()
    if not rows:
        return None
    require(len(rows) == 1, "worker_claim_association_changed")
    row = rows[0]
    if row["claim_link"] is None:
        require(row["state"] != "claim_prepared", "worker_claim_association_missing")
        return None
    require(type(row["claim_link"]) is str, "worker_claim_association_changed")
    link = fields(decoded(row["claim_link"].encode(), 8192), CLAIM_ASSOCIATION)
    require(
        link["schema"] == "vardr.worker-claim-association/1"
        and encoded(link).decode() == row["claim_link"],
        "worker_claim_association_changed",
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
        and row["state"] in {"claim_prepared", "bind_in_flight", "bound"}
        and (link["origin"], link["job_id"])
        == (claim["backend"], claim["job"])
        == (run["backend_url"], run["job_id"])
        and all(
            link[key] == claim[key] == profile.get(key)
            for key in ("plan_sha256", "case_sha256", "association_sha256")
        ),
        "worker_claim_association_changed",
    )
    if row["state"] == "claim_prepared":
        require(row["binding"] is None, "worker_claim_association_changed")
    else:
        binding = fields(decoded(row["binding"].encode(), 8192), RUNTIME_BINDING)
        require(
            all(
                binding[key] == link[key]
                for key in ("runtime_id", "runtime_sha256", "origin", "job_id", "runner_id")
            )
            and (binding["contract_id"], binding["attempt_id"], binding["fence"])
            == (claim["contract"], claim["attempt"], claim["fence"]),
            "worker_claim_association_changed",
        )
    return link


def check_binding_ack(reply: dict, binding: dict) -> None:
    fields(reply, RUNTIME_BINDING | {"schema", "bound"})
    integer(reply["fence"], 1)
    require(
        reply == {"schema": "vardr.worker-runtime-binding/1", **binding, "bound": True}
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
