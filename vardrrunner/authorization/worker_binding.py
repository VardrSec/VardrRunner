"""One-shot worker runtime bindings in the existing journal; no execution rights."""

from __future__ import annotations

import json
import sqlite3

from vardrrunner.journal import Journal, Phase

from .codec import AuthorizationError, encoded, fields, integer, require
from .results import BINDING

RUNTIME_BINDING = BINDING | {"runtime_id", "runtime_sha256"}


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
                run_id TEXT UNIQUE, binding TEXT, state TEXT NOT NULL)""")

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
                    "SELECT runtime_sha256 FROM managed_runtime_bindings WHERE runtime_id=?",
                    (binding["runtime_id"],),
                ).fetchone()
                require(
                    invocation is not None and invocation[0] == binding["runtime_sha256"],
                    "worker_runtime_not_invoked",
                )
                self._claim(con, run_id, binding)
                changed = con.execute(
                    "UPDATE managed_runtime_bindings SET run_id=?,binding=?,state='bind_in_flight' WHERE runtime_id=? AND state='waiting' AND run_id IS NULL",
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
