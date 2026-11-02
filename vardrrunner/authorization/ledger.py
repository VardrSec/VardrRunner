"""Additive prototype tables in the existing Runner journal, never a default path."""

from __future__ import annotations

import sqlite3
from datetime import timezone

from vardrrunner.journal import Journal

from .codec import AuthorizationError, TrustAnchor, digest, encoded, identifier, require, sign
from .contracts import ValidationContext, approved, hash_field, validate


class AuthorizationLedger:
    def __init__(self, journal: Journal):
        self.journal = journal
        with journal._connection() as con:
            columns = con.execute("PRAGMA table_info(authorization_state)").fetchall()
            require(
                not columns or "authority_digest" in {r["name"] for r in columns},
                "unsupported_prototype_ledger_schema",
            )
            con.executescript("""
                CREATE TABLE IF NOT EXISTS authorization_approvals (
                    issuer TEXT NOT NULL, approval TEXT NOT NULL, digest TEXT NOT NULL,
                    issued INTEGER NOT NULL, PRIMARY KEY (issuer, approval));
                CREATE TABLE IF NOT EXISTS authorization_contracts (
                    issuer TEXT NOT NULL, contract TEXT NOT NULL, approval TEXT NOT NULL,
                    ordinal INTEGER NOT NULL, job TEXT NOT NULL, attempt TEXT NOT NULL,
                    fence INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (issuer, contract), UNIQUE (issuer, approval, ordinal),
                    UNIQUE (issuer, job, fence));
                CREATE TABLE IF NOT EXISTS authorization_fences (
                    issuer TEXT NOT NULL, job TEXT NOT NULL, fence INTEGER NOT NULL,
                    PRIMARY KEY (issuer, job));
                CREATE TABLE IF NOT EXISTS authorization_state (
                    issuer TEXT NOT NULL, engagement TEXT NOT NULL, revision INTEGER NOT NULL,
                    stopped INTEGER NOT NULL, authority_digest TEXT NOT NULL,
                    PRIMARY KEY (issuer, engagement));
                CREATE TABLE IF NOT EXISTS authorization_clock (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1), observed TEXT NOT NULL);
            """)

    def set_state(
        self, issuer: str, engagement: str, revision: int, stopped: bool, authority_sha256: str
    ) -> None:
        """Trusted local/prototype control adapter; never exposed to queued data."""
        from .codec import integer

        identifier(issuer)
        identifier(engagement)
        integer(revision)
        hash_field(authority_sha256)
        require(type(stopped) is bool, "invalid_stop_state")
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT revision, stopped, authority_digest FROM authorization_state WHERE issuer=? AND engagement=?",
                (issuer, engagement),
            ).fetchone()
            require(
                row is None
                or revision > row["revision"]
                or (
                    revision == row["revision"]
                    and stopped == bool(row["stopped"])
                    and authority_sha256 == row["authority_digest"]
                ),
                "state_rollback",
            )
            con.execute(
                "INSERT OR REPLACE INTO authorization_state VALUES (?,?,?,?,?)",
                (issuer, engagement, revision, int(stopped), authority_sha256),
            )

    def _state(self, con: sqlite3.Connection, context: ValidationContext, issuer: str) -> None:
        row = con.execute(
            "SELECT revision, stopped, authority_digest FROM authorization_state WHERE issuer=? AND engagement=?",
            (issuer, context.engagement_id),
        ).fetchone()
        require(
            row is not None
            and row["revision"] == context.authority_revision
            and row["authority_digest"] == context.authority_sha256
            and not row["stopped"],
            "authority_state_unavailable_or_revoked",
        )
        now = context.now.astimezone(timezone.utc).isoformat()
        clock = con.execute("SELECT observed FROM authorization_clock WHERE singleton=1").fetchone()
        require(clock is None or now >= clock["observed"], "clock_rollback")
        con.execute("INSERT OR REPLACE INTO authorization_clock VALUES (1,?)", (now,))

    def issue(
        self,
        approval: dict,
        anchors: tuple[TrustAnchor, ...],
        issuer: dict,
        private_key: bytes,
        contract_id: str,
        attempt_id: str,
        context: ValidationContext,
        plan: dict,
        case: dict,
        execution: dict,
    ) -> dict:
        receipt = approved(approval, anchors)
        permission = receipt["context"]
        require(issuer["id"] == receipt["issuer"]["id"], "approval_issuer_mismatch")
        identifier(contract_id)
        identifier(attempt_id)
        try:
            with self.journal._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                self._state(con, context, issuer["id"])
                active = con.execute(
                    "SELECT 1 FROM authorization_contracts WHERE issuer=? AND job=? AND consumed=1",
                    (issuer["id"], permission["job_id"]),
                ).fetchone()
                require(active is None, "attempt_in_flight")
                row = con.execute(
                    "SELECT digest, issued FROM authorization_approvals WHERE issuer=? AND approval=?",
                    (issuer["id"], receipt["approval_id"]),
                ).fetchone()
                receipt_digest = digest(encoded(approval))
                require(row is None or row["digest"] == receipt_digest, "approval_id_reused")
                ordinal = 1 if row is None else row["issued"] + 1
                require(ordinal <= permission["max_executions"], "approval_exhausted")
                previous = con.execute(
                    "SELECT fence FROM authorization_fences WHERE issuer=? AND job=?",
                    (issuer["id"], permission["job_id"]),
                ).fetchone()
                fence = 1 if previous is None else previous["fence"] + 1
                require(
                    context.fence == fence and context.attempt_id == attempt_id, "fence_mismatch"
                )
                payload = {
                    "schema": "vardr.authorization/1",
                    "issuer": issuer,
                    "origin": receipt["origin"],
                    "contract_id": contract_id,
                    "approval_id": receipt["approval_id"],
                    "approval_sha256": receipt_digest,
                    "execution_index": ordinal,
                    "plan_sha256": permission["plan_sha256"],
                    "runner_id": permission["runner_id"],
                    "engagement_id": permission["engagement_id"],
                    "job_id": permission["job_id"],
                    "attempt_id": attempt_id,
                    "fence": fence,
                    "issued_at": context.now.astimezone(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "expires_at": permission["expires_at"],
                    "authority_revision": permission["authority_revision"],
                }
                envelope = sign(payload, private_key, "contract")
                validate(envelope, approval, plan, case, execution, anchors, context)
                con.execute(
                    "INSERT OR REPLACE INTO authorization_approvals VALUES (?,?,?,?)",
                    (issuer["id"], receipt["approval_id"], receipt_digest, ordinal),
                )
                con.execute(
                    "INSERT OR REPLACE INTO authorization_fences VALUES (?,?,?)",
                    (issuer["id"], permission["job_id"], fence),
                )
                con.execute(
                    "INSERT INTO authorization_contracts VALUES (?,?,?,?,?,?,?,0)",
                    (
                        issuer["id"],
                        contract_id,
                        receipt["approval_id"],
                        ordinal,
                        permission["job_id"],
                        attempt_id,
                        fence,
                    ),
                )
            return envelope
        except sqlite3.Error as exc:
            raise AuthorizationError("issuance_state_failed") from exc

    def consume(
        self,
        envelope: dict,
        approval: dict,
        plan: dict,
        case: dict,
        execution: dict,
        anchors: tuple[TrustAnchor, ...],
        context: ValidationContext,
    ) -> dict:
        payload = validate(envelope, approval, plan, case, execution, anchors, context)
        issuer = payload["issuer"]["id"]
        try:
            with self.journal._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                self._state(con, context, issuer)
                current = con.execute(
                    "SELECT fence FROM authorization_fences WHERE issuer=? AND job=?",
                    (issuer, payload["job_id"]),
                ).fetchone()
                require(current is None or payload["fence"] >= current["fence"], "stale_fence")
                active = con.execute(
                    "SELECT 1 FROM authorization_contracts WHERE issuer=? AND job=? AND consumed=1 AND contract<>?",
                    (issuer, payload["job_id"], payload["contract_id"]),
                ).fetchone()
                require(active is None, "attempt_in_flight")
                approval_row = con.execute(
                    "SELECT digest, issued FROM authorization_approvals WHERE issuer=? AND approval=?",
                    (issuer, payload["approval_id"]),
                ).fetchone()
                approval_digest = digest(encoded(approval))
                require(
                    approval_row is None or approval_row["digest"] == approval_digest,
                    "approval_id_reused",
                )
                con.execute(
                    "INSERT OR REPLACE INTO authorization_approvals VALUES (?,?,?,?)",
                    (
                        issuer,
                        payload["approval_id"],
                        approval_digest,
                        max(
                            payload["execution_index"],
                            approval_row["issued"] if approval_row else 0,
                        ),
                    ),
                )
                row = con.execute(
                    "SELECT * FROM authorization_contracts WHERE issuer=? AND contract=?",
                    (issuer, payload["contract_id"]),
                ).fetchone()
                if row is None:
                    con.execute(
                        "INSERT INTO authorization_contracts VALUES (?,?,?,?,?,?,?,1)",
                        (
                            issuer,
                            payload["contract_id"],
                            payload["approval_id"],
                            payload["execution_index"],
                            payload["job_id"],
                            payload["attempt_id"],
                            payload["fence"],
                        ),
                    )
                else:
                    require(
                        not row["consumed"]
                        and row["approval"] == payload["approval_id"]
                        and row["ordinal"] == payload["execution_index"]
                        and row["job"] == payload["job_id"]
                        and row["attempt"] == payload["attempt_id"]
                        and row["fence"] == payload["fence"],
                        "contract_replayed_or_changed",
                    )
                    con.execute(
                        "UPDATE authorization_contracts SET consumed=1 WHERE issuer=? AND contract=?",
                        (issuer, payload["contract_id"]),
                    )
                con.execute(
                    "INSERT OR REPLACE INTO authorization_fences VALUES (?,?,?)",
                    (issuer, payload["job_id"], payload["fence"]),
                )
            return payload
        except sqlite3.Error as exc:
            raise AuthorizationError("consumption_state_failed") from exc

    def finish(self, payload: dict) -> None:
        """Record known completion; ambiguous launches stay reserved.

        A trusted execution adapter calls this after the tool returns. Evidence
        finalization remains possible after expiry/revocation, without reexecution.
        """
        with self.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            changed = con.execute(
                "UPDATE authorization_contracts SET consumed=2 WHERE issuer=? AND contract=? AND attempt=? AND fence=? AND consumed IN (1,2)",
                (
                    payload["issuer"]["id"],
                    payload["contract_id"],
                    payload["attempt_id"],
                    payload["fence"],
                ),
            ).rowcount
            require(changed == 1, "completion_owner_mismatch")
