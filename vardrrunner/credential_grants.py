"""Explicit expiring reference grants; no secrets, provider writes or legacy fallback.

Reference metadata stays in config. The existing journal serializes grant updates
and launch, and anchors the catalog digest so stale JSON cannot undo revocation.
A torn two-file update refuses further protected use, rather than repairing itself.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import closing, contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from vardrrunner import config, configs, launch_guard
from vardrrunner.journal import Journal, JournalError, journal_path_present

KEY = "gate_credential_grants_v1"


class GrantError(configs.ConfigError):
    """Fixed reason codes only; never provider exception text or secret values."""


def now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise GrantError("invalid_grant_timestamp")
    return result


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def issuer(value: str) -> str:
    if value == "standalone":
        return value
    try:
        parsed = urlsplit(value)
        config.url_origin(value)
        if (
            parsed.query
            or parsed.fragment
            or any(c.isspace() for c in value)
            or (
                parsed.scheme != "https"
                and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            )
        ):
            raise ValueError()
    except (ValueError, TypeError):
        raise GrantError("invalid_grant_issuer") from None
    return value.rstrip("/")


def binding(authority: str, engagement: str, origin: str, source: str, name: str) -> dict:
    try:
        return {"issuer": issuer(authority), **config._approval(engagement, origin, source, name)}
    except (ValueError, TypeError):
        raise GrantError("invalid_grant_binding") from None


def validate_catalog(catalog: dict) -> None:
    if (
        not isinstance(catalog, dict)
        or set(catalog) != {"schema_version", "revision", "grants"}
        or type(catalog["schema_version"]) is not int
        or catalog["schema_version"] != 1
        or type(catalog["revision"]) is not int
        or catalog["revision"] < 0
        or not isinstance(catalog["grants"], list)
    ):
        raise GrantError("malformed_grant_catalog")
    seen = set()
    for row in catalog["grants"]:
        expected = {
            "issuer",
            "engagement_id",
            "origin",
            "source",
            "name",
            "id",
            "issued_at",
            "expires_at",
            "status",
        }
        if (
            not isinstance(row, dict)
            or set(row) != expected
            or not all(type(v) is str for v in row.values())
        ):
            raise GrantError("malformed_grant_record")
        normalized = binding(
            row["issuer"], row["engagement_id"], row["origin"], row["source"], row["name"]
        )
        if any(row[k] != v for k, v in normalized.items()):
            raise GrantError("noncanonical_grant_binding")
        fingerprint = digest(normalized)
        if fingerprint in seen or str(uuid.UUID(row["id"])) != row["id"]:
            raise GrantError("duplicate_or_invalid_grant")
        seen.add(fingerprint)
        if row["status"] not in {"active", "revoked"} or timestamp(row["expires_at"]) <= timestamp(
            row["issued_at"]
        ):
            raise GrantError("invalid_grant_lifetime")


class Store:
    def __init__(self):
        self.path = config.journal_file()
        self.store = digest(str(config.CONFIG_FILE.resolve()))

    @contextmanager
    def transaction(self, *, create=False):
        try:
            Journal(self.path)
            if not journal_path_present(self.path):
                raise GrantError("grant_state_unavailable")
            with closing(sqlite3.connect(self.path, timeout=5)) as con:
                con.execute(
                    "CREATE TABLE IF NOT EXISTS credential_grant_state (store TEXT PRIMARY KEY, snapshot TEXT NOT NULL, observed TEXT NOT NULL)"
                )
                con.execute(
                    "CREATE TABLE IF NOT EXISTS credential_grant_events (event TEXT PRIMARY KEY, store TEXT NOT NULL, grant_id TEXT NOT NULL, action TEXT NOT NULL, at TEXT NOT NULL)"
                )
                con.execute("BEGIN IMMEDIATE")
                data = config.load()
                catalog = data.get(KEY)
                anchor = con.execute(
                    "SELECT snapshot, observed FROM credential_grant_state WHERE store=?",
                    (self.store,),
                ).fetchone()
                clock = now()
                if catalog is None and anchor is None and create:
                    catalog = {"schema_version": 1, "revision": 0, "grants": []}
                    con.execute(
                        "INSERT INTO credential_grant_state VALUES (?, ?, ?)",
                        (self.store, digest(catalog), stamp(clock)),
                    )
                elif catalog is None or anchor is None:
                    raise GrantError("missing_or_stale_grant_state")
                validate_catalog(catalog)
                if anchor is not None and digest(catalog) != anchor[0]:
                    raise GrantError("stale_grant_catalog")
                if anchor is not None and clock < timestamp(anchor[1]):
                    raise GrantError("grant_clock_rollback")
                con.execute(
                    "UPDATE credential_grant_state SET observed=? WHERE store=?",
                    (stamp(clock), self.store),
                )
                try:
                    yield con, data, catalog, clock
                    con.commit()
                except BaseException:
                    # Roll back permission changes, but never forget a trusted
                    # time at which an expiry/launch refusal was observed.
                    con.rollback()
                    with con:
                        con.execute("BEGIN IMMEDIATE")
                        observed = stamp(max(clock, now()))
                        con.execute(
                            "UPDATE credential_grant_state SET observed=CASE WHEN observed < ? THEN ? ELSE observed END WHERE store=?",
                            (observed, observed, self.store),
                        )
                    raise
        except GrantError:
            raise
        except (sqlite3.Error, JournalError, OSError, ValueError, TypeError, KeyError):
            raise GrantError("grant_state_unavailable") from None

    def publish(self, con, data, catalog, grant_id: str, action: str, clock: datetime):
        catalog["revision"] += 1
        data[KEY] = catalog
        config.save(data)
        con.execute(
            "UPDATE credential_grant_state SET snapshot=? WHERE store=?",
            (digest(catalog), self.store),
        )
        con.execute(
            "INSERT INTO credential_grant_events VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), self.store, grant_id, action, stamp(clock)),
        )

    def approve(
        self, authority: str, engagement: str, origin: str, source: str, name: str, seconds: int
    ) -> dict:
        if type(seconds) is not int or not 1 <= seconds <= 86400:
            raise GrantError("grant_ttl_out_of_range")
        bound = binding(authority, engagement, origin, source, name)
        with self.transaction(create=True) as (con, data, catalog, clock):
            row = {
                **bound,
                "id": str(uuid.uuid4()),
                "issued_at": stamp(clock),
                "expires_at": stamp(clock + timedelta(seconds=seconds)),
                "status": "active",
            }
            catalog["grants"] = [
                r for r in catalog["grants"] if not all(r[k] == v for k, v in bound.items())
            ] + [row]
            self.publish(con, data, catalog, row["id"], "approved", clock)
            return row

    def revoke(self, authority: str, engagement: str, origin: str, source: str, name: str) -> bool:
        bound = binding(authority, engagement, origin, source, name)
        with self.transaction() as (con, data, catalog, clock):
            for row in catalog["grants"]:
                if all(row[k] == v for k, v in bound.items()) and row["status"] == "active":
                    row["status"] = "revoked"
                    self.publish(con, data, catalog, row["id"], "revoked", clock)
                    return True
            return False

    def entries(self) -> list[dict]:
        with self.transaction() as (_, _, catalog, _):
            return catalog["grants"]


class Policy:
    def __init__(self, authority: str):
        self.authority = issuer(authority)
        self.expected: dict[str, str] | None = None
        self.expires_at: datetime | None = None
        self.store = Store()

    def permitted(self, catalog: dict, requested: set[str], entered_at: datetime) -> dict[str, str]:
        current = {}
        expiries = []
        for row in catalog["grants"]:
            fingerprint = digest(
                {k: row[k] for k in ("issuer", "engagement_id", "origin", "source", "name")}
            )
            if fingerprint in requested:
                if row["status"] != "active":
                    raise GrantError("grant_expired_or_revoked")
                current[fingerprint] = row["id"]
                expiries.append(timestamp(row["expires_at"]))
        checked_at = now()  # After catalog validation/hash work, immediately before use.
        if checked_at < entered_at:
            raise GrantError("grant_clock_rollback")
        if expiries and min(expiries) <= checked_at:
            raise GrantError("grant_expired_or_revoked")
        if self.expires_at is not None and self.expires_at <= checked_at:
            raise GrantError("grant_expired_or_revoked")
        if set(current) != requested or (self.expected is not None and current != self.expected):
            raise GrantError("grant_missing_or_replaced")
        return current

    def check(self, engagement: str, origins: list[str], refs: list[tuple[str, str, str]]) -> None:
        requested = {
            digest(binding(self.authority, engagement, origin, source, name))
            for _, source, name in refs
            for origin in origins
        }
        if not requested:
            if self.expected:
                raise GrantError("grant_binding_changed")
            self.expected = {}
            return
        with self.store.transaction() as (_, _, catalog, clock):
            self.expected = self.permitted(catalog, requested, clock)
            if self.expires_at is None:
                ids = set(self.expected.values())
                self.expires_at = min(
                    timestamp(row["expires_at"]) for row in catalog["grants"] if row["id"] in ids
                )

    @contextmanager
    def launch(self):
        if self.expected is None:
            raise GrantError("grant_snapshot_required")
        if not self.expected:
            yield
            return
        with self.store.transaction() as (_, _, catalog, clock):
            requested = set(self.expected)

            def recheck():
                self.permitted(catalog, requested, clock)

            with launch_guard.revalidation(recheck):
                recheck()
                yield  # Writer lock remains held through the process-creation call.


_POLICY: ContextVar[Policy | None] = ContextVar("expiring_credential_grants", default=None)


def current() -> Policy | None:
    return _POLICY.get()


@contextmanager
def required(authority: str) -> Iterator[Policy]:
    policy = Policy(authority)
    token = _POLICY.set(policy)
    try:
        with launch_guard.install(policy.launch):
            yield policy
    finally:
        _POLICY.reset(token)
