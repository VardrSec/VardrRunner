"""Durable local execution journal.

Every claimed backend job is represented by an explicit state machine in a
small SQLite database.  Transactions make each phase transition atomic; WAL
mode lets audit readers inspect state while a `jobs run` is active.  The journal
contains sanitized metadata only—never targets, credentials, headers, or raw
tool output.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from vardrrunner import manifests, redaction
from vardrrunner.windows_journal import WindowsJournalError, WindowsJournalPin

SCHEMA_VERSION = 1
RETENTION_RECORD_LIMIT = 10_000
RETENTION_PATH_BYTES = 4096
RETENTION_TOTAL_BYTES = 8 * 1024 * 1024


class JournalError(RuntimeError):
    """The journal is unavailable, corrupt, or received an invalid transition."""


def _journal_path_info(path: Path) -> os.stat_result | None:
    """Observe the target and retain its identity for the Windows handle check."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise JournalError("Cannot inspect journal path") from None
    try:
        # Preserve leaf symlinks to ordinary files; dangling/special targets refuse.
        if stat.S_ISLNK(info.st_mode):
            info = path.stat()
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise JournalError("Unsupported nonregular or reparse journal target")
    except OSError:
        raise JournalError("Cannot inspect journal target") from None
    return info


def journal_path_present(path: Path) -> bool:
    """Observe an ordinary journal target, not a race-safe open or I/O deadline."""
    return _journal_path_info(path) is not None


@contextmanager
def journal_connection(path: Path, *, readonly: bool = False) -> Iterator[sqlite3.Connection]:
    """Use one canonical DB/WAL identity; keep Windows names pinned until close.

    POSIX retains the existing observed-file check, not a race-safe open promise.
    Read-only SQLite connections can still create or change WAL sidecars.
    """
    observed = _journal_path_info(path)
    try:
        canonical = path.resolve(strict=readonly)
        guard = (
            WindowsJournalPin(canonical, create=not readonly, observed=observed)
            if os.name == "nt"
            else nullcontext()
        )
        with guard:
            target = canonical.as_uri() + "?mode=ro" if readonly else canonical
            con = sqlite3.connect(target, uri=readonly, timeout=5.0)
            try:
                yield con
            finally:
                con.close()
    except OSError:
        raise JournalError("Cannot open journal path") from None
    except WindowsJournalError:
        raise JournalError("Cannot pin journal path") from None


class Phase(str, Enum):
    DISCOVERED = "discovered"
    VALIDATING = "validating"
    TARGETS_RESOLVED = "targets_resolved"
    CLAIMING = "claiming"
    CLAIMED = "claimed"
    EXECUTING = "executing"
    ARTIFACT_READY = "artifact_ready"
    UPLOADING = "uploading"
    FINALIZING = "finalizing"
    DONE = "done"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    STOP_WORK = "stop_work"
    SKIPPED = "skipped"


TERMINAL_PHASES = frozenset(
    {Phase.DONE, Phase.FAILED, Phase.INTERRUPTED, Phase.STOP_WORK, Phase.SKIPPED}
)
_TERMINAL_VALUES = tuple(sorted(phase.value for phase in TERMINAL_PHASES))

_FORWARD: dict[Phase, frozenset[Phase]] = {
    Phase.DISCOVERED: frozenset({Phase.VALIDATING}),
    Phase.VALIDATING: frozenset({Phase.TARGETS_RESOLVED}),
    Phase.TARGETS_RESOLVED: frozenset({Phase.CLAIMING, Phase.FINALIZING}),
    Phase.CLAIMING: frozenset({Phase.CLAIMED}),
    Phase.CLAIMED: frozenset({Phase.EXECUTING, Phase.FINALIZING}),
    Phase.EXECUTING: frozenset({Phase.ARTIFACT_READY, Phase.FINALIZING}),
    Phase.ARTIFACT_READY: frozenset({Phase.UPLOADING}),
    Phase.UPLOADING: frozenset({Phase.FINALIZING}),
    Phase.FINALIZING: frozenset({Phase.DONE}),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_backend_url(url: str) -> str:
    """Keep backend identity while dropping userinfo, query strings and fragments."""
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path.rstrip("/"), "", ""))


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    job_id: str
    backend_url: str
    engagement_id: str
    job_type: str
    tool: str
    job_schema_version: int
    target_source: str
    target_count: int
    command_profile: dict[str, Any]
    phase: Phase
    pid: int | None
    run_dir: str | None
    artifact_path: str | None
    artifact_sha256: str | None
    artifact_size: int | None
    manifest_path: str | None
    last_event: str | None
    upload_state: str
    started_at: str
    claimed_at: str | None
    completed_at: str | None
    status: str
    failure_category: str | None
    failure_reason: str | None
    warnings: list[dict[str, str]]
    updated_at: str

    def manifest_payload(self) -> dict[str, Any]:
        data = asdict(self)
        data["phase"] = self.phase.value
        data.pop("backend_url", None)
        data.pop("manifest_path", None)
        return data


@dataclass(frozen=True)
class RetainedPaths:
    run_dir: str | None
    artifact_path: str | None
    manifest_path: str | None


class Journal:
    """Transaction-safe journal repository; one short-lived connection per call."""

    def __init__(self, path: Path):
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._migrate()
        except (OSError, sqlite3.Error) as exc:
            raise JournalError(f"cannot open execution journal: {exc}") from exc

    @classmethod
    def read_existing(cls, path: Path, run_id: str) -> RunRecord | None:
        """Inspect one current-schema record without creating or migrating storage."""
        try:
            with journal_connection(Path(path), readonly=True) as con:
                con.row_factory = sqlite3.Row
                if con.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                    raise JournalError("unsupported read-only journal schema")
                row = con.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            return cls._record(row) if row else None
        except (OSError, sqlite3.Error):
            raise JournalError("cannot inspect existing execution journal") from None

    @classmethod
    def read_existing_paths(cls, path: Path) -> list[RetainedPaths]:
        """Read complete, bounded path references for conservative retention.

        A destructive cleanup decision must never use a truncated inventory.
        This is a SQLite read, not a promise of unchanged filesystem sidecars.
        """
        try:
            with journal_connection(Path(path), readonly=True) as con:
                con.row_factory = sqlite3.Row
                if con.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                    raise JournalError("unsupported read-only journal schema")
                # Bound database-encoded bytes before Python materializes them.
                # A bytes sentinel cannot be mistaken for an admissible text path.
                rows = con.execute(
                    """SELECT
                    CASE WHEN run_dir IS NULL THEN NULL
                         WHEN typeof(run_dir)='text' AND length(CAST(run_dir AS BLOB))<=?
                         THEN run_dir ELSE x'00' END,
                    CASE WHEN artifact_path IS NULL THEN NULL
                         WHEN typeof(artifact_path)='text' AND length(CAST(artifact_path AS BLOB))<=?
                         THEN artifact_path ELSE x'00' END,
                    CASE WHEN manifest_path IS NULL THEN NULL
                         WHEN typeof(manifest_path)='text' AND length(CAST(manifest_path AS BLOB))<=?
                         THEN manifest_path ELSE x'00' END
                    FROM runs LIMIT ?""",
                    (RETENTION_PATH_BYTES,) * 3 + (RETENTION_RECORD_LIMIT + 1,),
                )
                records: list[RetainedPaths] = []
                total = 0
                for row in rows:
                    if len(records) >= RETENTION_RECORD_LIMIT:
                        raise JournalError("journal retention inventory exceeds safe limit")
                    values = tuple(row)
                    if any(value is not None and not isinstance(value, str) for value in values):
                        raise JournalError("unsupported journal retention path")
                    sizes = [len(value.encode("utf-8")) for value in values if value is not None]
                    if any(size > RETENTION_PATH_BYTES for size in sizes):
                        raise JournalError("unsupported journal retention path")
                    total += sum(sizes)
                    if total > RETENTION_TOTAL_BYTES:
                        raise JournalError("journal retention inventory exceeds safe byte limit")
                    records.append(RetainedPaths(*values))
                return records
        except (OSError, sqlite3.Error):
            raise JournalError("cannot inspect existing execution journal") from None

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with journal_connection(self.path) as con:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA foreign_keys = ON")
            con.execute("PRAGMA busy_timeout = 5000")
            yield con

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Commit or roll back the transaction and always close the handle."""
        with self._connect() as con:
            with con:
                yield con

    def _migrate(self) -> None:
        with self._connection() as con:
            version = int(con.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise JournalError(
                    f"journal schema {version} is newer than supported {SCHEMA_VERSION}"
                )
            if version == 0:
                con.executescript(
                    """
                    PRAGMA journal_mode = WAL;
                    CREATE TABLE runs (
                        run_id TEXT PRIMARY KEY,
                        job_id TEXT NOT NULL,
                        backend_url TEXT NOT NULL,
                        engagement_id TEXT NOT NULL,
                        job_type TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        job_schema_version INTEGER NOT NULL,
                        target_source TEXT NOT NULL,
                        target_count INTEGER NOT NULL DEFAULT 0,
                        command_profile TEXT NOT NULL DEFAULT '{}',
                        phase TEXT NOT NULL,
                        pid INTEGER,
                        run_dir TEXT,
                        artifact_path TEXT,
                        artifact_sha256 TEXT,
                        artifact_size INTEGER,
                        manifest_path TEXT,
                        last_event TEXT,
                        upload_state TEXT NOT NULL DEFAULT 'not_started',
                        started_at TEXT NOT NULL,
                        claimed_at TEXT,
                        completed_at TEXT,
                        status TEXT NOT NULL,
                        failure_category TEXT,
                        failure_reason TEXT,
                        warnings_json TEXT NOT NULL DEFAULT '[]',
                        updated_at TEXT NOT NULL
                    );
                    CREATE INDEX idx_runs_job_id ON runs(job_id);
                    CREATE INDEX idx_runs_phase ON runs(phase);
                    CREATE UNIQUE INDEX idx_runs_one_active_job ON runs(job_id)
                    WHERE phase NOT IN ('done', 'failed', 'interrupted', 'stop_work', 'skipped');
                    PRAGMA user_version = 1;
                    """
                )
            try:
                # Use SQLite's canonical name while its Windows pins remain held;
                # an unpinned input alias must not redirect the permission update.
                database = Path(con.execute("PRAGMA database_list").fetchone()[2])
                database.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass

    def begin(
        self,
        *,
        job_id: str,
        backend_url: str,
        engagement_id: str,
        job_type: str,
        tool: str,
        target_source: str,
        command_profile: dict[str, Any] | None = None,
        job_schema_version: int = 1,
    ) -> RunRecord:
        """Create a run unless this job already has an unfinished attempt."""
        now = utc_now()
        run_id = uuid.uuid4().hex
        profile = redaction.redact(command_profile or {})
        try:
            with self._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                existing = self._active_for_job(con, job_id)
                if existing:
                    return existing
                con.execute(
                    """INSERT INTO runs (
                    run_id, job_id, backend_url, engagement_id, job_type, tool,
                    job_schema_version, target_source, command_profile, phase,
                    started_at, status, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        run_id,
                        job_id,
                        normalize_backend_url(backend_url),
                        engagement_id,
                        job_type,
                        tool,
                        job_schema_version,
                        target_source,
                        json.dumps(profile, sort_keys=True),
                        Phase.DISCOVERED.value,
                        now,
                        "active",
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            # A second process may have inserted between opening connections.
            # The partial unique index is authoritative; return its winner.
            existing = self.active_for_job(job_id)
            if existing:
                return existing
            raise JournalError("could not create a unique active run") from exc
        record = self.get(run_id)
        if record is None:  # pragma: no cover - SQLite insert invariant
            raise JournalError("journal insert disappeared")
        return record

    def transition(self, run_id: str, phase: Phase, **fields: Any) -> RunRecord:
        """Atomically move a run forward, rejecting impossible state changes."""
        with self._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                raise JournalError(f"unknown run {run_id}")
            current = Phase(row["phase"])
            if current in TERMINAL_PHASES and phase != current:
                raise JournalError(
                    f"terminal journal run cannot change {current.value} -> {phase.value}"
                )
            if (
                phase != current
                and phase not in TERMINAL_PHASES
                and phase not in _FORWARD.get(current, frozenset())
            ):
                raise JournalError(f"invalid journal transition {current.value} -> {phase.value}")

            allowed = {
                "target_count",
                "pid",
                "run_dir",
                "artifact_path",
                "artifact_sha256",
                "artifact_size",
                "manifest_path",
                "last_event",
                "upload_state",
                "claimed_at",
                "completed_at",
                "status",
                "failure_category",
                "failure_reason",
                "warnings_json",
            }
            unknown = set(fields) - allowed
            if unknown:
                raise JournalError(f"unsupported journal field(s): {', '.join(sorted(unknown))}")
            con.execute(
                """UPDATE runs SET
                    target_count = ?, pid = ?, run_dir = ?, artifact_path = ?,
                    artifact_sha256 = ?, artifact_size = ?, manifest_path = ?,
                    last_event = ?, upload_state = ?, claimed_at = ?, completed_at = ?,
                    status = ?, failure_category = ?, failure_reason = ?, warnings_json = ?,
                    phase = ?, updated_at = ?
                WHERE run_id = ?""",
                (
                    *(
                        fields.get(name, row[name])
                        for name in (
                            "target_count",
                            "pid",
                            "run_dir",
                            "artifact_path",
                            "artifact_sha256",
                            "artifact_size",
                            "manifest_path",
                            "last_event",
                            "upload_state",
                            "claimed_at",
                            "completed_at",
                            "status",
                            "failure_category",
                            "failure_reason",
                            "warnings_json",
                        )
                    ),
                    phase.value,
                    utc_now(),
                    run_id,
                ),
            )
        record = self.get(run_id)
        if record is None:  # pragma: no cover - transaction invariant
            raise JournalError(f"run {run_id} disappeared after transition")
        return record

    def finish(
        self,
        run_id: str,
        phase: Phase,
        *,
        status: str,
        failure_category: str | None = None,
        failure_reason: str | None = None,
    ) -> RunRecord:
        """Close a run and atomically create its sanitized manifest when possible."""
        if phase not in TERMINAL_PHASES:
            raise JournalError(f"{phase.value} is not terminal")
        record = self.transition(
            run_id,
            phase,
            status=status,
            completed_at=utc_now(),
            failure_category=failure_category,
            failure_reason=redaction.redact_text(failure_reason or "") or None,
        )
        if record.run_dir:
            manifest = manifests.write_run_manifest(Path(record.run_dir), record.manifest_payload())
            record = self.transition(run_id, phase, manifest_path=str(manifest))
        return record

    def attach_artifact(self, run_id: str, path: Path) -> RunRecord:
        digest, size = manifests.artifact_digest(path)
        return self.transition(
            run_id,
            Phase.ARTIFACT_READY,
            artifact_path=str(path),
            artifact_sha256=digest,
            artifact_size=size,
        )

    def get(self, run_id: str) -> RunRecord | None:
        with self._connection() as con:
            row = con.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return self._record(row) if row else None

    def request_stop(self, run_id: str) -> None:
        """Durable local request only; never signal an unverified/reused PID."""
        record = self.get(run_id)
        if record is None or record.phase in TERMINAL_PHASES:
            raise JournalError("run is missing or already terminal")
        if not record.command_profile.get("controlled"):
            raise JournalError("run has no controlled execution monitor")
        with self._connection() as con:
            con.execute("CREATE TABLE IF NOT EXISTS local_stop_requests (run_id TEXT PRIMARY KEY)")
            con.execute("INSERT OR IGNORE INTO local_stop_requests VALUES (?)", (run_id,))

    def stop_requested(self, run_id: str) -> bool:
        with self._connection() as con:
            exists = con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='local_stop_requests'"
            ).fetchone()
            return bool(
                exists
                and con.execute(
                    "SELECT 1 FROM local_stop_requests WHERE run_id = ?", (run_id,)
                ).fetchone()
            )

    def managed_claim_exists(self, run_id: str) -> bool:
        """Read-only recovery fence; never initialize prototype tables here."""
        try:
            with self._connection() as con:
                exists = con.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_claim_intents'"
                ).fetchone()
                return bool(
                    exists
                    and con.execute(
                        "SELECT 1 FROM managed_claim_intents WHERE run_id=?", (run_id,)
                    ).fetchone()
                )
        except sqlite3.Error:
            raise JournalError("managed_claim_state_unavailable") from None

    def active_for_job(self, job_id: str) -> RunRecord | None:
        with self._connection() as con:
            return self._active_for_job(con, job_id)

    def _active_for_job(self, con: sqlite3.Connection, job_id: str) -> RunRecord | None:
        row = con.execute(
            """SELECT * FROM runs
                WHERE job_id = ? AND phase NOT IN (?, ?, ?, ?, ?)
                ORDER BY started_at DESC LIMIT 1""",
            (job_id, *_TERMINAL_VALUES),
        ).fetchone()
        return self._record(row) if row else None

    def unfinished(self) -> list[RunRecord]:
        with self._connection() as con:
            rows = con.execute(
                """SELECT * FROM runs
                    WHERE phase NOT IN (?, ?, ?, ?, ?)
                    ORDER BY started_at""",
                _TERMINAL_VALUES,
            ).fetchall()
        return [self._record(row) for row in rows]

    def list(
        self, *, since: str | None = None, limit: int = 100, engagement_id: str | None = None
    ) -> list[RunRecord]:
        query = "SELECT * FROM runs"
        params: list[Any] = []
        conditions = []
        if since:
            conditions.append("started_at >= ?")
            params.append(since)
        if engagement_id is not None:
            conditions.append("engagement_id = ?")
            params.append(engagement_id)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(max(1, min(limit, 10_000)))
        with self._connection() as con:
            rows = con.execute(query, params).fetchall()
        return [self._record(row) for row in rows]

    @staticmethod
    def _record(row: sqlite3.Row) -> RunRecord:
        try:
            profile = json.loads(row["command_profile"])
            warnings = json.loads(row["warnings_json"])
        except (TypeError, ValueError) as exc:
            raise JournalError("journal contains invalid JSON") from exc
        return RunRecord(
            run_id=row["run_id"],
            job_id=row["job_id"],
            backend_url=row["backend_url"],
            engagement_id=row["engagement_id"],
            job_type=row["job_type"],
            tool=row["tool"],
            job_schema_version=row["job_schema_version"],
            target_source=row["target_source"],
            target_count=row["target_count"],
            command_profile=profile,
            phase=Phase(row["phase"]),
            pid=row["pid"],
            run_dir=row["run_dir"],
            artifact_path=row["artifact_path"],
            artifact_sha256=row["artifact_sha256"],
            artifact_size=row["artifact_size"],
            manifest_path=row["manifest_path"],
            last_event=row["last_event"],
            upload_state=row["upload_state"],
            started_at=row["started_at"],
            claimed_at=row["claimed_at"],
            completed_at=row["completed_at"],
            status=row["status"],
            failure_category=row["failure_category"],
            failure_reason=row["failure_reason"],
            warnings=warnings,
            updated_at=row["updated_at"],
        )
