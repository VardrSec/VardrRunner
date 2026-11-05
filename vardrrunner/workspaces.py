"""Inert local workspace metadata in the existing execution journal."""

from __future__ import annotations

import re
import sqlite3
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from vardrrunner import redaction
from vardrrunner.journal import SCHEMA_VERSION, Journal, JournalError, journal_path_present, utc_now


class WorkspaceError(RuntimeError):
    """Fixed, value-free errors for local metadata operations."""


def validate_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or not name
        or name != name.strip()
        or not name.isprintable()
        or len(name.encode("utf-8")) > 160
        or redaction.redact_text(name) != name
    ):
        raise WorkspaceError("Invalid workspace name; use a short label without credentials")
    return name


def validate_id(workspace_id: str) -> str:
    if not isinstance(workspace_id, str) or not re.fullmatch(r"[0-9a-f]{32}", workspace_id):
        raise WorkspaceError("Invalid workspace ID")
    return workspace_id


@dataclass(frozen=True)
class Workspace:
    workspace_id: str
    name: str
    created_at: str
    workspace_schema_version: int = 1


class Workspaces:
    """No execution, approval, grant, key, network or active-workspace selection."""

    def __init__(self, journal: Journal):
        self.journal = journal

    @staticmethod
    def _exists(con: sqlite3.Connection) -> bool:
        row = con.execute(
            "SELECT type FROM sqlite_master WHERE name = ?", ("local_workspaces",)
        ).fetchone()
        if row is None:
            return False
        if row["type"] != "table":
            raise WorkspaceError("Unsupported local workspace schema")
        columns = con.execute("PRAGMA table_info(local_workspaces)").fetchall()
        if [(r["name"], r["type"], r["notnull"], r["pk"]) for r in columns] != [
            ("workspace_id", "TEXT", 1, 1),
            ("name", "TEXT", 1, 0),
            ("created_at", "TEXT", 1, 0),
            ("workspace_schema_version", "INTEGER", 1, 0),
        ]:
            raise WorkspaceError("Unsupported local workspace schema")
        return True

    def create(self, name: str) -> Workspace:
        name = validate_name(name)
        workspace = Workspace(uuid.uuid4().hex, name, utc_now())
        try:
            with self.journal._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                if not self._exists(con):
                    con.execute(
                        """CREATE TABLE local_workspaces (
                            workspace_id TEXT PRIMARY KEY NOT NULL,
                            name TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            workspace_schema_version INTEGER NOT NULL CHECK(workspace_schema_version=1)
                        )"""
                    )
                con.execute(
                    "INSERT INTO local_workspaces VALUES (?, ?, ?, ?)",
                    (workspace.workspace_id, workspace.name, workspace.created_at, 1),
                )
        except sqlite3.Error:
            raise WorkspaceError("Cannot create local workspace metadata") from None
        return workspace

    def get(self, workspace_id: str) -> Workspace | None:
        validate_id(workspace_id)
        try:
            with self.journal._connection() as con:
                if not self._exists(con):
                    return None
                row = con.execute(
                    "SELECT * FROM local_workspaces WHERE workspace_id = ?", (workspace_id,)
                ).fetchone()
            if row is None:
                return None
            return self._record(row)
        except (sqlite3.Error, TypeError, ValueError):
            raise WorkspaceError("Cannot read local workspace metadata") from None

    @staticmethod
    def _record(row: sqlite3.Row) -> Workspace:
        if row["workspace_schema_version"] != 1:
            raise WorkspaceError("Unsupported local workspace metadata")
        validate_id(row["workspace_id"])
        validate_name(row["name"])
        created = datetime.fromisoformat(row["created_at"])
        if created.utcoffset() != timezone.utc.utcoffset(created):
            raise WorkspaceError("Invalid local workspace metadata")
        return Workspace(row["workspace_id"], row["name"], row["created_at"])

    @staticmethod
    def list_existing(path: Path, *, limit: int = 100) -> list[Workspace]:
        """Read bounded metadata without constructing/migrating a Journal."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise WorkspaceError("Invalid workspace list limit")
        try:
            if not journal_path_present(path):
                return []
            with closing(sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True)) as con:
                con.row_factory = sqlite3.Row
                if con.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                    raise WorkspaceError("Unsupported local journal schema")
                if not Workspaces._exists(con):
                    return []
                rows = con.execute(
                    "SELECT * FROM local_workspaces ORDER BY created_at DESC, workspace_id ASC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [Workspaces._record(row) for row in rows]
        except (OSError, sqlite3.Error, JournalError, TypeError, ValueError):
            raise WorkspaceError("Cannot list local workspace metadata") from None
