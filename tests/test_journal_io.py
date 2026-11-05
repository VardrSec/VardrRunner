"""Canonical WAL identity and native Windows replacement boundaries."""

import ctypes
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vardrrunner import journal as journal_module
from vardrrunner import windows_journal
from vardrrunner.journal import Journal, JournalError, RetainedPaths, journal_connection
from vardrrunner.workspaces import Workspaces


def begin(journal):
    return journal.begin(
        job_id="fixture",
        backend_url="",
        engagement_id="fixture",
        job_type="fixture",
        tool="fixture",
        target_source="explicit",
    )


def test_retention_inventory_reads_every_record_without_initialization(tmp_path, monkeypatch):
    path = tmp_path / "journal.sqlite3"
    journal = Journal(path)
    first = begin(journal)
    with journal._connection() as con:
        # More records than ordinary audit-list pagination may return.
        con.executemany(
            "INSERT INTO runs SELECT ? || run_id, ? || job_id, backend_url, engagement_id, "
            "job_type, tool, job_schema_version, target_source, target_count, command_profile, "
            "phase, pid, run_dir, artifact_path, artifact_sha256, artifact_size, manifest_path, "
            "last_event, upload_state, started_at, claimed_at, completed_at, status, "
            "failure_category, failure_reason, warnings_json, updated_at FROM runs WHERE run_id=?",
            [(str(index), str(index), first.run_id) for index in range(1010)],
        )
    with patch.object(Journal, "_migrate", side_effect=AssertionError("Must not migrate")):
        records = Journal.read_existing_paths(path)
    assert len(records) == 1011
    assert records == [RetainedPaths(None, None, None)] * 1011
    monkeypatch.setattr(journal_module, "RETENTION_RECORD_LIMIT", 1010)
    with pytest.raises(JournalError, match="retention inventory exceeds safe limit"):
        Journal.read_existing_paths(path)
    missing = tmp_path / "absent" / "journal.sqlite3"
    with pytest.raises(JournalError):
        Journal.read_existing_paths(missing)
    assert not missing.parent.exists()


def test_retention_inventory_refuses_unsupported_schema(tmp_path):
    path = tmp_path / "future.sqlite3"
    with sqlite3.connect(path) as con:
        con.execute("PRAGMA user_version=999")
    con.close()
    with pytest.raises(JournalError, match="unsupported read-only journal schema"):
        Journal.read_existing_paths(path)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows sharing semantics")
@pytest.mark.parametrize("operation", ["read", "write", "workspaces"])
@pytest.mark.parametrize("mutation", ["leaf", "ancestor"])
def test_replacement_at_actual_sqlite_open_is_blocked(tmp_path, operation, mutation):
    root = tmp_path / "state"
    path = root / "journal.sqlite3"
    journal = Journal(path)
    record = begin(journal)
    workspace = Workspaces(journal).create("Original workspace")
    replacement = tmp_path / "replacement.sqlite3"
    other = Journal(replacement)
    Workspaces(other).create("Replacement workspace")
    attempts = []
    connect = sqlite3.connect

    def replace_at_open(target, **kwargs):
        # This is after path inspection/pinning and immediately before SQLite's
        # real open, where a pathname-only check previously accepted replacement.
        with pytest.raises(PermissionError):
            if mutation == "leaf":
                os.replace(replacement, path)
            else:
                root.rename(tmp_path / "moved-state")
        attempts.append(True)
        return connect(target, **kwargs)

    with patch("sqlite3.connect", side_effect=replace_at_open):
        if operation == "read":
            assert Journal.read_existing(path, record.run_id) == record
        elif operation == "write":
            assert journal.list() == [record]
        else:
            assert Workspaces.list_existing(path) == [workspace]
    assert attempts == [True]
    assert replacement.exists()
    # The guard must not leak a handle and permanently lock the installation.
    root.rename(tmp_path / "released-state")


@pytest.mark.skipif(os.name != "nt", reason="Native Windows sharing semantics")
def test_pin_lasts_until_connection_closes_and_connect_errors_release_it(tmp_path):
    path = tmp_path / "journal.sqlite3"
    Journal(path)
    with journal_connection(path):
        with pytest.raises(PermissionError):
            path.rename(tmp_path / "locked.sqlite3")
    with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("fixture")):
        with pytest.raises(sqlite3.OperationalError):
            with journal_connection(path):
                pytest.fail("Connection unexpectedly succeeded")
    path.rename(tmp_path / "released.sqlite3")


@pytest.mark.skipif(os.name != "nt", reason="Native Windows observed-to-pinned identity")
@pytest.mark.parametrize("existing", [False, True])
def test_replacement_before_leaf_pin_refuses_before_sqlite(tmp_path, monkeypatch, existing):
    path = tmp_path / "journal.sqlite3"
    if existing:
        journal = Journal(path)
        begin(journal)
    replacement = tmp_path / "replacement.sqlite3"
    Journal(replacement)
    retained = tmp_path / "retained.sqlite3"
    original_open = windows_journal.WindowsJournalPin._open
    replaced = []

    def replace_before_pin(self, target, *, directory=False):
        if not directory and not replaced:
            if existing:
                path.rename(retained)
            replacement.rename(path)
            replaced.append(True)
        return original_open(self, target, directory=directory)

    monkeypatch.setattr(windows_journal.WindowsJournalPin, "_open", replace_before_pin)
    with patch("sqlite3.connect", side_effect=AssertionError("Must refuse before SQLite")):
        with pytest.raises(JournalError, match="Cannot pin journal path"):
            if existing:
                Journal.read_existing(path, "fixture")
            else:
                Journal(path)
    assert replaced == [True]
    assert retained.exists() == existing
    path.rename(tmp_path / "released.sqlite3")


@pytest.mark.skipif(os.name != "nt", reason="Native Windows file identity")
def test_windows_hardlink_alias_refuses_separate_wal_names(tmp_path):
    path = tmp_path / "journal.sqlite3"
    Journal(path)
    alias = tmp_path / "alias.sqlite3"
    try:
        os.link(path, alias)
    except PermissionError as exc:
        if getattr(exc, "winerror", None) == 5:
            pytest.skip("Native hardlink fixture permission unavailable")
        raise
    with patch("sqlite3.connect", side_effect=AssertionError("Must refuse before SQLite")):
        for source in (path, alias):
            with pytest.raises(JournalError, match="Cannot pin journal path"):
                Journal.read_existing(source, "fixture")
    alias.unlink()
    assert Journal.read_existing_paths(path) == []


@pytest.mark.parametrize("invalid", ["oversized", "wrong_type", "total"])
def test_retention_paths_refuse_incomplete_or_oversized_inventory(tmp_path, monkeypatch, invalid):
    path = tmp_path / "journal.sqlite3"
    journal = Journal(path)
    record = begin(journal)
    value = b"not-text" if invalid == "wrong_type" else "a" * 32
    with journal._connection() as con:
        con.execute("UPDATE runs SET run_dir=? WHERE run_id=?", (value, record.run_id))
    if invalid == "oversized":
        monkeypatch.setattr(journal_module, "RETENTION_PATH_BYTES", 31)
    elif invalid == "total":
        monkeypatch.setattr(journal_module, "RETENTION_TOTAL_BYTES", 31)
    with pytest.raises(JournalError):
        Journal.read_existing_paths(path)


def test_retention_path_limit_checks_decoded_utf8_for_utf16_journal(tmp_path):
    path = tmp_path / "utf16.sqlite3"
    with sqlite3.connect(path) as con:
        con.execute("PRAGMA encoding='UTF-16le'")
        # Persist the encoding before Journal creates its actual schema.
        con.execute("CREATE TABLE encoding_fixture (value TEXT)")
    con.close()
    journal = Journal(path)
    record = begin(journal)
    value = "界" * 1800
    with journal._connection() as con:
        con.execute("UPDATE runs SET run_dir=? WHERE run_id=?", (value, record.run_id))
        assert con.execute("PRAGMA encoding").fetchone()[0] == "UTF-16le"
        assert con.execute("SELECT length(CAST(run_dir AS BLOB)) FROM runs").fetchone()[0] == 3600
    assert len(value.encode("utf-8")) == 5400
    with pytest.raises(JournalError, match="unsupported journal retention path"):
        Journal.read_existing_paths(path)


@pytest.fixture
def pin():
    io = object.__new__(windows_journal.WindowsJournalPin)
    io.path = Path("fixture")
    io.create = False
    io.observed = None
    io.handles = []

    def information(handle, target):
        target._obj.index_low = 1
        target._obj.links = 1
        return True

    io.kernel = SimpleNamespace(
        CreateFileW=lambda *args: 7,
        GetFileType=lambda handle: 1,
        GetFileInformationByHandle=information,
        CloseHandle=lambda handle: True,
    )
    return io


@pytest.mark.parametrize("handle", [None, 0, ctypes.c_void_p(-1).value])
def test_invalid_native_handles_refuse(pin, handle):
    pin.kernel.CreateFileW = lambda *args: handle
    with pytest.raises(windows_journal.WindowsJournalError, match="journal_handle_unavailable"):
        pin._open(pin.path)
    assert pin.handles == []


@pytest.mark.parametrize(
    "attributes,links,kind", [(0x400, 1, 1), (0x10, 1, 1), (0, 2, 1), (0, 1, 2)]
)
def test_native_open_validates_actual_handle(pin, attributes, links, kind):
    def information(handle, target):
        target._obj.attributes = attributes
        target._obj.index_low = 1
        target._obj.links = links
        return True

    pin.kernel.GetFileInformationByHandle = information
    pin.kernel.GetFileType = lambda handle: kind
    with pytest.raises(windows_journal.WindowsJournalError, match="journal_handle_unsupported"):
        with pin:
            pytest.fail("Unsupported handle admitted")
    assert pin.handles == []


def test_native_open_flags_allow_database_writers_but_deny_replacement(pin):
    calls = []
    pin.kernel.CreateFileW = lambda *args: calls.append(args) or 7
    pin._open(pin.path)
    assert calls[0][1:6] == (0x80, 3, None, 3, 0x00200000)
    pin.close()
    pin.create = True
    pin._open(pin.path)
    assert calls[1][1:6] == (0x40000080, 3, None, 1, 0x00200000)
    pin.close()


def test_native_close_attempts_all_handles_in_reverse(pin):
    calls = []
    pin.handles = [1, 2]
    pin.kernel.CloseHandle = lambda handle: calls.append(handle) or False
    with pytest.raises(windows_journal.WindowsJournalError, match="journal_handle_close_failed"):
        pin.close()
    assert calls == [2, 1]
    assert pin.handles == []
