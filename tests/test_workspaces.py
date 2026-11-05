"""Local metadata never becomes execution or approval authority."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import asdict
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vardrrunner import api, config
from vardrrunner.cli import app, process_runner
from vardrrunner.journal import Journal
from vardrrunner.workspaces import WorkspaceError, Workspaces


def test_create_and_reopen_preserves_existing_run_and_journal_version(tmp_path):
    path = tmp_path / "journal.sqlite3"
    journal = Journal(path)
    old = journal.begin(
        job_id="map-job",
        backend_url="https://map.example/backend",
        engagement_id="map-eng",
        job_type="httpx",
        tool="httpx",
        target_source="scope",
    )
    workspace = Workspaces(journal).create("Local assessment")
    reopened = Journal(path)
    assert Workspaces(reopened).get(workspace.workspace_id) == workspace
    assert reopened.get(old.run_id) == old
    assert reopened.unfinished() == [old]
    with closing(sqlite3.connect(path)) as con:
        assert con.execute("PRAGMA user_version").fetchone()[0] == 1
        tables = {
            row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert tables == {"runs", "local_workspaces"}
    assert set(asdict(workspace)) == {
        "workspace_id",
        "name",
        "created_at",
        "workspace_schema_version",
    }
    # No approval, contract, grant, issuer, execution or active-selection state was added.


def test_concurrent_creates_never_overwrite_same_label(tmp_path):
    journal = Journal(tmp_path / "journal.sqlite3")
    with ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(lambda _: Workspaces(journal).create("Assessment"), range(8)))
    assert len({r.workspace_id for r in records}) == 8
    assert all(Workspaces(journal).get(r.workspace_id) == r for r in records)


def test_duplicate_id_refuses_without_overwriting_existing_metadata(tmp_path):
    store = Workspaces(Journal(tmp_path / "journal.sqlite3"))
    with patch("vardrrunner.workspaces.uuid.uuid4") as uuid:
        uuid.return_value.hex = "a" * 32
        first = store.create("First")
        with pytest.raises(WorkspaceError, match="Cannot create"):
            store.create("Second")
    assert store.get(first.workspace_id) == first


@pytest.mark.parametrize(
    "name", ["", " spaced", "spaced ", "line\nbreak", "\x1b[0m", "a" * 161, "vmap_supersecret123"]
)
def test_invalid_names_create_no_workspace_state(tmp_path, name):
    journal = Journal(tmp_path / "journal.sqlite3")
    with pytest.raises(WorkspaceError):
        Workspaces(journal).create(name)
    with journal._connection() as con:
        assert (
            con.execute("SELECT name FROM sqlite_master WHERE name='local_workspaces'").fetchone()
            is None
        )


def test_missing_lookup_does_not_create_workspace_table(tmp_path):
    journal = Journal(tmp_path / "journal.sqlite3")
    assert Workspaces(journal).get("b" * 32) is None
    with journal._connection() as con:
        assert (
            con.execute("SELECT name FROM sqlite_master WHERE name='local_workspaces'").fetchone()
            is None
        )


def test_unsupported_schema_refuses_read_and_write_without_repair(tmp_path):
    journal = Journal(tmp_path / "journal.sqlite3")
    with journal._connection() as con:
        con.execute("CREATE TABLE local_workspaces (future TEXT)")
        con.execute("INSERT INTO local_workspaces VALUES ('retained')")
    store = Workspaces(journal)
    for operation in (
        lambda: store.get("a" * 32),
        lambda: store.create("Assessment"),
        lambda: Workspaces.list_existing(journal.path),
    ):
        with pytest.raises(WorkspaceError, match="Unsupported"):
            operation()
    with journal._connection() as con:
        assert con.execute("SELECT future FROM local_workspaces").fetchall()[0][0] == "retained"


@pytest.mark.parametrize(
    "column,value",
    [
        ("name", "vmap_supersecret123"),
        ("created_at", "invalid"),
        ("created_at", "2026-11-03T00:00:00"),
    ],
)
def test_corrupt_metadata_is_not_reported_valid(tmp_path, column, value):
    journal = Journal(tmp_path / "journal.sqlite3")
    store = Workspaces(journal)
    record = store.create("Assessment")
    with journal._connection() as con:
        # Column is one of this test's literal parameters, never user input.
        assert column in {"name", "created_at"}
        con.execute(f"UPDATE local_workspaces SET {column}=?", (value,))
    with pytest.raises(WorkspaceError):
        store.get(record.workspace_id)
    with pytest.raises(WorkspaceError):
        Workspaces.list_existing(journal.path)


def test_list_existing_is_bounded_stable_and_preserves_mixed_journal(tmp_path):
    path = tmp_path / "journal.sqlite3"
    journal = Journal(path)
    connected = journal.begin(
        job_id="connected-fixture",
        backend_url="https://map.invalid",
        engagement_id="map-only",
        job_type="httpx",
        tool="httpx",
        target_source="scope",
    )
    store = Workspaces(journal)
    records = [store.create(label) for label in ("First", "Second", "Third")]
    with journal._connection() as con:
        for record, timestamp in zip(
            records,
            ("2026-11-01T00:00:00+00:00", "2026-11-02T00:00:00+00:00", "2026-11-02T00:00:00+00:00"),
            strict=True,
        ):
            con.execute(
                "UPDATE local_workspaces SET created_at=? WHERE workspace_id=?",
                (timestamp, record.workspace_id),
            )
    expected = sorted(
        (store.get(r.workspace_id) for r in records),
        key=lambda r: (-int(r.created_at[8:10]), r.workspace_id),
    )
    before = path.read_bytes()
    with patch(
        "vardrrunner.workspaces.Journal",
        side_effect=AssertionError("List must not initialize/migrate"),
    ):
        assert Workspaces.list_existing(path, limit=2) == expected[:2]
    assert path.read_bytes() == before
    assert journal.get(connected.run_id) == connected
    assert all(
        set(asdict(row)) == {"workspace_id", "name", "created_at", "workspace_schema_version"}
        for row in expected
    )


def test_list_missing_or_no_workspace_table_does_not_initialize(tmp_path):
    path = tmp_path / "missing" / "journal.sqlite3"
    assert Workspaces.list_existing(path) == []
    assert not path.parent.exists()
    existing = tmp_path / "existing.sqlite3"
    Journal(existing)
    before = existing.read_bytes()
    assert Workspaces.list_existing(existing) == []
    assert existing.read_bytes() == before


@pytest.mark.parametrize("limit", [0, -1, 1001, True, "7"])
def test_list_invalid_limit_refuses_before_creating_journal(tmp_path, limit):
    path = tmp_path / "absent.sqlite3"
    with pytest.raises(WorkspaceError):
        Workspaces.list_existing(path, limit=limit)
    assert not path.exists()


def test_cli_list_is_local_and_errors_emit_no_metadata(tmp_path, monkeypatch):
    path = tmp_path / "journal.sqlite3"
    monkeypatch.setattr(config, "JOURNAL_FILE", path)
    record = Workspaces(Journal(path)).create("Assessment")
    # Preserve the global maintenance/security hook in production; isolate it in tests.
    monkeypatch.setattr(process_runner, "cleanup_sensitive_temp_dirs", lambda: None)

    def forbidden(*args, **kwargs):
        raise AssertionError("No authentication, provider or process for listing")

    monkeypatch.setattr(config, "load", forbidden)
    monkeypatch.setattr(config, "require_auth", forbidden)
    monkeypatch.setattr(config, "get_api_key", forbidden)
    monkeypatch.setattr(api, "VardrMapClient", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    listed = CliRunner().invoke(app, ["workspace", "list"])
    assert listed.exit_code == 0, listed.output
    assert json.loads(listed.output) == [asdict(record)]
    with closing(sqlite3.connect(path)) as con, con:
        con.execute("UPDATE local_workspaces SET name=?", ("vmap_syntheticneveremit",))
    before = path.read_bytes()
    failed = CliRunner().invoke(app, ["workspace", "list"])
    assert failed.exit_code == 1 and "vmap_syntheticneveremit" not in failed.output
    assert path.read_bytes() == before


def test_list_future_journal_refuses_without_migration(tmp_path):
    path = tmp_path / "future.sqlite3"
    with closing(sqlite3.connect(path)) as con, con:
        con.execute("PRAGMA user_version=999")
        con.execute("CREATE TABLE retained (value TEXT)")
        con.execute("INSERT INTO retained VALUES ('synthetic retained')")
    before = path.read_bytes()
    with pytest.raises(WorkspaceError, match="Unsupported"):
        Workspaces.list_existing(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("raw", [b"", b"vmap_synthetic_unreadable_fixture"])
def test_list_empty_or_corrupt_existing_journal_is_not_initialized(tmp_path, raw):
    path = tmp_path / "existing.sqlite3"
    path.write_bytes(raw)
    with pytest.raises(WorkspaceError):
        Workspaces.list_existing(path)
    assert path.read_bytes() == raw


def test_list_unknown_filesystem_observation_is_not_reported_empty(tmp_path):
    with (
        patch("pathlib.Path.lstat", side_effect=PermissionError("synthetic private path")),
        patch("vardrrunner.workspaces.sqlite3.connect") as connect,
    ):
        with pytest.raises(WorkspaceError, match="Cannot list"):
            Workspaces.list_existing(tmp_path / "journal.sqlite3")
    connect.assert_not_called()


def test_cli_needs_no_map_credentials_provider_or_process(tmp_path, monkeypatch):
    path = tmp_path / "journal.sqlite3"
    monkeypatch.setattr(config, "JOURNAL_FILE", path)

    def forbidden(*args, **kwargs):
        raise AssertionError("External authority or execution is forbidden")

    monkeypatch.setattr(config, "load", forbidden)
    monkeypatch.setattr(config, "require_auth", forbidden)
    monkeypatch.setattr(config, "get_api_key", forbidden)
    monkeypatch.setattr(api, "VardrMapClient", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    # Preserve the existing global startup hook in production, isolate it in this test.
    monkeypatch.setattr(process_runner, "cleanup_sensitive_temp_dirs", lambda: None)
    runner = CliRunner()
    created = runner.invoke(app, ["workspace", "create", "Assessment"])
    assert created.exit_code == 0, created.output
    payload = json.loads(created.output)
    shown = runner.invoke(app, ["workspace", "show", payload["workspace_id"]])
    assert shown.exit_code == 0, shown.output
    assert json.loads(shown.output) == payload
    assert not config.CONFIG_FILE.exists()


@pytest.mark.parametrize(
    "args",
    [
        ["workspace", "show", "a" * 32],
        ["workspace", "show", "../../private"],
        ["workspace", "create", "vmap_supersecret123"],
    ],
)
def test_cli_failure_has_no_values_or_new_journal(tmp_path, monkeypatch, args):
    path = tmp_path / "missing/journal.sqlite3"
    monkeypatch.setattr(config, "JOURNAL_FILE", path)
    monkeypatch.setattr(process_runner, "cleanup_sensitive_temp_dirs", lambda: None)
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    assert args[-1] not in result.output
    assert not path.exists()
