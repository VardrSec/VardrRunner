"""Reject observed special objects without claiming race-safe SQLite opens."""

import os
import sqlite3
import stat
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vardrrunner import config, credential_grants
from vardrrunner.cli import app, process_runner
from vardrrunner.journal import Journal, JournalError, journal_path_present
from vardrrunner.workspaces import WorkspaceError, Workspaces


def fifo(path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("Native FIFO fixture unavailable")
    os.mkfifo(path)


@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_observed_special_object_refuses_all_opens_and_public_list(tmp_path, monkeypatch, kind):
    path = tmp_path / "journal.sqlite3"
    fifo(path) if kind == "fifo" else path.mkdir()
    monkeypatch.setattr(config, "JOURNAL_FILE", path)
    monkeypatch.setattr(process_runner, "cleanup_sensitive_temp_dirs", lambda: None)
    with patch(
        "sqlite3.connect", side_effect=AssertionError("Must refuse before SQLite")
    ) as connect:
        with pytest.raises(JournalError):
            Journal.read_existing(path, "synthetic-run")
        with pytest.raises(JournalError):
            Journal(path)
        with pytest.raises(WorkspaceError):
            Workspaces.list_existing(path)
        with pytest.raises(credential_grants.GrantError, match="grant_state_unavailable"):
            with credential_grants.Store().transaction():
                pytest.fail("Special object admitted")
        result = CliRunner().invoke(app, ["workspace", "list"])
        assert result.exit_code == 1
        assert result.output == "Cannot list workspace metadata; check the local journal.\n"
        connect.assert_not_called()
    assert path.lstat().st_mode & (stat.S_IFIFO | stat.S_IFDIR)
    assert not config.CONFIG_FILE.exists()


def test_journal_rechecks_after_initialization(tmp_path):
    path = tmp_path / "journal.sqlite3"
    journal = Journal(path)
    retained = tmp_path / "retained.sqlite3"
    path.rename(retained)
    fifo(path)
    with patch("sqlite3.connect", side_effect=AssertionError("Must not open FIFO")) as connect:
        with pytest.raises(JournalError):
            journal.list()
        connect.assert_not_called()
    assert retained.is_file()


def test_grant_store_checks_its_separate_connection(tmp_path, monkeypatch):
    path = config.journal_file()
    Journal(path)
    retained = tmp_path / "retained-grant-journal.sqlite3"

    def replace_after_initializer(actual):
        assert actual == path
        path.rename(retained)
        fifo(path)

    monkeypatch.setattr(credential_grants, "Journal", replace_after_initializer)
    with patch("sqlite3.connect", side_effect=AssertionError("Must not open FIFO")) as connect:
        with pytest.raises(credential_grants.GrantError, match="grant_state_unavailable"):
            with credential_grants.Store().transaction():
                pytest.fail("Special object admitted")
        connect.assert_not_called()
    assert retained.is_file()
    assert not config.CONFIG_FILE.exists()


def test_absent_read_does_not_initialize_and_ordinary_creation_still_works(tmp_path):
    path = tmp_path / "absent" / "journal.sqlite3"
    assert not journal_path_present(path)
    assert Workspaces.list_existing(path) == []
    assert not path.parent.exists()
    journal = Journal(path)
    assert journal_path_present(path)
    assert journal.list() == []


def symlink(target, alias):
    try:
        alias.symlink_to(target)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Native symlink fixture privilege unavailable")
        raise


def test_regular_leaf_alias_retains_live_wal_visibility(tmp_path):
    path = tmp_path / "journal.sqlite3"
    journal = Journal(path)
    first = Workspaces(journal).create("First")
    run = journal.begin(
        job_id="fixture",
        backend_url="",
        engagement_id=first.workspace_id,
        job_type="fixture",
        tool="fixture",
        target_source="explicit",
        command_profile={},
    )
    alias = tmp_path / "alias.sqlite3"
    symlink(path, alias)
    with closing(sqlite3.connect(path)) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "UPDATE local_workspaces SET name='Committed in WAL' WHERE workspace_id=?",
            (first.workspace_id,),
        )
        writer.execute("UPDATE runs SET status=? WHERE run_id=?", ("committed-in-wal", run.run_id))
        writer.commit()
        assert path.with_name(path.name + "-wal").stat().st_size > 0
        for source in (path, alias):
            assert Journal.read_existing(source, run.run_id).status == "committed-in-wal"
            assert journal_path_present(source)
            assert Workspaces.list_existing(source)[0].name == "Committed in WAL"
            assert Workspaces(Journal(source)).get(first.workspace_id).name == "Committed in WAL"


@pytest.mark.parametrize("target_kind", ["fifo", "missing"])
def test_leaf_alias_to_unsupported_target_refuses_before_sqlite(tmp_path, target_kind):
    target = tmp_path / "target"
    if target_kind == "fifo":
        fifo(target)
    alias = tmp_path / "alias.sqlite3"
    symlink(target, alias)
    with patch("sqlite3.connect", side_effect=AssertionError("Must not open target")) as connect:
        with pytest.raises(JournalError):
            Journal.read_existing(alias, "synthetic-run")
        with pytest.raises(JournalError):
            Journal(alias)
        with pytest.raises(WorkspaceError):
            Workspaces.list_existing(alias)
        connect.assert_not_called()


def test_observed_windows_reparse_attribute_refuses(tmp_path):
    path = tmp_path / "journal.sqlite3"
    observed = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_file_attributes=0x400)
    with patch.object(type(path), "lstat", return_value=observed):
        with pytest.raises(JournalError, match="reparse"):
            journal_path_present(path)


def test_inspection_errors_are_fixed_and_not_empty_inventory(tmp_path):
    path = tmp_path / "journal.sqlite3"
    with patch.object(type(path), "lstat", side_effect=PermissionError("synthetic-private-detail")):
        with pytest.raises(JournalError, match="Cannot inspect journal path") as error:
            journal_path_present(path)
        assert "synthetic-private-detail" not in str(error.value)
        with pytest.raises(WorkspaceError):
            Workspaces.list_existing(path)
