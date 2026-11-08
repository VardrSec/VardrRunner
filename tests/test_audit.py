"""Audit CLI reads and exports only sanitized journal state."""

import json
from unittest.mock import patch

import pytest
import typer

from vardrrunner import config
from vardrrunner.commands import audit
from vardrrunner.journal import Journal, Phase


def _seed(path):
    store = Journal(path)
    record = store.begin(
        job_id="job-123",
        backend_url="https://api.example.com",
        engagement_id="eng-1",
        job_type="httpx",
        tool="httpx",
        target_source="scope",
        command_profile={"token": "do-not-export"},
    )
    store.finish(record.run_id, Phase.FAILED, status="failed", failure_reason="vmap_abcdefghi")
    return record


def test_list_json_and_show_are_sanitized(tmp_path, capsys, monkeypatch):
    path = tmp_path / "journal.sqlite3"
    record = _seed(path)
    monkeypatch.setattr(config, "JOURNAL_FILE", path)
    audit.list_runs(as_json=True)
    audit.show_run(record.run_id)
    output = capsys.readouterr().out
    assert "do-not-export" not in output
    assert "vmap_abcdefghi" not in output
    assert "***REDACTED***" in output


def test_export_is_atomic_and_versioned(tmp_path, monkeypatch):
    path = tmp_path / "journal.sqlite3"
    _seed(path)
    monkeypatch.setattr(config, "JOURNAL_FILE", path)
    output = tmp_path / "audit.json"
    audit.export_runs(output)
    payload = json.loads(output.read_text())
    assert payload["audit_schema_version"] == 1
    assert payload["run_count"] == 1
    assert payload["runs"][0]["command_profile"]["token"] == "***REDACTED***"


def test_show_unknown_run_exits(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "JOURNAL_FILE", tmp_path / "journal.sqlite3")
    with pytest.raises(typer.Exit):
        audit.show_run("missing")


def test_empty_and_table_list_views(tmp_path, capsys, monkeypatch):
    path = tmp_path / "journal.sqlite3"
    monkeypatch.setattr(config, "JOURNAL_FILE", path)
    audit.list_runs()
    assert "No journaled runs" in capsys.readouterr().out
    _seed(path)
    audit.list_runs(limit=1)
    output = capsys.readouterr().out
    assert "Execution Audit" in output
    assert "job-123" in output


def test_store_and_export_errors_exit_cleanly(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "JOURNAL_FILE", tmp_path / "journal.sqlite3")
    with patch("vardrrunner.commands.audit.Journal", side_effect=audit.JournalError("broken")):
        with pytest.raises(typer.Exit):
            audit.list_runs()
    _seed(config.JOURNAL_FILE)
    with patch(
        "vardrrunner.commands.audit.manifests.write_atomic_json", side_effect=OSError("disk")
    ):
        with pytest.raises(typer.Exit):
            audit.export_runs(tmp_path / "out.json")


def test_scoped_list_and_export_are_local_redacted_and_preserve_other_runs(tmp_path, monkeypatch):
    path = tmp_path / "journal.sqlite3"
    selected = _seed(path)
    store = Journal(path)
    other = store.begin(
        job_id="other-job",
        backend_url="",
        engagement_id="other-workspace",
        job_type="httpx",
        tool="httpx",
        target_source="explicit",
    )
    before = path.read_bytes()
    monkeypatch.setattr(config, "JOURNAL_FILE", path)

    def forbidden(*args, **kwargs):
        raise AssertionError("Local audit must not require Map authentication")

    monkeypatch.setattr(config, "require_auth", forbidden)
    output = tmp_path / "scoped.json"
    audit.export_runs(output, engagement_id="eng-1", limit=1)
    document = json.loads(output.read_text())
    assert document["audit_schema_version"] == 1 and document["run_count"] == 1
    assert document["runs"][0]["run_id"] == selected.run_id
    assert "do-not-export" not in output.read_text() and "vmap_abcdefghi" not in output.read_text()
    assert store.get(other.run_id) == other and path.read_bytes() == before


def test_scoped_json_and_table_history_and_empty_export(tmp_path, capsys, monkeypatch):
    path = tmp_path / "journal.sqlite3"
    selected = _seed(path)
    monkeypatch.setattr(config, "JOURNAL_FILE", path)
    audit.list_runs(engagement_id="eng-1", as_json=True)
    assert selected.run_id in capsys.readouterr().out
    audit.list_runs(engagement_id="missing", as_json=True)
    assert json.loads(capsys.readouterr().out) == []
    audit.list_runs(engagement_id="missing")
    assert "No journaled runs" in capsys.readouterr().out
    output = tmp_path / "empty.json"
    audit.export_runs(output, engagement_id="missing")
    assert json.loads(output.read_text()) == {"audit_schema_version": 1, "run_count": 0, "runs": []}
