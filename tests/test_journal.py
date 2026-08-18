"""Durable execution journal and manifest invariants."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from vardrrunner import manifests
from vardrrunner.commands.jobs import execute_pending_jobs
from vardrrunner.journal import Journal, JournalError, Phase, normalize_backend_url


def _begin(store: Journal, job_id: str = "job-1"):
    return store.begin(
        job_id=job_id,
        backend_url="https://user:pass@example.com/api/?token=secret#fragment",
        engagement_id="eng-1",
        job_type="httpx",
        tool="httpx",
        target_source="scope",
        command_profile={"limit": 10, "api_key": "vmap_supersecret"},
    )


def test_begin_creates_versioned_wal_journal_and_sanitizes(tmp_path):
    path = tmp_path / "journal.sqlite3"
    store = Journal(path)
    record = _begin(store)

    assert record.phase == Phase.DISCOVERED
    assert record.backend_url == "https://example.com/api"
    assert record.command_profile == {"api_key": "***REDACTED***", "limit": 10}
    with closing(sqlite3.connect(path)) as con, con:
        assert con.execute("PRAGMA user_version").fetchone()[0] == 1
        assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_active_job_is_unique_under_concurrency(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    with ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(lambda _: _begin(store), range(8)))
    assert len({record.run_id for record in records}) == 1


def test_transition_rejects_skips_and_terminal_rewrites(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    record = _begin(store)
    with pytest.raises(JournalError, match="invalid journal transition"):
        store.transition(record.run_id, Phase.EXECUTING)
    store.finish(record.run_id, Phase.FAILED, status="failed")
    with pytest.raises(JournalError, match="terminal journal run"):
        store.transition(record.run_id, Phase.DONE)


def test_artifact_hash_and_terminal_manifest_are_durable(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    artifact = run_dir / "httpx.jsonl"
    artifact.write_text('{"url":"https://example.com"}\n')
    record = _begin(store)
    store.transition(record.run_id, Phase.VALIDATING)
    store.transition(record.run_id, Phase.TARGETS_RESOLVED, target_count=1)
    store.transition(record.run_id, Phase.CLAIMING)
    store.transition(record.run_id, Phase.CLAIMED)
    store.transition(record.run_id, Phase.EXECUTING, run_dir=str(run_dir), pid=123)
    attached = store.attach_artifact(record.run_id, artifact)
    assert attached.artifact_sha256 == manifests.artifact_digest(artifact)[0]
    store.transition(record.run_id, Phase.UPLOADING, upload_state="in_progress")
    store.transition(record.run_id, Phase.FINALIZING, upload_state="succeeded")
    done = store.finish(record.run_id, Phase.DONE, status="done")

    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert done.manifest_path == str(run_dir / "manifest.json")
    assert manifest["manifest_schema_version"] == 1
    assert manifest["artifact_sha256"] == attached.artifact_sha256
    assert "backend_url" not in manifest


def test_atomic_json_redacts_and_leaves_no_temp_file(tmp_path):
    output = tmp_path / "audit.json"
    manifests.write_atomic_json(output, {"token": "secret", "value": "vmap_abcdefghi"})
    assert json.loads(output.read_text()) == {
        "token": "***REDACTED***",
        "value": "***REDACTED***",
    }
    assert list(tmp_path.glob("*.tmp")) == []


def test_newer_or_corrupt_schema_fails_closed(tmp_path):
    newer = tmp_path / "newer.sqlite3"
    with closing(sqlite3.connect(newer)) as con, con:
        con.execute("PRAGMA user_version = 999")
    with pytest.raises(JournalError, match="newer than supported"):
        Journal(newer)

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not sqlite")
    with pytest.raises(JournalError, match="cannot open execution journal"):
        Journal(corrupt)


def test_normalize_backend_url_handles_plain_urls():
    assert normalize_backend_url("https://example.com/") == "https://example.com"
    assert normalize_backend_url("https://example.com:8443/api") == "https://example.com:8443/api"


def test_query_limits_since_and_invalid_inputs(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    first = _begin(store, "job-a")
    store.finish(first.run_id, Phase.SKIPPED, status="skipped")
    second = _begin(store, "job-b")
    assert store.list(since=second.started_at, limit=50)
    assert len(store.list(limit=1)) == 1
    assert store.active_for_job("missing") is None
    assert store.get("missing") is None
    with pytest.raises(JournalError, match="unknown run"):
        store.transition("missing", Phase.DONE)
    with pytest.raises(JournalError, match="unsupported journal field"):
        store.transition(second.run_id, Phase.VALIDATING, bad_field=True)
    with pytest.raises(JournalError, match="is not terminal"):
        store.finish(second.run_id, Phase.EXECUTING, status="active")


def test_invalid_json_in_record_is_rejected(tmp_path):
    path = tmp_path / "journal.sqlite3"
    store = Journal(path)
    record = _begin(store)
    with closing(sqlite3.connect(path)) as con, con:
        con.execute(
            "UPDATE runs SET command_profile = 'not json' WHERE run_id = ?", (record.run_id,)
        )
    with pytest.raises(JournalError, match="invalid JSON"):
        store.get(record.run_id)


def test_job_lifecycle_writes_done_record_and_manifest(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    output = run_dir / "httpx.jsonl"
    output.write_text('{"url":"https://example.com"}\n')
    job = {
        "id": "job-integrated",
        "engagement_id": "eng-1",
        "tool_type": "httpx",
        "target_source": "scope",
        "config": {"limit": 5, "authorization": "must-not-persist"},
    }
    client = MagicMock(base="https://api.example.com")
    client.pending_jobs.return_value = [job]
    client.scope.return_value = {"in": [{"value": "example.com"}], "out": []}
    client.import_file.return_value = {"import_record": {"imported_count": 1}}
    with (
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=run_dir),
        patch("vardrrunner.commands.jobs.runner.run_httpx"),
    ):
        execute_pending_jobs(
            client,
            Console(),
            journal_store=store,
            backend_url="https://api.example.com",
        )
    records = store.list()
    assert len(records) == 1
    assert records[0].phase == Phase.DONE
    assert records[0].command_profile == {"limit": 5}
    assert (run_dir / "manifest.json").exists()


def test_unavailable_journal_prevents_claim(tmp_path):
    job = {
        "id": "job-no-journal",
        "engagement_id": "eng-1",
        "tool_type": "httpx",
        "target_source": "scope",
        "config": {},
    }
    client = MagicMock(base="https://api.example.com")
    client.pending_jobs.return_value = [job]
    broken = MagicMock()
    broken.begin.side_effect = JournalError("disk unavailable")
    with pytest.raises(JournalError, match="disk unavailable"):
        execute_pending_jobs(client, Console(), journal_store=broken)
    client.claim_job.assert_not_called()
