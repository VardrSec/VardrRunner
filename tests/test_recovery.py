"""Startup reconciliation resumes only operations with a known-safe outcome."""

from unittest.mock import MagicMock, patch

from vardrrunner import errors
from vardrrunner.journal import Journal, Phase
from vardrrunner.recovery import process_alive, reconcile


def _run_at(store: Journal, phase: Phase, run_dir=None, tool="httpx"):
    record = store.begin(
        job_id=f"job-{phase.value}",
        backend_url="https://api.example.com",
        engagement_id="eng-1",
        job_type=tool,
        tool=tool,
        target_source="scope",
    )
    if phase == Phase.DISCOVERED:
        return record
    record = store.transition(record.run_id, Phase.VALIDATING)
    if phase == Phase.VALIDATING:
        return record
    record = store.transition(record.run_id, Phase.TARGETS_RESOLVED, target_count=1)
    if phase == Phase.TARGETS_RESOLVED:
        return record
    record = store.transition(record.run_id, Phase.CLAIMING)
    if phase == Phase.CLAIMING:
        return record
    record = store.transition(record.run_id, Phase.CLAIMED)
    if phase == Phase.CLAIMED:
        return record
    record = store.transition(
        record.run_id, Phase.EXECUTING, run_dir=str(run_dir) if run_dir else None, pid=999999
    )
    if phase == Phase.EXECUTING:
        return record
    artifact = run_dir / "httpx.jsonl"
    artifact.write_text('{"url":"https://example.com"}\n')
    record = store.attach_artifact(record.run_id, artifact)
    if phase == Phase.ARTIFACT_READY:
        return record
    record = store.transition(record.run_id, Phase.UPLOADING, upload_state="in_progress")
    if phase == Phase.UPLOADING:
        return record
    return store.transition(record.run_id, Phase.FINALIZING, upload_state="succeeded")


def test_preclaim_run_is_closed_locally_without_backend_mutation(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    record = _run_at(store, Phase.VALIDATING)
    client = MagicMock()
    result = reconcile(store, client, "https://api.example.com")
    assert result.failed == 1
    assert store.get(record.run_id).phase == Phase.INTERRUPTED
    client.complete_job.assert_not_called()


def test_dead_claimed_run_is_failed_on_backend(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    record = _run_at(store, Phase.CLAIMED)
    client = MagicMock()
    result = reconcile(store, client, "https://api.example.com")
    assert result.failed == 1
    client.complete_job.assert_called_once()
    assert store.get(record.run_id).failure_category == errors.FailureCategory.UNKNOWN.value


def test_live_tool_process_is_deferred(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    record = _run_at(store, Phase.EXECUTING, tmp_path / "run")
    with patch("vardrrunner.recovery.process_alive", return_value=True):
        result = reconcile(store, MagicMock(), "https://api.example.com")
    assert result.deferred == 1
    assert store.get(record.run_id).phase == Phase.EXECUTING


def test_completed_artifact_is_uploaded_and_finalized(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.EXECUTING, run_dir)
    (run_dir / "httpx.jsonl").write_text('{"url":"https://example.com"}\n')
    client = MagicMock()
    client.import_file.return_value = {"import_record": {"imported_count": 1}}
    with patch("vardrrunner.recovery.process_alive", return_value=False):
        result = reconcile(store, client, "https://api.example.com")
    assert result.recovered == 1
    assert store.get(record.run_id).phase == Phase.DONE
    client.import_file.assert_called_once()
    client.complete_job.assert_called_once_with(record.job_id, "done")
    assert (run_dir / "manifest.json").exists()


def test_unknown_upload_outcome_is_never_replayed(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.UPLOADING, run_dir)
    client = MagicMock()
    result = reconcile(store, client, "https://api.example.com")
    assert result.failed == 1
    client.import_file.assert_not_called()
    client.complete_job.assert_called_once()
    final = store.get(record.run_id)
    assert final.phase == Phase.INTERRUPTED
    assert final.failure_category == errors.FailureCategory.UPLOAD_FAILED.value


def test_finalization_is_retried_without_reupload(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.FINALIZING, run_dir)
    client = MagicMock()
    result = reconcile(store, client, "https://api.example.com")
    assert result.recovered == 1
    client.import_file.assert_not_called()
    client.complete_job.assert_called_once_with(record.job_id, "done")
    assert store.get(record.run_id).phase == Phase.DONE


def test_backend_failure_keeps_run_open_for_next_reconciliation(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    record = _run_at(store, Phase.CLAIMED)
    client = MagicMock()
    client.complete_job.side_effect = RuntimeError("offline")
    result = reconcile(store, client, "https://api.example.com")
    assert result.deferred == 1
    assert store.get(record.run_id).phase == Phase.CLAIMED


def test_other_backend_is_not_touched(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    record = _run_at(store, Phase.CLAIMED)
    client = MagicMock()
    result = reconcile(store, client, "https://different.example.com")
    assert result.foreign_backend == 1
    assert store.get(record.run_id).phase == Phase.CLAIMED
    client.complete_job.assert_not_called()


def test_missing_artifact_and_backend_failure_is_deferred(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.EXECUTING, run_dir)
    client = MagicMock()
    client.complete_job.side_effect = RuntimeError("offline")
    with patch("vardrrunner.recovery.process_alive", return_value=False):
        result = reconcile(store, client, "https://api.example.com")
    assert result.deferred == 1
    assert store.get(record.run_id).phase == Phase.EXECUTING


def test_recovery_upload_failure_becomes_unknown_and_is_not_replayed(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.ARTIFACT_READY, run_dir)
    client = MagicMock()
    client.import_file.side_effect = RuntimeError("response lost")
    first = reconcile(store, client, "https://api.example.com")
    assert first.deferred == 1
    assert store.get(record.run_id).phase == Phase.UPLOADING
    client.import_file.reset_mock()
    client.import_file.side_effect = None
    second = reconcile(store, client, "https://api.example.com")
    assert second.failed == 1
    client.import_file.assert_not_called()


def test_recovery_upload_success_but_finalization_failure_is_deferred(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.ARTIFACT_READY, run_dir)
    client = MagicMock()
    client.import_file.return_value = {"import_record": {"imported_count": 1}}
    client.complete_job.side_effect = RuntimeError("offline")
    result = reconcile(store, client, "https://api.example.com")
    assert result.deferred == 1
    assert store.get(record.run_id).phase == Phase.FINALIZING


def test_finalization_backend_failure_remains_retryable(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.FINALIZING, run_dir)
    client = MagicMock()
    client.complete_job.side_effect = RuntimeError("offline")
    result = reconcile(store, client, "https://api.example.com")
    assert result.deferred == 1
    assert store.get(record.run_id).phase == Phase.FINALIZING


def test_unknown_handler_with_artifact_is_failed(tmp_path):
    store = Journal(tmp_path / "journal.sqlite3")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.ARTIFACT_READY, run_dir, tool="removed-tool")
    client = MagicMock()
    result = reconcile(store, client, "https://api.example.com")
    assert result.failed == 1
    assert store.get(record.run_id).failure_category == errors.FailureCategory.UNSUPPORTED_JOB.value


def test_reconciliation_summary_is_printed(tmp_path, capsys):
    from rich.console import Console

    store = Journal(tmp_path / "journal.sqlite3")
    _run_at(store, Phase.DISCOVERED)
    reconcile(store, MagicMock(), "https://api.example.com", Console())
    assert "Reconciliation:" in capsys.readouterr().out


def test_process_alive_guards_invalid_pid():
    assert process_alive(None) is False
    assert process_alive(0) is False


def test_process_alive_windows_queries_handle_without_kill():
    fake_kernel32 = MagicMock()
    fake_kernel32.OpenProcess.return_value = 0
    fake_ctypes = MagicMock()
    fake_ctypes.windll.kernel32 = fake_kernel32
    with (
        patch("vardrrunner.recovery.os.name", "nt"),
        patch.dict("sys.modules", {"ctypes": fake_ctypes}),
        patch("vardrrunner.recovery.os.kill") as kill,
    ):
        assert process_alive(1234) is False
    kill.assert_not_called()


def test_process_alive_posix_error_semantics():
    with (
        patch("vardrrunner.recovery.os.name", "posix"),
        patch("vardrrunner.recovery.os.kill", side_effect=PermissionError),
    ):
        assert process_alive(1234) is True
    with (
        patch("vardrrunner.recovery.os.name", "posix"),
        patch("vardrrunner.recovery.os.kill", side_effect=ProcessLookupError),
    ):
        assert process_alive(1234) is False
