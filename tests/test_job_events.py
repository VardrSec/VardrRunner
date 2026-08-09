"""
Tests for job event posting in the VardrRunner job execution loop.
All HTTP and subprocess calls are mocked.
"""

from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# api.VardrMapClient.post_event
# ---------------------------------------------------------------------------


def test_post_event_calls_correct_endpoint():
    from vardrrunner.api import VardrMapClient

    client = VardrMapClient("https://example.com", "vmap_test")
    with patch.object(client, "post", return_value={"id": "abc"}) as mock_post:
        result = client.post_event("job-1", "started", "runner claimed job")
        mock_post.assert_called_once_with(
            "/jobs/job-1/events",
            json={"kind": "started", "text": "runner claimed job"},
        )
        assert result == {"id": "abc"}


def test_post_event_default_text():
    from vardrrunner.api import VardrMapClient

    client = VardrMapClient("https://example.com", "vmap_test")
    with patch.object(client, "post", return_value={}) as mock_post:
        client.post_event("job-2", "done")
        mock_post.assert_called_once_with(
            "/jobs/job-2/events",
            json={"kind": "done", "text": ""},
        )


# ---------------------------------------------------------------------------
# _emit helper — errors are swallowed
# ---------------------------------------------------------------------------


def test_emit_swallows_api_error():
    from vardrrunner.commands.jobs import _emit

    client = MagicMock()
    client.post_event.side_effect = Exception("network error")
    _emit(client, "job-1", "started")  # must not raise


def test_emit_calls_post_event_with_correct_args():
    from vardrrunner.commands.jobs import _emit

    client = MagicMock()
    _emit(client, "job-99", "targets_resolved", "4 targets from scope")
    client.post_event.assert_called_once_with("job-99", "targets_resolved", "4 targets from scope")


# ---------------------------------------------------------------------------
# run_jobs — events posted at the right lifecycle points for httpx
# ---------------------------------------------------------------------------


def _make_job(tool_type="httpx", target_src="scope"):
    return {
        "id": "job-httpx-1",
        "tool_type": tool_type,
        "target_source": target_src,
        "engagement_id": "prog-1",
        "config": {},
    }


def test_run_jobs_httpx_emits_lifecycle_events(tmp_path):
    from vardrrunner.commands import jobs as jobs_mod

    mock_client = MagicMock()
    mock_client.pending_jobs.return_value = [_make_job("httpx")]
    mock_client.claim_job.return_value = {}
    mock_client.complete_job.return_value = {}
    mock_client.post_event.return_value = {}

    output_file = tmp_path / "httpx.jsonl"
    output_file.write_text('{"host":"example.com"}\n')

    with (
        patch("vardrrunner.commands.jobs.send_heartbeat"),
        patch("vardrrunner.commands.jobs.config.require_auth", return_value=("https://x.com", "k")),
        patch("vardrrunner.commands.jobs.api.VardrMapClient", return_value=mock_client),
        patch("vardrrunner.handlers._resolve_targets", return_value=["https://example.com"]),
        patch("vardrrunner.commands.jobs._confirm"),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs.runner.run_httpx", return_value=0),
    ):
        mock_client.import_file.return_value = {"import_record": {"imported_count": 1}}
        jobs_mod.run_jobs(yes=True)

    event_kinds = [c.args[1] for c in mock_client.post_event.call_args_list]
    assert "started" in event_kinds
    assert "targets_resolved" in event_kinds
    assert "running" in event_kinds
    assert "uploaded" in event_kinds
    assert "done" in event_kinds


def test_run_jobs_tool_missing_emits_failed_event():
    from vardrrunner.commands import jobs as jobs_mod

    mock_client = MagicMock()
    mock_client.pending_jobs.return_value = [_make_job("httpx")]

    with (
        patch("vardrrunner.commands.jobs.send_heartbeat"),
        patch("vardrrunner.commands.jobs.config.require_auth", return_value=("https://x.com", "k")),
        patch("vardrrunner.commands.jobs.api.VardrMapClient", return_value=mock_client),
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=False),
    ):
        jobs_mod.run_jobs(yes=True)

    kinds = [c.args[1] for c in mock_client.post_event.call_args_list]
    assert "failed" in kinds


def test_run_jobs_subfinder_emits_lifecycle_events(tmp_path):
    from vardrrunner.commands import jobs as jobs_mod

    sf_output = tmp_path / "subfinder.txt"
    sf_output.write_text("sub.example.com\napi.example.com\n")

    mock_client = MagicMock()
    mock_client.pending_jobs.return_value = [_make_job("subfinder", "scope")]
    mock_client.scope.return_value = {"in": [{"value": "*.example.com"}], "out": []}
    mock_client.claim_job.return_value = {}
    mock_client.complete_job.return_value = {}
    mock_client.post_event.return_value = {}
    mock_client.import_file.return_value = {"import_record": {"imported_count": 2}}

    with (
        patch("vardrrunner.commands.jobs.send_heartbeat"),
        patch("vardrrunner.commands.jobs.config.require_auth", return_value=("https://x.com", "k")),
        patch("vardrrunner.commands.jobs.api.VardrMapClient", return_value=mock_client),
        patch("vardrrunner.commands.jobs._confirm"),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs.runner.run_subfinder", return_value=0),
    ):
        jobs_mod.run_jobs(yes=True)

    kinds = [c.args[1] for c in mock_client.post_event.call_args_list]
    assert "started" in kinds
    assert "targets_resolved" in kinds
    assert "running" in kinds
    assert "uploaded" in kinds
    assert "done" in kinds
