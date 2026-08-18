import threading
import time
from unittest.mock import MagicMock, patch

import pytest
import typer
from rich.console import Console

from vardrrunner import compatibility, configs, resources, targets
from vardrrunner.commands import jobs
from vardrrunner.commands import run as run_command


def test_job_envelope_rejects_unsupported_or_boolean_schema():
    base = {
        "id": "job-1",
        "tool_type": "httpx",
        "target_source": "scope",
        "engagement_id": "eng-1",
    }
    for version in (True, 2, "1"):
        with pytest.raises(configs.ConfigError, match="schema_version"):
            configs.JobEnvelope.from_dict({**base, "schema_version": version})


@pytest.mark.parametrize(
    "unsafe",
    [
        "-o",
        "two targets",
        "bad\nvalue",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://",
    ],
)
def test_target_shape_rejects_unsafe_values(unsafe):
    with pytest.raises(targets.TargetValidationError):
        targets.validate_targets([unsafe])


def test_target_shape_trims_and_deduplicates():
    assert targets.validate_targets([" example.com ", "example.com", ""]) == ["example.com"]


def test_target_shape_rejects_non_string_values():
    with pytest.raises(targets.TargetValidationError, match="not a string"):
        targets.validate_targets([123])  # type: ignore[list-item]


def test_target_shape_rejects_overlong_value():
    with pytest.raises(targets.TargetValidationError, match="exceeds"):
        targets.validate_targets(["a" * (targets.MAX_TARGET_LENGTH + 1)])


def test_inline_invalid_target_and_missing_source_exit_cleanly(capsys):
    with pytest.raises(typer.Exit):
        targets._resolve_targets(MagicMock(), "eng", False, False, "-o", None, None, 10)
    assert "Invalid target input" in capsys.readouterr().out
    with pytest.raises(typer.Exit):
        targets._resolve_targets(MagicMock(), "eng", False, False, None, None, None, 10)
    assert "No target source" in capsys.readouterr().out


def test_oversized_target_file_exits_cleanly(tmp_path, monkeypatch, capsys):
    path = tmp_path / "targets.txt"
    path.write_text("example.com")
    monkeypatch.setattr(targets, "MAX_TARGET_FILE_BYTES", 1)
    with pytest.raises(typer.Exit):
        targets._resolve_targets(MagicMock(), "eng", False, False, None, path, None, 10)
    assert "exceeds" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("scope", "recon"),
    [
        ("bad", None),
        ({"in": "bad"}, None),
        ({"in": ["bad"]}, None),
        ({"in": [{"value": 1}]}, None),
        (None, {}),
        (None, ["bad"]),
    ],
)
def test_malformed_backend_target_sources_exit_cleanly(scope, recon, capsys):
    client = MagicMock()
    if scope is not None:
        client.scope.return_value = scope
        args = (True, False)
    else:
        client.recon.return_value = recon
        args = (False, True)
    with pytest.raises(typer.Exit):
        targets._resolve_targets(client, "eng", *args, None, None, None, 10)
    assert "Invalid target data" in capsys.readouterr().out


def test_queue_target_limit_fails_before_claim(tmp_path):
    client = MagicMock()
    client.base = "https://api.example.com"
    client.pending_jobs.return_value = [
        {
            "id": "job-1",
            "tool_type": "httpx",
            "target_source": "scope",
            "engagement_id": "eng-1",
            "config": {},
        }
    ]
    handler = MagicMock(tool="httpx")
    handler.resolve_targets.return_value = ["a.example.com", "b.example.com"]
    with (
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch.dict("vardrrunner.commands.jobs.handlers.REGISTRY", {"httpx": handler}, clear=True),
    ):
        jobs.execute_pending_jobs(
            client,
            Console(),
            limits=resources.RunnerLimits(max_targets=1, min_free_disk_bytes=0),
        )
    client.claim_job.assert_not_called()
    client.complete_job.assert_called_once()
    assert "local limit" in client.complete_job.call_args.kwargs["error"]


def test_queue_artifact_limit_fails_without_upload(tmp_path):
    artifact = tmp_path / "out.jsonl"
    artifact.write_bytes(b"too large")
    client = MagicMock()
    client.base = "https://api.example.com"
    client.pending_jobs.return_value = [
        {
            "id": "job-1",
            "tool_type": "httpx",
            "target_source": "scope",
            "engagement_id": "eng-1",
            "config": {},
        }
    ]
    client.claim_job.return_value = {}
    handler = MagicMock(tool="httpx")
    handler.resolve_targets.return_value = ["a.example.com"]
    handler.execute.return_value = artifact
    with (
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch.dict("vardrrunner.commands.jobs.handlers.REGISTRY", {"httpx": handler}, clear=True),
    ):
        jobs.execute_pending_jobs(
            client,
            Console(),
            limits=resources.RunnerLimits(
                max_artifact_bytes=1,
                min_free_disk_bytes=0,
            ),
        )
    handler.upload.assert_not_called()
    assert "artifact exceeds" in client.complete_job.call_args.kwargs["error"]


def test_concurrency_never_overlaps_same_engagement():
    pending = [
        {"id": "a1", "engagement_id": "eng-a"},
        {"id": "a2", "engagement_id": "eng-a"},
        {"id": "b1", "engagement_id": "eng-b"},
    ]
    client = MagicMock()
    client.pending_jobs.return_value = pending
    lock = threading.Lock()
    active: dict[str, int] = {}
    max_active: dict[str, int] = {}

    def fake_execute(_client, _console, job, _yes, **_kwargs):
        engagement = job["engagement_id"]
        with lock:
            active[engagement] = active.get(engagement, 0) + 1
            max_active[engagement] = max(max_active.get(engagement, 0), active[engagement])
        time.sleep(0.02)
        with lock:
            active[engagement] -= 1

    made = []

    def factory():
        worker = MagicMock()
        made.append(worker)
        return worker

    with patch("vardrrunner.commands.jobs._execute_one", side_effect=fake_execute):
        jobs.execute_pending_jobs(
            client,
            Console(),
            limits=resources.RunnerLimits(max_concurrent_jobs=2, min_free_disk_bytes=0),
            client_factory=factory,
        )
    assert max_active["eng-a"] == 1
    assert len(made) == 2


def test_concurrency_requires_isolated_clients():
    client = MagicMock()
    client.pending_jobs.return_value = [
        {"id": "a", "engagement_id": "eng-a"},
        {"id": "b", "engagement_id": "eng-b"},
    ]
    with pytest.raises(resources.ResourceLimitError, match="isolated API client"):
        jobs.execute_pending_jobs(
            client,
            Console(),
            limits=resources.RunnerLimits(max_concurrent_jobs=2, min_free_disk_bytes=0),
        )


def test_jobs_run_stops_on_compatibility_block():
    report = compatibility.CompatibilityReport(
        compatibility.CompatibilityLevel.BLOCK, ("upgrade required",)
    )
    with (
        patch("vardrrunner.commands.jobs.send_heartbeat", return_value=report),
        patch("vardrrunner.commands.jobs.config.require_auth") as auth,
        pytest.raises(typer.Exit),
    ):
        jobs.run_jobs(yes=True)
    auth.assert_not_called()


def test_jobs_run_rejects_invalid_resource_policy(tmp_path):
    with (
        patch("vardrrunner.commands.jobs.send_heartbeat", return_value=None),
        patch(
            "vardrrunner.commands.jobs.config.require_auth",
            return_value=("https://api.example.com", "key"),
        ),
        patch("vardrrunner.commands.jobs.api.VardrMapClient"),
        patch(
            "vardrrunner.commands.jobs.resources.load_limits",
            side_effect=resources.ResourceLimitError("bad limit"),
        ),
        pytest.raises(typer.Exit),
    ):
        jobs.run_jobs(yes=True)


def test_direct_run_resource_and_artifact_limits_exit(tmp_path):
    handler = MagicMock()
    artifact = tmp_path / "output.jsonl"
    artifact.write_text("{}")
    handler.running_label.return_value = "httpx"
    handler.execute.return_value = artifact
    client = MagicMock()

    with (
        patch.dict("vardrrunner.commands.run.handlers.REGISTRY", {"httpx": handler}),
        patch(
            "vardrrunner.commands.run.resources.load_limits",
            side_effect=resources.ResourceLimitError("bad policy"),
        ),
        pytest.raises(typer.Exit),
    ):
        run_command._finish("httpx", client, "eng", ["example.com"], object(), tmp_path)
    handler.execute.assert_not_called()

    with (
        patch.dict("vardrrunner.commands.run.handlers.REGISTRY", {"httpx": handler}),
        patch("vardrrunner.commands.run.resources.ensure_free_space"),
        patch(
            "vardrrunner.commands.run.resources.enforce_artifact",
            side_effect=resources.ResourceLimitError("artifact too large"),
        ),
        pytest.raises(typer.Exit),
    ):
        run_command._finish("httpx", client, "eng", ["example.com"], object(), tmp_path)
    handler.upload.assert_not_called()
