"""Cancellation at real journal/upload boundaries; legacy behavior stays separate."""

import time
from unittest.mock import Mock

import pytest
from rich.console import Console

from vardrrunner import api, configs, controlled_jobs, execution_control, resources
from vardrrunner.commands import jobs
from vardrrunner.journal import Journal, Phase


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    client = Mock(spec=api.VardrMapClient)
    client.base = "http://localhost"

    def claim(job_id, runner_id):
        return {
            "warnings": [],
            "execution_control": {
                "job_id": job_id,
                "runner_id": runner_id,
                "origin": client.base,
                "token": "synthetic-fixture-capability-" * 2,
                "lease_seconds": 10,
            },
        }

    client.claim_controlled.side_effect = claim
    client.execution_control.side_effect = lambda job_id, payload, **kw: {
        "job_id": job_id,
        "runner_id": payload["runner_id"],
        "origin": client.base,
        "action": "continue",
        "lease_seconds": 10,
    }
    store = Journal(tmp_path / "journal.db")
    job = {
        "id": "job-one",
        "engagement_id": "eng-one",
        "tool_type": "httpx",
        "target_source": "scope",
        "config": {},
    }
    handler = Mock()
    handler.tool = "httpx"
    handler.parse_config.return_value = configs.HttpxConfig.from_dict({})
    handler.resolve_targets.return_value = ["http://127.0.0.1"]
    handler.running_label.return_value = "synthetic fixture"
    output = tmp_path / "partial.jsonl"
    output.write_text('{"synthetic":true}\n')
    handler.execute.return_value = output
    handler.completion_error.return_value = None
    monkeypatch.setitem(jobs.handlers.REGISTRY, "httpx", handler)
    monkeypatch.setattr(jobs.runner, "tool_available", lambda _: True)
    monkeypatch.setattr(jobs, "_make_run_dir", lambda: tmp_path)
    monkeypatch.setattr(resources, "ensure_free_space", lambda *_: None)
    monkeypatch.setattr(execution_control, "available", lambda: True)
    return client, store, job, handler, output


def execute(scenario):
    client, store, job, _, _ = scenario
    jobs._execute_one(
        client,
        Console(quiet=True),
        job,
        True,
        journal_store=store,
        backend_url=client.base,
        controlled=True,
    )


def test_late_stop_preserves_finalizing_upload_and_artifact(scenario):
    client, store, _, handler, output = scenario

    def upload(*_, **__):
        record = store.unfinished()[0]
        assert record.phase == Phase.UPLOADING
        store.request_stop(record.run_id)
        return "uploaded before local stop"

    handler.upload.side_effect = upload
    execute(scenario)
    record = store.list()[0]
    assert record.phase == Phase.INTERRUPTED
    assert record.status == "cancelled"
    assert record.upload_state == "succeeded"
    assert record.artifact_path == str(output)
    assert record.artifact_sha256
    calls = [call for call in client.execution_control.call_args_list if call.kwargs.get("finish")]
    assert [call.args[1]["outcome"] for call in calls] == ["cancelled"]


def test_uncertain_stop_retains_observers_durable_pid(scenario):
    _, store, _, handler, output = scenario

    def fail(*_):
        record = store.unfinished()[0]
        store.transition(record.run_id, Phase.EXECUTING, pid=987654)
        raise execution_control.ExecutionStopped("kill_unconfirmed", False)

    handler.execute.side_effect = fail
    execute(scenario)
    record = store.unfinished()[0]
    assert record.phase == Phase.EXECUTING
    assert record.pid == 987654
    assert record.status == "uncertain"
    assert output.exists()
    handler.upload.assert_not_called()


def test_missing_control_capability_never_falls_back(scenario):
    client, _, _, handler, _ = scenario
    client.claim_controlled.side_effect = None
    client.claim_controlled.return_value = {"status": "running"}
    execute(scenario)
    handler.execute.assert_not_called()
    client.claim_job.assert_not_called()


def test_unacknowledged_stop_keeps_local_fence(scenario):
    client, store, _, handler, _ = scenario
    handler.execute.side_effect = execution_control.ExecutionStopped("local_emergency_stop", True)
    client.execution_control.side_effect = OSError("unreachable")
    execute(scenario)
    assert store.unfinished()[0].status == "cancelled"


def test_expired_preparation_does_not_start_tool(scenario):
    client, _, _, handler, _ = scenario
    original = client.claim_controlled.side_effect

    def claim(*args):
        result = original(*args)
        return result

    client.claim_controlled.side_effect = claim
    # A known deadline expires while secret/private-file preparation is in
    # progress. The subprocess launch boundary checks again before any spawn.
    control = execution_control.Control(
        lambda: {}, {}, 0, started=time.monotonic(), local_stop=lambda: False
    )
    with execution_control.controlled(control):
        with pytest.raises(execution_control.ExecutionStopped):
            jobs.runner._run_tool(["never-launch"], None, "fixture", 5)


def test_cross_job_finalization_refused():
    client = Mock(base="http://localhost")
    owned = controlled_jobs.OwnedClient(client)
    owned.payload = {"token": "fixture"}
    owned.binding = {"job_id": "one"}
    with pytest.raises(ValueError, match="cross-job"):
        owned.complete_job("two", "done")
    client.execution_control.assert_not_called()


def test_timeout_is_failed_not_operator_cancelled(scenario):
    _, store, _, handler, _ = scenario
    handler.execute.side_effect = execution_control.ExecutionStopped("tool_timeout", True)
    execute(scenario)
    assert store.list()[0].status == "failed"
    assert store.list()[0].phase == Phase.FAILED
    assert store.list()[0].failure_category == "tool_timeout"


def test_unsupported_platform_refuses_before_claim(scenario, monkeypatch):
    client, _, _, handler, _ = scenario
    monkeypatch.setattr(execution_control, "available", lambda: False)
    execute(scenario)
    handler.execute.assert_not_called()
    client.claim_controlled.assert_not_called()


@pytest.mark.parametrize("reserved", [True, False, None])
def test_budgeted_claim_requires_explicit_reservation_receipt(scenario, reserved):
    client, _, _, _, _ = scenario
    original = client.claim_controlled.side_effect

    def claim(job_id, runner_id, **kwargs):
        assert kwargs == {"concurrency_budget": True}
        result = original(job_id, runner_id)
        result["execution_control"]["capacity_reserved"] = reserved
        return result

    client.claim_controlled.side_effect = claim
    owned = controlled_jobs.OwnedClient(client, concurrency_budget=True)
    if reserved is True:
        assert owned.claim_job("job-one")["execution_control"]["capacity_reserved"] is True
    else:
        with pytest.raises(ValueError, match="no legacy fallback"):
            owned.claim_job("job-one")


def test_budget_requires_controlled_before_connecting(monkeypatch):
    import typer

    heartbeat = Mock()
    monkeypatch.setattr(jobs, "send_heartbeat", heartbeat)
    with pytest.raises(typer.Exit):
        jobs.run_jobs(concurrency_budget=True)
    heartbeat.assert_not_called()
