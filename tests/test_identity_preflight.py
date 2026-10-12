import json
from unittest.mock import MagicMock, patch

import pytest

from tests.test_recovery import _run_at
from vardrrunner import configs, handlers, runner
from vardrrunner.journal import Journal, Phase
from vardrrunner.recovery import reconcile


def cfg():
    return configs.VardrGateConfig.from_dict(
        {
            "test_case": {
                "id": "session",
                "request": {"method": "GET", "url": "https://api.test/resource"},
                "identities": [
                    {
                        "id": "owner",
                        "credential": {"type": "bearer", "value_env": "OWNER_TOKEN"},
                        "preflight": {
                            "url": "https://api.test/session",
                            "expected_status": 200,
                            "json_fields": {"id": "owner"},
                        },
                    }
                ],
            },
            "execution": {},
        }
    )


def result(failed=False):
    return {
        "test_case_id": "session",
        "executions": [],
        "findings": [],
        "preflight": [
            {
                "identity_id": "owner",
                "status": "failed" if failed else "passed",
                "reason": "credential_rejected" if failed else "identity_verified",
                "status_code": 401 if failed else 200,
            }
        ],
    }


@pytest.mark.parametrize("failed", [False, True])
def test_result_keeps_preflight_and_unresolved_binding(monkeypatch, tmp_path, failed):
    monkeypatch.setenv("OWNER_TOKEN", "local-secret")

    def run(job, out, timeout=None):
        assert job["config"]["test_case"]["identities"][0]["credential"]["value"] == "local-secret"
        out.write_text(json.dumps(result(failed)), encoding="utf-8")
        return 3 if failed else 0

    h = handlers.VardrGateHandler()
    with patch("vardrrunner.runner.run_vardrgate", side_effect=run):
        out = h.execute([], tmp_path, cfg())
    assert "local-secret" not in out.read_text()
    assert json.loads(out.read_text())["case_hash"]
    client = MagicMock()
    summary = h.upload(client, "eng", out, job_id="job")
    assert client.post.call_args.kwargs["json"]["preflight"] == result(failed)["preflight"]
    assert bool(h.completion_error(out)) == failed
    assert ("preflight failed" in summary) == failed


@pytest.mark.parametrize(
    "rows,exit_code",
    [
        (None, 0),
        ([], 0),
        ([{}], 0),
        (result()["preflight"] * 2, 0),
        (result()["preflight"], 3),
        (result(True)["preflight"], 0),
        ([{**result()["preflight"][0], "body": "secret"}], 0),
        ([{**result()["preflight"][0], "identity_id": "foreign"}], 0),
        ([{**result()["preflight"][0], "status_code": True}], 0),
    ],
)
def test_invalid_or_missing_preflight_report_fails(monkeypatch, tmp_path, rows, exit_code):
    monkeypatch.setenv("OWNER_TOKEN", "local-secret")

    def run(job, out, timeout=None):
        out.write_text(json.dumps({**result(), "preflight": rows}), encoding="utf-8")
        return exit_code

    with patch("vardrrunner.runner.run_vardrgate", side_effect=run):
        with pytest.raises(runner.ToolError, match="preflight result"):
            handlers.VardrGateHandler().execute([], tmp_path, cfg())


def test_runner_requires_new_binary_before_any_request(tmp_path):
    p = MagicMock()
    p.wait.return_value = 1  # older Gate rejects unknown flag
    with patch("vardrrunner.runner._spawn_tool", return_value=p) as spawn:
        with pytest.raises(runner.ToolError, match="code 1"):
            runner.run_vardrgate(
                {"config": {"test_case": cfg().test_case}}, tmp_path / "result.json"
            )
    assert "--require-identity-preflight" in spawn.call_args.args[0]


def test_recovery_uploads_failed_diagnostics_and_keeps_job_failed(tmp_path):
    store = Journal(tmp_path / "journal.db")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.EXECUTING, run_dir, tool="vardrgate_api_test")
    (run_dir / "vardrgate_result.json").write_text(json.dumps(result(True)))
    client = MagicMock()
    with patch("vardrrunner.recovery.process_alive", return_value=False):
        outcome = reconcile(store, client, "https://api.example.com")
    assert outcome.failed == 1 and outcome.recovered == 0
    assert store.get(record.run_id).status == "failed"
    client.complete_job.assert_called_once()
    assert client.complete_job.call_args.args[1] == "failed"


def test_deferred_failed_finalization_never_becomes_done(tmp_path):
    store = Journal(tmp_path / "journal.db")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    record = _run_at(store, Phase.EXECUTING, run_dir, tool="vardrgate_api_test")
    (run_dir / "vardrgate_result.json").write_text(json.dumps(result(True)))
    client = MagicMock()
    client.complete_job.side_effect = RuntimeError("backend unavailable")
    with patch("vardrrunner.recovery.process_alive", return_value=False):
        assert reconcile(store, client, "https://api.example.com").deferred == 1
    assert store.get(record.run_id).phase == Phase.FINALIZING
    client.complete_job.side_effect = None
    assert reconcile(store, client, "https://api.example.com").failed == 1
    assert all(call.args[1] == "failed" for call in client.complete_job.call_args_list)
