"""Guarded execution cannot bypass reservation, local grants or capability flag."""

from dataclasses import replace
from datetime import timedelta
from unittest.mock import MagicMock

import pytest

from tests.test_authorization_contract import NOW, SEED, TOOL, specimen  # noqa: F401
from vardrrunner import runner
from vardrrunner.authorization import runtime
from vardrrunner.authorization.codec import AuthorizationError, decoded, sign, unb64


class Clock:
    @staticmethod
    def now(_):
        return NOW


@pytest.fixture
def local_execution(request, tmp_path, monkeypatch):
    s = request.getfixturevalue("specimen")
    binary = tmp_path / "fixture-binary"
    binary.write_bytes(b"fixture-only")
    run_dir = tmp_path / "result"
    run_dir.mkdir()
    monkeypatch.setattr(runtime, "datetime", Clock)
    monkeypatch.setattr(runtime.runner, "program", lambda _: str(binary))
    monkeypatch.setattr(runtime, "digest", lambda _: TOOL)
    monkeypatch.delenv("VARDRRUNNER_ALLOW_PRIVATE_TARGETS", raising=False)
    local_grants = MagicMock()
    monkeypatch.setattr(runtime.handlers, "check_gate_case", local_grants)
    output = run_dir / "vardrgate_result.json"

    def execute(*args, **kwargs):
        output.write_text('{"findings":[],"executions":[]}')
        return output

    handler = MagicMock(side_effect=execute)
    monkeypatch.setattr(runtime.handlers.VardrGateHandler, "execute", handler)
    return s, run_dir, handler, local_grants


def launch(s, run_dir, context=None):
    return runtime.execute_gate(
        s["ledger"],
        s["contract"],
        s["approval"],
        s["plan"],
        s["case"],
        s["execution"],
        (s["anchor"],),
        context or s["runtime"],
        run_dir,
    )


def test_guarded_standalone_reuses_handler_and_single_use(local_execution, tmp_path):
    s, run_dir, handler, grants = local_execution
    assert launch(s, run_dir).exists()
    grants.assert_called_once_with(s["case"], "eng-1")
    assert handler.call_args.kwargs["request_guard"] == s["plan"]
    assert handler.call_args.kwargs["total_timeout"] == 60
    other = tmp_path / "second"
    other.mkdir()
    with pytest.raises(AuthorizationError, match="replayed"):
        launch(s, other)
    assert handler.call_count == 1


def test_shorter_signed_contract_caps_execution_timeout(local_execution):
    s, run_dir, handler, _ = local_execution
    payload = decoded(unb64(s["contract"]["payload"]))
    payload["expires_at"] = (NOW + timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    s["contract"] = sign(payload, SEED, "contract")
    assert launch(s, run_dir).exists()
    assert handler.call_args.kwargs["total_timeout"] == 20
    assert (
        handler.call_args.kwargs["execution_deadline"] == (NOW + timedelta(seconds=20)).timestamp()
    )


@pytest.mark.parametrize("preflight", [False, True])
@pytest.mark.parametrize("elapsed", [15, 20])
def test_deadline_rechecked_after_private_job_preparation(
    tmp_path, monkeypatch, preflight, elapsed
):
    prepared = []
    now = [NOW.timestamp()]
    original_write = runner._write_private_job

    def write_private(payload):
        paths = original_write(payload)
        prepared.append(paths)
        if len(prepared) == 2:
            now[0] += elapsed
        return paths

    process = MagicMock()
    process.wait.return_value = 0
    spawn = MagicMock(return_value=process)
    monkeypatch.setattr(runner, "_write_private_job", write_private)
    monkeypatch.setattr(runner, "_spawn_tool", spawn)
    monkeypatch.setattr(runner.time, "time", lambda: now[0])
    identities = [{"id": "owner", "preflight": {}}] if preflight else []
    job = {"config": {"test_case": {"identities": identities}}}
    kwargs = dict(request_guard={"schema": "fixture"}, execution_deadline=NOW.timestamp() + 20)
    if elapsed == 20:
        with pytest.raises(runner.ToolTimeout, match="deadline elapsed before launch"):
            runner.run_vardrgate(job, tmp_path / "result.json", timeout=60, **kwargs)
        spawn.assert_not_called()
    else:
        assert runner.run_vardrgate(job, tmp_path / "result.json", timeout=60, **kwargs) == 0
        process.wait.assert_called_once_with(timeout=5)
    assert len(prepared) == 2
    assert all(not file.exists() and not directory.exists() for file, directory in prepared)


@pytest.mark.parametrize(
    "reason", ["map", "tool", "private", "output", "deadline", "missing_artifact"]
)
def test_runtime_failure_boundaries(local_execution, monkeypatch, reason):
    s, run_dir, handler, _ = local_execution
    context = s["runtime"]
    if reason == "map":
        context = replace(context, origin="map", managed_status_verified=True)
    elif reason == "tool":
        monkeypatch.setattr(runtime, "digest", lambda _: "0" * 64)
    elif reason == "private":
        monkeypatch.setenv("VARDRRUNNER_ALLOW_PRIVATE_TARGETS", "1")
    elif reason == "output":
        (run_dir / "vardrgate_result.json").write_text("existing evidence")
    elif reason == "deadline":
        monkeypatch.setattr(runtime, "timestamp", lambda _: NOW)
    else:
        handler.side_effect = None
        handler.return_value = None
    with pytest.raises(AuthorizationError):
        launch(s, run_dir, context)
    if reason != "missing_artifact":
        handler.assert_not_called()


def test_projection_file_is_private_bound_and_removed(tmp_path, monkeypatch):
    process = MagicMock()
    process.wait.return_value = 0
    captured = {}

    def spawn(argv):
        from pathlib import Path

        job = Path(argv[argv.index("--job") + 1])
        projection = Path(argv[argv.index("--request-guard") + 1])
        assert decoded(job.read_bytes()) == {"config": {"test_case": {}}}
        assert decoded(projection.read_bytes()) == {"schema": "fixture-projection"}
        assert job.parent != projection.parent
        captured.update(job=job, projection=projection)
        return process

    monkeypatch.setattr(runner, "_spawn_tool", spawn)
    runner.run_vardrgate(
        {"config": {"test_case": {}}},
        tmp_path / "result.json",
        request_guard={"schema": "fixture-projection"},
    )
    assert not captured["job"].exists() and not captured["projection"].exists()
