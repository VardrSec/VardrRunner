"""Synthetic launch failures must not retain resolved Gate credentials."""

import json
from unittest.mock import patch

import pytest

from vardrrunner import runner, toolchain


@pytest.mark.parametrize(
    "failure", ["malformed_receipt", "unreadable_receipt", "program", "preflight"]
)
@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_gate_setup_failure_cleans_sensitive_job(
    tmp_path, monkeypatch, caplog, capsys, failure, cleanup_fails
):
    # All tool/profile paths are isolated by conftest; also confine temp creation
    # and abandoned-directory discovery so neither touches an operator's files.
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(runner.tempfile, "tempdir", str(scratch))
    fake_secret = "synthetic-gate-credential-do-not-retain"
    job = {
        "config": {
            "test_case": {"identities": [{"id": "synthetic", "credential": {"value": fake_secret}}]}
        }
    }
    expected = None
    if failure in {"malformed_receipt", "unreadable_receipt"}:
        receipt = toolchain.lock_path()
        receipt.parent.mkdir(parents=True, exist_ok=True)
        if failure == "malformed_receipt":
            receipt.write_text("{invalid-json", encoding="utf-8")
        else:
            # A directory is deterministically unreadable as a file on all OSes,
            # unlike chmod-based permissions when the test process runs as root.
            receipt.mkdir()
    else:
        expected = RuntimeError("synthetic setup failure")

        def fail(*args, **kwargs):
            raise expected

        if failure == "program":
            monkeypatch.setattr(runner, "program", fail)
        else:
            monkeypatch.setattr(runner.configs, "gate_identities", fail)

    written = []
    write_private_job = runner._write_private_job

    def record_job(payload):
        path, directory = write_private_job(payload)
        assert json.loads(path.read_text(encoding="utf-8")) == job
        written.append((path, directory))
        return path, directory

    monkeypatch.setattr(runner, "_write_private_job", record_job)
    if cleanup_fails:

        def fail_cleanup(*args):
            raise OSError(fake_secret)

        monkeypatch.setattr(runner, "_remove_private_job", fail_cleanup)

    with (
        patch("vardrrunner.runner._spawn_tool") as spawn,
        patch("vardrrunner.runner._run_tool_status") as run,
        pytest.raises(RuntimeError if expected else runner.ToolError) as caught,
    ):
        runner.run_vardrgate(job, tmp_path / "result.json", request_guard={"synthetic": True})

    spawn.assert_not_called()
    run.assert_not_called()
    assert len(written) == 1  # Setup failed before writing a request guard.
    if expected is not None:
        assert caught.value is expected
    else:
        assert isinstance(caught.value.__cause__, toolchain.ToolIntegrityError)
        assert "unreadable" in str(caught.value)
    if cleanup_fails:
        assert "Could not remove sensitive VardrGate job data after a failed run" in caplog.text
        # Failed filesystem deletion retains the synthetic file; this is the
        # existing contract, not a guarantee against OS-level cleanup failure.
        assert written[0][0].exists()
    else:
        assert list(scratch.iterdir()) == []
        assert all(not path.exists() and not directory.exists() for path, directory in written)
    assert not (tmp_path / "result.json").exists()
    output = capsys.readouterr()
    assert fake_secret not in output.out + output.err + caplog.text + str(caught.value)
