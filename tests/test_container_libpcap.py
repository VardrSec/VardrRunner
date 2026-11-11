"""Bounded supervisor checks; native cases run only in isolated container CI."""

import json
import runpy
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

SCRIPT = Path(__file__).with_name("container_libpcap.py")


def test_supervisor_runs_all_cases_with_timeout_and_rejects_child_failure(monkeypatch):
    scope = runpy.run_path(str(SCRIPT))
    monkeypatch.setattr(scope["sys"], "argv", [str(SCRIPT)])
    run = Mock(side_effect=subprocess.TimeoutExpired("bounded native case", 5))
    monkeypatch.setattr(scope["subprocess"], "run", run)
    with pytest.raises(subprocess.TimeoutExpired):
        scope["main"]()
    assert run.call_args.kwargs["timeout"] == 5
    assert run.call_args.kwargs["check"] is True


def test_supervisor_binds_one_library_identity(monkeypatch, capsys):
    scope = runpy.run_path(str(SCRIPT))
    monkeypatch.setattr(scope["sys"], "argv", [str(SCRIPT)])

    def run(args, **kwargs):
        assert kwargs["timeout"] == 5 and kwargs["check"] is True
        if args[0] == "dpkg-query":
            return subprocess.CompletedProcess(args, 0, "libpcap0.8t64 1.10.7-1+vardr1 amd64\n")
        case = args[-1]
        return subprocess.CompletedProcess(
            args,
            0,
            json.dumps(
                {
                    "case": case,
                    "library": "/lib/libpcap.so",
                    "sha256": "a" * 64,
                    "version": "1.10.7",
                    "result": scope["CASES"][case][1],
                }
            ),
        )

    monkeypatch.setattr(scope["subprocess"], "run", run)
    scope["main"]()
    result = json.loads(capsys.readouterr().out)
    assert {r["case"] for r in result["cases"]} == set(scope["CASES"])
    assert result["package"] == "libpcap0.8t64 1.10.7-1+vardr1 amd64"


def test_workflow_keeps_native_checks_offline_and_bounded():
    workflow = (SCRIPT.parents[1] / ".github/workflows/container.yml").read_text()
    command = next(line for line in workflow.splitlines() if "/checks/container_libpcap.py" in line)
    for required in (
        "--network none",
        "--read-only",
        "--memory 192m",
        "--pids-limit 32",
        "--cap-drop ALL",
    ):
        assert required in command
