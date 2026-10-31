"""Nmap is outside the supported toolkit: off by default, opt-in only, never packaged.

The rest of the suite opts in (tests/conftest.py) so the optional integration stays
covered. These tests start fresh interpreters without the opt-in to check the default.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vardrrunner import config, runner

ROOT = Path(__file__).resolve().parents[1]


def fresh(code: str, enable: str | None = None) -> str:
    env = {k: v for k, v in os.environ.items() if k != config.ENV_ENABLE_NMAP}
    if enable is not None:
        env[config.ENV_ENABLE_NMAP] = enable
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


TOOLS = (
    "import json; from vardrrunner import handlers, runner; "
    "print(json.dumps([sorted(runner.ALLOWED_TOOLS), sorted(handlers.REGISTRY)]))"
)


def test_nmap_is_neither_allowed_nor_registered_by_default():
    allowed, registry = json.loads(fresh(TOOLS))
    assert "nmap" not in allowed and "nmap" not in registry
    assert "naabu" in allowed and "naabu" in registry


@pytest.mark.parametrize("value", ["", "0", "true", "yes", "2"])
def test_only_an_explicit_one_enables_nmap(value):
    allowed, registry = json.loads(fresh(TOOLS, enable=value))
    assert "nmap" not in allowed and "nmap" not in registry


def test_explicit_opt_in_restores_the_integration():
    allowed, registry = json.loads(fresh(TOOLS, enable="1"))
    assert "nmap" in allowed and "nmap" in registry


def test_run_nmap_is_refused_with_the_supported_alternative_by_default():
    output = fresh(
        "from vardrrunner.commands import run\n"
        "try:\n"
        "    run.run_nmap('engagement', target='example.test', yes=True)\n"
        "except Exception as error:\n"
        "    print(type(error).__name__, error)\n"
    )
    assert output.startswith("BadParameter")
    assert "naabu" in output and config.ENV_ENABLE_NMAP in output


def test_disabled_tool_reason_only_describes_a_disabled_optional_tool():
    assert runner.disabled_tool_reason("httpx") is None
    assert runner.disabled_tool_reason("unknown-tool") is None
    reason = fresh("from vardrrunner import runner; print(runner.disabled_tool_reason('nmap'))")
    assert "naabu" in reason and "Community Alpha" in reason


def test_a_queued_nmap_job_has_no_handler_and_fails_as_unsupported():
    registry = json.loads(
        fresh(
            "import json; from vardrrunner import handlers; print(json.dumps(sorted(handlers.REGISTRY)))"
        )
    )
    assert "nmap" not in registry


def test_methodology_suggestions_name_only_supported_tools():
    text = (ROOT / "vardrrunner" / "methodologies.json").read_text(encoding="utf-8")
    assert "nmap" not in text.lower()


def test_naabu_is_run_without_any_nmap_integration(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(runner, "program", lambda name: name)
    monkeypatch.setattr(
        runner, "_run_tool", lambda cmd, targets_file, name, timeout: seen.update(cmd=cmd)
    )
    runner.run_naabu(["example.test"], tmp_path / "naabu.json", top_ports=100)
    command = seen["cmd"]
    assert command[0] == "naabu"
    forbidden = {"-nmap", "-nmap-cli", "-sv", "-sc"}
    assert not [arg for arg in command if "nmap" in arg.lower() or arg.lower() in forbidden]


def test_the_container_image_does_not_install_nmap():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    installs = [line for line in dockerfile.splitlines() if "apt-get install" in line]
    assert installs and not [line for line in installs if "nmap" in line.lower()]
    assert "libpcap0.8" in "".join(installs)
