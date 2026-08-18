"""
Tests for the safe subprocess runner. Tools are mocked — we test argument
construction and wildcard handling, not actual tool execution.
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vardrrunner import runner
from vardrrunner.commands.run import _is_wildcard, _resolve_targets

# ---------------------------------------------------------------------------
# Wildcard detection
# ---------------------------------------------------------------------------


def test_wildcard_detected():
    assert _is_wildcard("*.example.com") is True
    assert _is_wildcard("*example.com") is True


def test_non_wildcard_passes():
    assert _is_wildcard("app.example.com") is False
    assert _is_wildcard("https://api.example.com") is False
    assert _is_wildcard("192.168.1.1") is False


# ---------------------------------------------------------------------------
# tool_available
# ---------------------------------------------------------------------------


def test_tool_available_returns_false_for_unknown():
    assert runner.tool_available("notarealtool") is False


def test_tool_available_uses_shutil_which():
    with patch("shutil.which", return_value="/usr/bin/httpx"):
        assert runner.tool_available("httpx") is True


def test_tool_available_missing():
    with patch("shutil.which", return_value=None):
        assert runner.tool_available("httpx") is False


# ---------------------------------------------------------------------------
# _resolve_targets — inline target
# ---------------------------------------------------------------------------


def test_resolve_targets_inline():
    client = MagicMock()
    targets = _resolve_targets(
        client,
        "prog-1",
        scope=False,
        from_recon=False,
        target="https://example.com",
        targets_file=None,
        status_code=None,
        limit=100,
    )
    assert targets == ["https://example.com"]
    client.scope.assert_not_called()
    client.recon.assert_not_called()


# ---------------------------------------------------------------------------
# _resolve_targets — targets file
# ---------------------------------------------------------------------------


def test_resolve_targets_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("https://a.com\nhttps://b.com\n")
    client = MagicMock()
    targets = _resolve_targets(
        client,
        "prog-1",
        scope=False,
        from_recon=False,
        target=None,
        targets_file=f,
        status_code=None,
        limit=100,
    )
    assert targets == ["https://a.com", "https://b.com"]


def test_resolve_targets_file_missing_raises(tmp_path):
    import typer

    client = MagicMock()
    with pytest.raises(typer.Exit):
        _resolve_targets(
            client,
            "prog-1",
            scope=False,
            from_recon=False,
            target=None,
            targets_file=tmp_path / "missing.txt",
            status_code=None,
            limit=100,
        )


# ---------------------------------------------------------------------------
# _resolve_targets — scope (wildcards skipped)
# ---------------------------------------------------------------------------


def test_resolve_targets_scope_skips_wildcards(capsys):
    client = MagicMock()
    client.scope.return_value = {
        "in": [
            {"value": "app.example.com", "kind": "domain"},
            {"value": "*.example.com", "kind": "domain"},
            {"value": "api.example.com", "kind": "domain"},
        ],
        "out": [],
    }
    targets = _resolve_targets(
        client,
        "prog-1",
        scope=True,
        from_recon=False,
        target=None,
        targets_file=None,
        status_code=None,
        limit=100,
    )
    assert "app.example.com" in targets
    assert "api.example.com" in targets
    assert "*.example.com" not in targets


# ---------------------------------------------------------------------------
# _resolve_targets — from recon
# ---------------------------------------------------------------------------


def test_resolve_targets_from_recon():
    client = MagicMock()
    client.recon.return_value = [
        {"url": "https://app.example.com", "host": "app.example.com"},
        {"url": "", "host": "api.example.com"},
    ]
    targets = _resolve_targets(
        client,
        "prog-1",
        scope=False,
        from_recon=True,
        target=None,
        targets_file=None,
        status_code=200,
        limit=50,
    )
    client.recon.assert_called_once_with("prog-1", limit=50, status_code=200)
    assert "https://app.example.com" in targets
    assert "api.example.com" in targets


# ---------------------------------------------------------------------------
# run_httpx / run_nuclei — subprocess is called with a list, not a shell string
# ---------------------------------------------------------------------------


def test_run_httpx_uses_arg_list(tmp_path):
    output = tmp_path / "out.jsonl"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        runner.run_httpx(["https://example.com"], output)
        args = mock_run.call_args[0][0]
        assert isinstance(args, list), "subprocess must be called with a list, not a shell string"
        assert args[0] == "httpx"


def test_run_nuclei_uses_arg_list(tmp_path):
    output = tmp_path / "out.jsonl"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        runner.run_nuclei(["https://example.com"], output, severity="high,critical")
        args = mock_run.call_args[0][0]
        assert isinstance(args, list)
        assert args[0] == "nuclei"
        assert "-severity" in args
        assert "high,critical" in args


def test_run_dnsx_uses_arg_list(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        runner.run_dnsx(["a.example.com"], tmp_path / "out.txt")
        args = mock_run.call_args[0][0]
        assert args[0] == "dnsx" and "-l" in args and "-silent" in args


def test_run_vardrgate_uses_arg_list(tmp_path):
    output = tmp_path / "result.json"
    job = {"config": {"test_case": {"id": "x"}, "execution": {}}}
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        runner.run_vardrgate(job, output)
        args = mock_run.call_args[0][0]
    assert isinstance(args, list)
    assert args[0] == "vardrgate"
    assert args[1] == "run"
    assert "--job" in args and "--out" in args
    assert str(output) in args


def test_run_naabu_uses_arg_list(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        runner.run_naabu(["a.example.com"], tmp_path / "out.json", top_ports=50)
        args = mock_run.call_args[0][0]
        assert args[0] == "naabu" and "-json" in args
        assert "-top-ports" in args and "50" in args


def test_parse_naabu_json(tmp_path):
    f = tmp_path / "naabu.json"
    f.write_text(
        '{"host":"a.example.com","ip":"1.2.3.4","port":443,"protocol":"tcp"}\n'
        "\n"  # blank line ignored
        "not-json\n"  # malformed line ignored
        '{"ip":"5.6.7.8","port":80}\n'  # host falls back to ip; protocol defaults tcp
    )
    services = runner.parse_naabu_json(f)
    assert len(services) == 2
    assert services[0] == {
        "host": "a.example.com",
        "port": 443,
        "protocol": "tcp",
        "service_name": "",
        "product": "",
        "version": "",
        "state": "open",
        "source": "naabu",
    }
    assert services[1]["host"] == "5.6.7.8" and services[1]["protocol"] == "tcp"


def test_parse_naabu_json_missing_file(tmp_path):
    assert runner.parse_naabu_json(tmp_path / "nope.json") == []


# ---------------------------------------------------------------------------
# Tool timeouts
# ---------------------------------------------------------------------------


def test_resolve_timeout_override_wins(monkeypatch):
    monkeypatch.setenv("VARDRRUNNER_TOOL_TIMEOUT", "100")
    assert runner._resolve_timeout(42) == 42


def test_resolve_timeout_uses_env_when_no_override(monkeypatch):
    monkeypatch.setenv("VARDRRUNNER_TOOL_TIMEOUT", "123")
    assert runner._resolve_timeout(None) == 123


def test_resolve_timeout_default(monkeypatch):
    monkeypatch.delenv("VARDRRUNNER_TOOL_TIMEOUT", raising=False)
    assert runner._resolve_timeout(None) == runner.DEFAULT_TOOL_TIMEOUT


def test_resolve_timeout_invalid_env_falls_back(monkeypatch):
    monkeypatch.setenv("VARDRRUNNER_TOOL_TIMEOUT", "not-a-number")
    assert runner._resolve_timeout(None) == runner.DEFAULT_TOOL_TIMEOUT


def test_run_forwards_timeout_to_subprocess(tmp_path):
    output = tmp_path / "out.jsonl"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        runner.run_httpx(["https://example.com"], output, timeout=42)
        assert mock_run.call_args.kwargs["timeout"] == 42


def test_run_raises_tooltimeout_and_cleans_up(tmp_path):
    output = tmp_path / "out.jsonl"
    with patch(
        "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="httpx", timeout=1)
    ) as mock_run:
        with pytest.raises(runner.ToolTimeout):
            runner.run_httpx(["https://example.com"], output, timeout=1)
    # The temp targets file (cmd is ["httpx", "-l", <file>, ...]) must be cleaned up.
    targets_file = mock_run.call_args[0][0][2]
    assert not Path(targets_file).exists()


# ---------------------------------------------------------------------------
# ToolError — non-zero exit must not silently succeed
# ---------------------------------------------------------------------------


def test_run_raises_toolerror_on_nonzero_exit(tmp_path):
    output = tmp_path / "out.jsonl"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        with pytest.raises(runner.ToolError, match="httpx exited with code 1"):
            runner.run_httpx(["https://example.com"], output)


def test_run_does_not_raise_on_zero_exit(tmp_path):
    output = tmp_path / "out.jsonl"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        runner.run_httpx(["https://example.com"], output)  # should not raise


def test_nuclei_raises_toolerror_on_failure(tmp_path):
    output = tmp_path / "out.jsonl"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=2)
        with pytest.raises(runner.ToolError):
            runner.run_nuclei(["https://example.com"], output)


def test_nmap_raises_toolerror_on_failure(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=3)
        with pytest.raises(runner.ToolError):
            runner.run_nmap(["10.0.0.1"], tmp_path / "nmap.xml")


def test_subfinder_raises_toolerror_on_failure(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        with pytest.raises(runner.ToolError):
            runner.run_subfinder(["example.com"], tmp_path / "out.txt")


# ---------------------------------------------------------------------------
# tool_version — per-tool version args and broader regex
# ---------------------------------------------------------------------------


def test_tool_version_uses_dash_dash_version_for_nmap():
    with patch("shutil.which", return_value="/usr/bin/nmap"), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="Nmap version 7.94 ( https://nmap.org )\n", stderr="", returncode=0
        )
        version = runner.tool_version("nmap")
    args = mock_run.call_args[0][0]
    assert "--version" in args
    assert version == "7.94"


def test_tool_version_uses_single_dash_version_for_httpx():
    with patch("shutil.which", return_value="/usr/bin/httpx"), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", stderr="v1.6.9\n", returncode=0)
        version = runner.tool_version("httpx")
    args = mock_run.call_args[0][0]
    assert "-version" in args
    assert version == "v1.6.9"


def test_tool_version_returns_unknown_when_no_match():
    with patch("shutil.which", return_value="/usr/bin/httpx"), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="no version here", stderr="", returncode=0)
        assert runner.tool_version("httpx") == "unknown"


def test_process_observer_receives_pid_and_uses_popen(tmp_path):
    temp = tmp_path / "targets.txt"
    temp.write_text("example.com")
    process = MagicMock(pid=4321)
    process.wait.return_value = 0
    seen = []
    with patch("subprocess.Popen", return_value=process) as popen:
        with runner.observe_process(seen.append):
            runner._run_tool(["httpx"], str(temp), "httpx", 10)
    assert seen == [4321]
    popen.assert_called_once_with(["httpx"])
    assert not temp.exists()


def test_process_is_killed_if_observer_cannot_persist_pid(tmp_path):
    temp = tmp_path / "targets.txt"
    temp.write_text("example.com")
    process = MagicMock(pid=4321)

    def fail(_pid):
        raise RuntimeError("journal unavailable")

    with patch("subprocess.Popen", return_value=process):
        with runner.observe_process(fail):
            with pytest.raises(RuntimeError, match="journal unavailable"):
                runner._run_tool(["httpx"], str(temp), "httpx", 10)
    process.kill.assert_called_once()
    process.wait.assert_called_once()
