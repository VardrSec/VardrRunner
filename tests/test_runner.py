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


def _mock_tool_process(returncode=0, pid=4321):
    process = MagicMock(pid=pid)
    process.wait.return_value = returncode
    return process


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
    process = _mock_tool_process()
    with patch("vardrrunner.runner._spawn_tool", return_value=process) as mock_spawn:
        runner.run_httpx(["https://example.com"], output)
        args = mock_spawn.call_args[0][0]
        assert isinstance(args, list), "subprocess must be called with a list, not a shell string"
        assert args[0] == "httpx"


def test_run_nuclei_uses_arg_list(tmp_path):
    output = tmp_path / "out.jsonl"
    process = _mock_tool_process()
    with patch("vardrrunner.runner._spawn_tool", return_value=process) as mock_spawn:
        runner.run_nuclei(["https://example.com"], output, severity="high,critical")
        args = mock_spawn.call_args[0][0]
        assert isinstance(args, list)
        assert args[0] == "nuclei"
        assert "-severity" in args
        assert "high,critical" in args


def test_run_dnsx_uses_arg_list(tmp_path):
    process = _mock_tool_process()
    with patch("vardrrunner.runner._spawn_tool", return_value=process) as mock_spawn:
        runner.run_dnsx(["a.example.com"], tmp_path / "out.txt")
        args = mock_spawn.call_args[0][0]
        assert args[0] == "dnsx" and "-l" in args and "-silent" in args


def test_run_vardrgate_uses_arg_list(tmp_path):
    output = tmp_path / "result.json"
    job = {"config": {"test_case": {"id": "x"}, "execution": {}}}
    process = _mock_tool_process()
    with patch("vardrrunner.runner._spawn_tool", return_value=process) as mock_spawn:
        runner.run_vardrgate(job, output)
        args = mock_spawn.call_args[0][0]
    assert isinstance(args, list)
    assert args[0] == "vardrgate"
    assert args[1] == "run"
    assert "--job" in args and "--out" in args
    assert str(output) in args
    job_path = Path(args[args.index("--job") + 1])
    assert not job_path.exists()
    assert not job_path.parent.exists()


def test_run_naabu_uses_arg_list(tmp_path):
    process = _mock_tool_process()
    with patch("vardrrunner.runner._spawn_tool", return_value=process) as mock_spawn:
        runner.run_naabu(["a.example.com"], tmp_path / "out.json", top_ports=50)
        args = mock_spawn.call_args[0][0]
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
    process = _mock_tool_process()
    with patch("vardrrunner.runner._spawn_tool", return_value=process):
        runner.run_httpx(["https://example.com"], output, timeout=42)
        process.wait.assert_called_once_with(timeout=42)


def test_run_raises_tooltimeout_and_cleans_up(tmp_path):
    output = tmp_path / "out.jsonl"
    process = _mock_tool_process()
    process.wait.side_effect = subprocess.TimeoutExpired(cmd="httpx", timeout=1)
    with (
        patch("vardrrunner.runner._spawn_tool", return_value=process) as mock_spawn,
        patch("vardrrunner.runner._terminate_process_tree") as terminate,
    ):
        with pytest.raises(runner.ToolTimeout):
            runner.run_httpx(["https://example.com"], output, timeout=1)
    terminate.assert_called_once_with(process)
    # The temp targets file (cmd is ["httpx", "-l", <file>, ...]) must be cleaned up.
    targets_file = mock_spawn.call_args[0][0][2]
    assert not Path(targets_file).exists()


# ---------------------------------------------------------------------------
# ToolError — non-zero exit must not silently succeed
# ---------------------------------------------------------------------------


def test_run_raises_toolerror_on_nonzero_exit(tmp_path):
    output = tmp_path / "out.jsonl"
    process = _mock_tool_process(returncode=1)
    with patch("vardrrunner.runner._spawn_tool", return_value=process):
        with pytest.raises(runner.ToolError, match="httpx exited with code 1"):
            runner.run_httpx(["https://example.com"], output)


def test_run_does_not_raise_on_zero_exit(tmp_path):
    output = tmp_path / "out.jsonl"
    process = _mock_tool_process()
    with patch("vardrrunner.runner._spawn_tool", return_value=process):
        runner.run_httpx(["https://example.com"], output)  # should not raise


def test_nuclei_raises_toolerror_on_failure(tmp_path):
    output = tmp_path / "out.jsonl"
    process = _mock_tool_process(returncode=2)
    with patch("vardrrunner.runner._spawn_tool", return_value=process):
        with pytest.raises(runner.ToolError):
            runner.run_nuclei(["https://example.com"], output)


def test_nmap_raises_toolerror_on_failure(tmp_path):
    process = _mock_tool_process(returncode=3)
    with patch("vardrrunner.runner._spawn_tool", return_value=process):
        with pytest.raises(runner.ToolError):
            runner.run_nmap(["10.0.0.1"], tmp_path / "nmap.xml")


def test_subfinder_raises_toolerror_on_failure(tmp_path):
    process = _mock_tool_process(returncode=1)
    with patch("vardrrunner.runner._spawn_tool", return_value=process):
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
    with patch("vardrrunner.runner._spawn_tool", return_value=process) as spawn:
        with runner.observe_process(seen.append):
            runner._run_tool(["httpx"], str(temp), "httpx", 10)
    assert seen == [4321]
    spawn.assert_called_once_with(["httpx"])
    assert not temp.exists()


def test_process_is_killed_if_observer_cannot_persist_pid(tmp_path):
    temp = tmp_path / "targets.txt"
    temp.write_text("example.com")
    process = MagicMock(pid=4321)

    def fail(_pid):
        raise RuntimeError("journal unavailable")

    with (
        patch("vardrrunner.runner._spawn_tool", return_value=process),
        patch("vardrrunner.runner._terminate_process_tree") as terminate,
    ):
        with runner.observe_process(fail):
            with pytest.raises(RuntimeError, match="journal unavailable"):
                runner._run_tool(["httpx"], str(temp), "httpx", 10)
    terminate.assert_called_once_with(process)


def test_spawn_tool_starts_a_new_posix_session():
    with (
        patch.object(runner.os, "name", "posix"),
        patch("vardrrunner.runner.subprocess.Popen") as popen,
    ):
        runner._spawn_tool(["httpx"])
    popen.assert_called_once_with(["httpx"], start_new_session=True)


def test_spawn_tool_starts_a_new_windows_process_group():
    with (
        patch.object(runner.os, "name", "nt"),
        patch.object(runner.subprocess, "CREATE_NEW_PROCESS_GROUP", 512, create=True),
        patch("vardrrunner.runner.subprocess.Popen") as popen,
    ):
        runner._spawn_tool(["httpx"])
    popen.assert_called_once_with(["httpx"], creationflags=512)


def test_terminate_process_tree_kills_posix_group():
    process = _mock_tool_process(pid=9876)
    with (
        patch.object(runner.os, "name", "posix"),
        patch.object(runner.signal, "SIGKILL", 9, create=True),
        patch("vardrrunner.runner.os.killpg", create=True) as killpg,
    ):
        runner._terminate_process_tree(process)
    killpg.assert_called_once_with(9876, 9)
    process.wait.assert_called_once_with(timeout=10)


def test_terminate_process_tree_uses_taskkill_on_windows():
    process = _mock_tool_process(pid=9876)
    result = MagicMock(returncode=0)
    with (
        patch.object(runner.os, "name", "nt"),
        patch("vardrrunner.runner.subprocess.run", return_value=result) as run,
    ):
        runner._terminate_process_tree(process)
    run.assert_called_once_with(
        ["taskkill.exe", "/PID", "9876", "/T", "/F"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    process.kill.assert_not_called()


@pytest.mark.parametrize("taskkill_result", [MagicMock(returncode=1), OSError("missing")])
def test_terminate_process_tree_falls_back_when_taskkill_fails(taskkill_result):
    process = _mock_tool_process(pid=9876)
    kwargs = (
        {"side_effect": taskkill_result}
        if isinstance(taskkill_result, BaseException)
        else {"return_value": taskkill_result}
    )
    with (
        patch.object(runner.os, "name", "nt"),
        patch("vardrrunner.runner.subprocess.run", **kwargs),
    ):
        runner._terminate_process_tree(process)
    process.kill.assert_called_once_with()


@pytest.mark.parametrize(
    ("killpg_error", "fallback_expected"),
    [(ProcessLookupError(), False), (OSError("denied"), True)],
)
def test_terminate_process_tree_handles_posix_kill_errors(killpg_error, fallback_expected):
    process = _mock_tool_process(pid=9876)
    with (
        patch.object(runner.os, "name", "posix"),
        patch.object(runner.signal, "SIGKILL", 9, create=True),
        patch("vardrrunner.runner.os.killpg", side_effect=killpg_error, create=True),
    ):
        runner._terminate_process_tree(process)
    assert process.kill.called is fallback_expected


def test_terminate_process_tree_force_reaps_parent_after_wait_timeout():
    process = _mock_tool_process(pid=9876)
    process.wait.side_effect = [subprocess.TimeoutExpired("httpx", 10), 0]
    with (
        patch.object(runner.os, "name", "posix"),
        patch.object(runner.signal, "SIGKILL", 9, create=True),
        patch("vardrrunner.runner.os.killpg", create=True),
    ):
        runner._terminate_process_tree(process)
    process.kill.assert_called_once_with()
    assert process.wait.call_count == 2


@pytest.mark.parametrize(
    ("pid", "kill_effect", "expected"),
    [
        (0, None, False),
        (123, None, True),
        (123, ProcessLookupError(), False),
        (123, PermissionError(), True),
    ],
)
def test_pid_alive_posix_outcomes(pid, kill_effect, expected):
    with (
        patch.object(runner.os, "name", "posix"),
        patch("vardrrunner.runner.os.kill", side_effect=kill_effect) as kill,
    ):
        assert runner._pid_alive(pid) is expected
    if pid <= 0:
        kill.assert_not_called()
    else:
        kill.assert_called_once_with(pid, 0)


def test_cleanup_sensitive_temp_dirs_removes_only_abandoned_private_dirs(tmp_path):
    abandoned = tmp_path / f"{runner._SENSITIVE_TEMP_PREFIX}999999-dead"
    active = tmp_path / f"{runner._SENSITIVE_TEMP_PREFIX}123-active"
    unrelated = tmp_path / "other-tool-data"
    for directory in (abandoned, active, unrelated):
        directory.mkdir()
        (directory / "job.json").write_text("secret")

    with (
        patch("vardrrunner.runner.tempfile.gettempdir", return_value=str(tmp_path)),
        patch("vardrrunner.runner._pid_alive", side_effect=lambda pid: pid == 123),
    ):
        runner.cleanup_sensitive_temp_dirs()

    assert not abandoned.exists()
    assert active.exists()
    assert unrelated.exists()


def test_cleanup_sensitive_temp_dirs_ignores_unreadable_temp_root(tmp_path):
    with (
        patch("vardrrunner.runner.tempfile.gettempdir", return_value=str(tmp_path)),
        patch("vardrrunner.runner.Path.iterdir", side_effect=OSError("denied")),
    ):
        runner.cleanup_sensitive_temp_dirs()


def test_cleanup_sensitive_temp_dirs_warns_when_removal_fails(tmp_path, caplog):
    abandoned = tmp_path / f"{runner._SENSITIVE_TEMP_PREFIX}999999-dead"
    abandoned.mkdir()
    with (
        patch("vardrrunner.runner.tempfile.gettempdir", return_value=str(tmp_path)),
        patch("vardrrunner.runner._pid_alive", return_value=False),
        patch("vardrrunner.runner.shutil.rmtree", side_effect=OSError("locked")),
        caplog.at_level("WARNING"),
    ):
        runner.cleanup_sensitive_temp_dirs()
    assert "abandoned sensitive VardrGate" in caplog.text


def test_write_private_job_removes_directory_when_creation_fails(tmp_path):
    directory = tmp_path / "private-job"
    directory.mkdir()
    with (
        patch("vardrrunner.runner.cleanup_sensitive_temp_dirs"),
        patch("vardrrunner.runner.tempfile.mkdtemp", return_value=str(directory)),
        patch("vardrrunner.runner.os.open", side_effect=OSError("denied")),
    ):
        with pytest.raises(OSError):
            runner._write_private_job({"secret": "value"})
    assert not directory.exists()


def test_run_vardrgate_cleans_private_directory_after_tool_failure(tmp_path):
    directory = tmp_path / "private-job"
    directory.mkdir()
    job_file = directory / "job.json"
    job_file.write_text("{}")
    with (
        patch("vardrrunner.runner._write_private_job", return_value=(job_file, directory)),
        patch("vardrrunner.runner._run_tool", side_effect=runner.ToolError("failed")),
    ):
        with pytest.raises(runner.ToolError, match="failed"):
            runner.run_vardrgate({}, tmp_path / "result.json")
    assert not directory.exists()


def test_run_vardrgate_fails_closed_when_sensitive_cleanup_fails(tmp_path):
    directory = tmp_path / "private-job"
    directory.mkdir()
    job_file = directory / "job.json"
    with (
        patch("vardrrunner.runner._write_private_job", return_value=(job_file, directory)),
        patch("vardrrunner.runner._run_tool"),
        patch("vardrrunner.runner.shutil.rmtree", side_effect=OSError("locked")),
    ):
        with pytest.raises(runner.ToolError, match="could not remove sensitive"):
            runner.run_vardrgate({}, tmp_path / "result.json")
