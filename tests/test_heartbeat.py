"""
Tests for the heartbeat command and tool_version helper.
All subprocess and HTTP calls are mocked.
"""

from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# runner.tool_version
# ---------------------------------------------------------------------------


def test_tool_version_returns_semver(tmp_path):
    from vardrrunner import runner

    with patch("shutil.which", return_value="/usr/bin/httpx"), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Current httpx version v1.6.9 (https://github.com/projectdiscovery/httpx)\n",
            stderr="",
        )
        version = runner.tool_version("httpx")
    assert version == "v1.6.9"


def test_tool_version_returns_none_if_not_on_path():
    from vardrrunner import runner

    with patch("shutil.which", return_value=None):
        assert runner.tool_version("httpx") is None


def test_tool_version_returns_none_for_unknown_tool():
    from vardrrunner import runner

    assert runner.tool_version("masscan") is None


def test_tool_version_handles_subprocess_error():
    from vardrrunner import runner

    with (
        patch("shutil.which", return_value="/usr/bin/httpx"),
        patch("subprocess.run", side_effect=OSError("not found")),
    ):
        assert runner.tool_version("httpx") is None


# ---------------------------------------------------------------------------
# commands.heartbeat.send_heartbeat
# ---------------------------------------------------------------------------


def test_send_heartbeat_posts_correct_payload():
    client = MagicMock()

    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.heartbeat.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.heartbeat.runner.tool_version", return_value="v1.0.0"),
        patch("vardrrunner.commands.heartbeat.socket.gethostname", return_value="test-host"),
        patch("vardrrunner.commands.heartbeat.platform.system", return_value="Linux"),
        patch("vardrrunner.commands.heartbeat.platform.release", return_value="6.5"),
    ):
        from vardrrunner.commands.heartbeat import send_heartbeat

        send_heartbeat(quiet=True)

    client.send_heartbeat.assert_called_once()
    payload = client.send_heartbeat.call_args[0][0]
    assert payload["hostname"] == "test-host"
    assert payload["runner_id"]
    assert payload["name"] == "test-host"
    assert payload["os"] == "Linux 6.5"
    assert "httpx" in payload["tools"]
    assert payload["tools"]["httpx"]["ok"] is True
    assert payload["tools"]["httpx"]["version"] == "v1.0.0"
    assert payload["compatibility"]["job_schema_versions"] == [1]


def test_send_heartbeat_returns_backend_compatibility_block(caplog):
    import logging

    from vardrrunner import compatibility
    from vardrrunner.commands.heartbeat import send_heartbeat

    client = MagicMock()
    client.send_heartbeat.return_value = {"compatibility": {"min_runner_version": "99.0.0"}}
    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.heartbeat.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=False),
        caplog.at_level(logging.ERROR),
    ):
        report = send_heartbeat(quiet=True)
    assert report is not None
    assert report.level is compatibility.CompatibilityLevel.BLOCK
    assert any("compatibility block" in record.message.lower() for record in caplog.records)


def test_send_heartbeat_prints_compatibility_warning(capsys):
    from vardrrunner.commands.heartbeat import send_heartbeat

    client = MagicMock()
    client.send_heartbeat.return_value = {"compatibility": {"min_runner_version": "not-semver"}}
    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.heartbeat.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=False),
    ):
        send_heartbeat(quiet=False)
    assert "Compatibility warning" in capsys.readouterr().out


def test_send_heartbeat_logs_compatibility_warning(caplog):
    import logging

    from vardrrunner.commands.heartbeat import send_heartbeat

    client = MagicMock()
    client.send_heartbeat.return_value = {"compatibility": {"min_runner_version": "not-semver"}}
    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.heartbeat.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=False),
        caplog.at_level(logging.WARNING),
    ):
        send_heartbeat(quiet=True)
    assert any("compatibility warning" in record.message.lower() for record in caplog.records)


def test_send_heartbeat_marks_missing_tools():
    client = MagicMock()

    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.heartbeat.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=False),
        patch("vardrrunner.commands.heartbeat.socket.gethostname", return_value="host"),
        patch("vardrrunner.commands.heartbeat.platform.system", return_value="Linux"),
        patch("vardrrunner.commands.heartbeat.platform.release", return_value="6.5"),
    ):
        from vardrrunner.commands.heartbeat import send_heartbeat

        send_heartbeat(quiet=True)

    payload = client.send_heartbeat.call_args[0][0]
    for info in payload["tools"].values():
        assert info["ok"] is False
        assert info["version"] is None


def test_send_heartbeat_does_not_raise_on_api_error():
    client = MagicMock()
    client.send_heartbeat.side_effect = Exception("network error")

    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.heartbeat.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.heartbeat.runner.tool_version", return_value="v1.0.0"),
        patch("vardrrunner.commands.heartbeat.socket.gethostname", return_value="host"),
        patch("vardrrunner.commands.heartbeat.platform.system", return_value="Linux"),
        patch("vardrrunner.commands.heartbeat.platform.release", return_value="6.5"),
    ):
        from vardrrunner.commands.heartbeat import send_heartbeat

        send_heartbeat(quiet=True)  # must not raise


def test_send_heartbeat_skips_when_not_authenticated():
    import typer

    with patch(
        "vardrrunner.commands.heartbeat.config.require_auth",
        side_effect=typer.BadParameter("not logged in"),
    ):
        from vardrrunner.commands.heartbeat import send_heartbeat

        send_heartbeat(quiet=True)  # must not raise


def test_send_heartbeat_unauthenticated_verbose_prints_message(capsys):
    """quiet=False and no auth → skipped message is printed."""
    with patch(
        "vardrrunner.commands.heartbeat.config.require_auth",
        side_effect=RuntimeError("not logged in"),
    ):
        from vardrrunner.commands.heartbeat import send_heartbeat

        send_heartbeat(quiet=False)

    assert "skipped" in capsys.readouterr().out.lower()


def test_send_heartbeat_verbose_prints_tool_status(capsys):
    """quiet=False prints per-tool status after a successful heartbeat."""
    client = MagicMock()

    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.heartbeat.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.heartbeat.runner.tool_version", return_value="v1.0.0"),
        patch("vardrrunner.commands.heartbeat.socket.gethostname", return_value="host"),
        patch("vardrrunner.commands.heartbeat.platform.system", return_value="Linux"),
        patch("vardrrunner.commands.heartbeat.platform.release", return_value="6.5"),
    ):
        from vardrrunner.commands.heartbeat import send_heartbeat

        send_heartbeat(quiet=False)

    out = capsys.readouterr().out
    assert "Heartbeat sent" in out
    assert "httpx" in out


def test_send_heartbeat_verbose_prints_failure(capsys):
    """quiet=False and API failure → failure message is printed."""
    client = MagicMock()
    client.send_heartbeat.side_effect = RuntimeError("backend down")

    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.heartbeat.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=False),
        patch("vardrrunner.commands.heartbeat.socket.gethostname", return_value="host"),
        patch("vardrrunner.commands.heartbeat.platform.system", return_value="Linux"),
        patch("vardrrunner.commands.heartbeat.platform.release", return_value="6.5"),
    ):
        from vardrrunner.commands.heartbeat import send_heartbeat

        send_heartbeat(quiet=False)

    assert "failed" in capsys.readouterr().out.lower()


def test_send_heartbeat_quiet_failure_logs_warning(caplog):
    """quiet=True and API failure → warning is emitted to the logging system."""
    import logging

    client = MagicMock()
    client.send_heartbeat.side_effect = RuntimeError("backend down")

    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.heartbeat.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=False),
        patch("vardrrunner.commands.heartbeat.socket.gethostname", return_value="host"),
        patch("vardrrunner.commands.heartbeat.platform.system", return_value="Linux"),
        patch("vardrrunner.commands.heartbeat.platform.release", return_value="6.5"),
        caplog.at_level(logging.WARNING),
    ):
        from vardrrunner.commands.heartbeat import send_heartbeat

        send_heartbeat(quiet=True)

    assert any("Heartbeat failed" in r.message for r in caplog.records)


def test_send_heartbeat_skips_when_identity_is_broken(caplog):
    import logging

    from vardrrunner import identity
    from vardrrunner.commands.heartbeat import send_heartbeat

    with (
        patch(
            "vardrrunner.commands.heartbeat.config.require_auth", return_value=("http://api", "key")
        ),
        patch(
            "vardrrunner.commands.heartbeat.identity.load_or_create",
            side_effect=identity.IdentityError("broken"),
        ),
        patch("vardrrunner.commands.heartbeat.runner.tool_available", return_value=False),
        caplog.at_level(logging.WARNING),
    ):
        send_heartbeat(quiet=True)
    assert any("identity unavailable" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# jobs.run_jobs — heartbeat is sent at startup
# ---------------------------------------------------------------------------


def test_run_jobs_sends_heartbeat_before_executing(tmp_path):
    output_file = tmp_path / "httpx.jsonl"
    output_file.write_text('{"url":"https://example.com"}\n')

    job = {
        "id": "job-hb1",
        "engagement_id": "prog-1",
        "tool_type": "httpx",
        "target_source": "scope",
        "config": {},
    }

    client = MagicMock()
    client.pending_jobs.return_value = [job]
    client.scope.return_value = {"in": [{"value": "app.example.com"}], "out": []}
    client.import_file.return_value = {"import_record": {"imported_count": 1}}

    heartbeat_calls = []

    def fake_heartbeat(quiet=False):
        heartbeat_calls.append(quiet)

    with (
        patch("vardrrunner.commands.jobs.config.require_auth", return_value=("http://api", "key")),
        patch("vardrrunner.commands.jobs.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.runner.run_httpx", return_value=0),
        patch("vardrrunner.commands.jobs.send_heartbeat", side_effect=fake_heartbeat),
    ):
        from vardrrunner.commands import jobs as jobs_cmd

        jobs_cmd.run_jobs(yes=True)

    assert heartbeat_calls == [True], "run_jobs must send a quiet heartbeat before executing"
