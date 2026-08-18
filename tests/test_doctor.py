"""Tests for `vardrrunner doctor` — the preflight health check and its exit codes."""

from unittest.mock import MagicMock, patch

import pytest
import typer

from vardrrunner.commands import doctor
from vardrrunner.commands.doctor import Check, Health


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Point config + runs at a temp dir and clear credential env vars."""
    monkeypatch.setattr("vardrrunner.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("vardrrunner.config.CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setattr("vardrrunner.config.RUNS_DIR", tmp_path / "runs")
    for var in ("VARDRMAP_URL", "VARDRMAP_API_KEY", "VARDRRUNNER_ALLOW_INSECURE"):
        monkeypatch.delenv(var, raising=False)
    # Never touch the real OS keychain in tests.
    monkeypatch.setattr("vardrrunner.keychain.get_key", lambda url: None)
    yield


def _run(as_json=False):
    """Run doctor, capturing the SystemExit-style code from typer.Exit."""
    try:
        doctor.run_doctor(as_json=as_json)
    except typer.Exit as e:
        return e.exit_code
    return 0


def test_fails_without_credentials():
    # No config, no env → credentials FAIL → exit non-zero.
    with patch("vardrrunner.runner.tool_available", return_value=True):
        assert _run() == 1


def test_exit_zero_when_healthy(monkeypatch):
    monkeypatch.setenv("VARDRMAP_URL", "https://api.example.com")
    monkeypatch.setenv("VARDRMAP_API_KEY", "vmap_ok")
    client = MagicMock()
    client.whoami.return_value = {"username": "alice"}
    with (
        patch("vardrrunner.commands.doctor.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.runner.tool_version", return_value="v1.0.0"),
    ):
        assert _run() == 0


def test_auth_failure_is_fatal(monkeypatch):
    import requests

    monkeypatch.setenv("VARDRMAP_URL", "https://api.example.com")
    monkeypatch.setenv("VARDRMAP_API_KEY", "vmap_bad")
    client = MagicMock()
    resp = MagicMock(status_code=401)
    client.whoami.side_effect = requests.HTTPError(response=resp)
    with (
        patch("vardrrunner.commands.doctor.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
    ):
        assert _run() == 1


def test_missing_tools_warn_but_one_present_is_ok(monkeypatch):
    """Some tools missing → warnings, not failure, as long as one is installed."""
    monkeypatch.setenv("VARDRMAP_URL", "https://api.example.com")
    monkeypatch.setenv("VARDRMAP_API_KEY", "vmap_ok")
    client = MagicMock()
    client.whoami.return_value = {"username": "alice"}
    with (
        patch("vardrrunner.commands.doctor.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", side_effect=lambda t: t == "httpx"),
        patch("vardrrunner.runner.tool_version", return_value="v1.0.0"),
    ):
        assert _run() == 0  # warnings don't fail the preflight


def test_no_tools_at_all_is_fatal(monkeypatch):
    monkeypatch.setenv("VARDRMAP_URL", "https://api.example.com")
    monkeypatch.setenv("VARDRMAP_API_KEY", "vmap_ok")
    client = MagicMock()
    client.whoami.return_value = {"username": "alice"}
    with (
        patch("vardrrunner.commands.doctor.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=False),
    ):
        assert _run() == 1


def test_stale_daemon_pid_warns(monkeypatch):
    check = None
    with (
        patch("vardrrunner.commands.doctor.daemon._read_pid", return_value=4242),
        patch("vardrrunner.commands.doctor.daemon._process_alive", return_value=False),
    ):
        check = doctor._check_daemon()
    assert check.status is Health.WARN and "stale" in check.detail


def test_json_output_is_structured(monkeypatch, capsys):
    monkeypatch.setenv("VARDRMAP_URL", "https://api.example.com")
    monkeypatch.setenv("VARDRMAP_API_KEY", "vmap_ok")
    client = MagicMock()
    client.whoami.return_value = {"username": "alice"}
    with (
        patch("vardrrunner.commands.doctor.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.runner.tool_version", return_value="v1.0.0"),
    ):
        code = _run(as_json=True)
    import json

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["healthy"] is True
    assert payload["summary"]["fail"] == 0
    assert any(c["name"] == "api auth" for c in payload["checks"])


def test_check_dataclass_shape():
    c = Check("x", Health.OK, "fine")
    assert c.remediation == "" and c.status is Health.OK


def test_production_profile_requires_secure_storage_and_service(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_text('{"api_url":"https://api.example.com","api_key":"vmap_plain"}')
    monkeypatch.setattr("vardrrunner.config.CONFIG_FILE", config_file)
    client = MagicMock()
    client.whoami.return_value = {"username": "alice"}
    with (
        patch("vardrrunner.commands.doctor.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch(
            "vardrrunner.commands.doctor.service.build_plan",
            side_effect=doctor.service.ServiceError("not installed"),
        ),
    ):
        checks = doctor._collect(production=True)
    storage = next(check for check in checks if check.name == "credential storage")
    background = next(check for check in checks if check.name == "background service")
    assert storage.status is Health.FAIL
    assert background.status is Health.FAIL


def test_production_service_accepts_running_daemon():
    with (
        patch("vardrrunner.commands.doctor.daemon._read_pid", return_value=123),
        patch("vardrrunner.commands.doctor.daemon._process_alive", return_value=True),
    ):
        check = doctor._check_service()
    assert check.status is Health.OK


def test_identity_and_journal_failures_are_fatal():
    from vardrrunner import identity
    from vardrrunner.journal import JournalError

    with patch(
        "vardrrunner.commands.doctor.identity.load_or_create",
        side_effect=identity.IdentityError("broken"),
    ):
        assert doctor._check_identity().status is Health.FAIL
    with patch("vardrrunner.commands.doctor.Journal", side_effect=JournalError("broken")):
        assert doctor._check_journal().status is Health.FAIL


def test_resource_policy_is_reported_and_invalid_values_fail(monkeypatch):
    monkeypatch.setenv("VARDRRUNNER_MAX_CONCURRENT_JOBS", "2")
    check = doctor._check_resource_policy()
    assert check.status is Health.OK
    assert "concurrency=2" in check.detail
    monkeypatch.setenv("VARDRRUNNER_MAX_CONCURRENT_JOBS", "99")
    assert doctor._check_resource_policy().status is Health.FAIL


def test_json_reports_standard_profile_by_default(capsys):
    checks = [Check("all", Health.OK, "ready")]
    with patch("vardrrunner.commands.doctor._collect", return_value=checks):
        assert _run(as_json=True) == 0
    import json

    assert json.loads(capsys.readouterr().out)["profile"] == "standard"


def test_auth_skipped_when_url_invalid(monkeypatch):
    """_check_auth returns WARN (not a network call) when the backend URL is bad."""
    monkeypatch.setenv("VARDRMAP_URL", "http://remote.example.com")  # non-local http → invalid
    monkeypatch.setenv("VARDRMAP_API_KEY", "vmap_ok")
    check = doctor._check_auth()
    assert check.status is Health.WARN
    assert "invalid backend URL" in check.detail


def test_corrupt_config_fails_doctor(tmp_path, monkeypatch):
    """A malformed config.json produces a FAIL check and doctor exits non-zero."""
    cf = tmp_path / "config.json"
    cf.write_text("{broken")
    monkeypatch.setattr("vardrrunner.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("vardrrunner.config.CONFIG_FILE", cf)
    monkeypatch.setattr("vardrrunner.config.RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr("vardrrunner.keychain.get_key", lambda url: None)
    with patch("vardrrunner.runner.tool_available", return_value=True):
        code = _run()
    assert code == 1


def test_corrupt_config_still_runs_tool_checks(tmp_path, monkeypatch):
    """Even with a broken config, doctor still reports tool availability."""
    cf = tmp_path / "config.json"
    cf.write_text("not-json")
    monkeypatch.setattr("vardrrunner.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("vardrrunner.config.CONFIG_FILE", cf)
    monkeypatch.setattr("vardrrunner.config.RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr("vardrrunner.keychain.get_key", lambda url: None)
    with patch("vardrrunner.runner.tool_available", return_value=False):
        checks = doctor._collect()
    names = [c.name for c in checks]
    # Config-file check present, and tool checks still ran.
    assert "config file" in names
    assert any(n.startswith("tool:") for n in names)
