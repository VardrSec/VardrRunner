"""Strict platform readiness and offline doctor checks; no repair or execution."""

import copy
import json
from unittest.mock import MagicMock, patch

import pytest
import requests
import typer

from vardrrunner.api import VardrMapClient
from vardrrunner.commands import doctor
from vardrrunner.commands.doctor import Check, Health


@pytest.fixture(autouse=True)
def isolate_keychain(monkeypatch):
    monkeypatch.setattr("vardrrunner.keychain.get_key", lambda url: None)


def payload(database="ok", migrations="current"):
    return {
        "schema_version": 1,
        "component": "vardrmap-api",
        "status": "ready" if database == "ok" and migrations == "current" else "not_ready",
        "checked_at": "2026-10-25T00:00:00+00:00",
        "checks": {"database": database, "migrations": migrations},
    }


def client_response(status, data):
    client = VardrMapClient("https://map.example", "vmap_fixture", retries=0)
    response = MagicMock(status_code=status)
    response.json.return_value = data
    if status >= 400 and status != 503:
        response.raise_for_status.side_effect = requests.HTTPError(response=response)
    client.session.get = MagicMock(return_value=response)
    return client


@pytest.mark.parametrize(
    "database,migrations",
    [
        ("ok", "current"),
        ("ok", "not_current"),
        ("ok", "unavailable"),
        ("unavailable", "not_checked"),
    ],
)
def test_readiness_preserves_explicit_failures_without_free_form_data(database, migrations):
    data = payload(database, migrations)
    data["private"] = "response-secret"
    code = 200 if data["status"] == "ready" else 503
    client = client_response(code, data)
    assert client.platform_readiness() == {"database": database, "migrations": migrations}
    client.session.get.assert_called_once_with(
        "https://map.example/ready",
        timeout=(3.05, 10),
        allow_redirects=False,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"component": "unknown"},
        {"status": "not_ready"},
        {"checks": []},
        {"checks": {"database": "ok", "migrations": "not_checked"}},
        {"checks": {"database": "ok", "migrations": "unknown"}},
        {"checks": {"database": ["ok"], "migrations": "current"}},
        {"checks": {"database": "unavailable", "migrations": "current"}},
    ],
)
def test_unknown_or_inconsistent_contract_cannot_report_healthy(change):
    data = payload()
    data.update(change)
    with pytest.raises(ValueError):
        client_response(200, data).platform_readiness()


@pytest.mark.parametrize("data", [None, [], "login page"])
def test_non_object_contract_is_rejected(data):
    with pytest.raises(ValueError):
        client_response(200, data).platform_readiness()


@pytest.mark.parametrize("status", [204, 302, 404, 500])
def test_unexpected_http_status_is_not_a_pass(status):
    with pytest.raises((requests.HTTPError, ValueError)):
        client_response(status, payload()).platform_readiness()


def test_http_status_must_agree_with_reported_readiness():
    with pytest.raises(ValueError):
        client_response(503, payload()).platform_readiness()
    with pytest.raises(ValueError):
        client_response(200, payload("ok", "not_current")).platform_readiness()


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("VARDRMAP_URL", "https://map.example")
    monkeypatch.setenv("VARDRMAP_API_KEY", "vmap_fixture")


@pytest.mark.parametrize(
    "database,migrations",
    [
        ("ok", "current"),
        ("ok", "not_current"),
        ("unavailable", "not_checked"),
    ],
)
def test_doctor_reports_ready_and_unready_components(configured, database, migrations):
    client = MagicMock()
    client.platform_readiness.return_value = {"database": database, "migrations": migrations}
    with patch("vardrrunner.commands.doctor.api.VardrMapClient", return_value=client) as factory:
        checks = doctor._check_platform()
    factory.assert_called_once_with("https://map.example", "vmap_fixture", retries=0)
    assert checks[0].status is (Health.OK if database == "ok" else Health.FAIL)
    assert checks[1].status is (Health.OK if migrations == "current" else Health.FAIL)


@pytest.mark.parametrize(
    "error",
    [
        requests.Timeout("response-secret"),
        requests.exceptions.SSLError("response-secret"),
        ValueError("response-secret"),
        requests.HTTPError(response=MagicMock(status_code=404)),
        requests.HTTPError(response=MagicMock(status_code=401)),
        requests.HTTPError(),
    ],
)
def test_doctor_reports_transport_or_contract_failure_safely(configured, error):
    with patch("vardrrunner.commands.doctor.api.VardrMapClient") as factory:
        factory.return_value.platform_readiness.side_effect = error
        checks = doctor._check_platform()
    assert checks[0].status is Health.FAIL
    assert "response-secret" not in str(checks)


def test_doctor_does_not_probe_without_config(monkeypatch):
    monkeypatch.delenv("VARDRMAP_URL", raising=False)
    monkeypatch.delenv("VARDRMAP_API_KEY", raising=False)
    with patch("vardrrunner.commands.doctor.api.VardrMapClient") as factory:
        assert doctor._check_platform()[0].status is Health.FAIL
    factory.assert_not_called()


def test_doctor_rejects_insecure_remote_backend_before_probe(configured, monkeypatch):
    monkeypatch.setenv("VARDRMAP_URL", "http://map.example")
    with patch("vardrrunner.commands.doctor.api.VardrMapClient") as factory:
        assert doctor._check_platform()[0].status is Health.FAIL
    factory.assert_not_called()


def test_offline_skips_release_discovery_and_platform_is_opt_in(configured):
    with (
        patch("vardrrunner.commands.doctor._check_version") as version,
        patch("vardrrunner.commands.doctor._check_platform", return_value=[]) as platform,
        patch(
            "vardrrunner.commands.doctor._check_auth", return_value=Check("auth", Health.OK, "ok")
        ),
        patch("vardrrunner.commands.doctor._check_tools", return_value=[]),
        patch("vardrrunner.commands.doctor._check_pipelines", return_value=[]),
        patch("vardrrunner.runner.run_vardrgate") as execute,
    ):
        standard = doctor._collect(offline=True)
        platform.assert_not_called()
        doctor._collect(platform=True, offline=True)
        platform.assert_called_once()
        version.assert_not_called()
        execute.assert_not_called()
    assert "release discovery skipped" in standard[0].detail


def test_platform_failure_is_machine_readable_and_nonzero(configured, capsys):
    checks = [Check("platform database", Health.FAIL, "unavailable")]
    with patch(
        "vardrrunner.commands.doctor._collect", return_value=copy.deepcopy(checks)
    ) as collect:
        with pytest.raises(typer.Exit) as raised:
            doctor.run_doctor(as_json=True, platform=True, offline=True)
    assert raised.value.exit_code == 1
    collect.assert_called_once_with(production=False, platform=True, offline=True)
    report = json.loads(capsys.readouterr().out)
    assert not report["healthy"] and report["checks"][0]["status"] == "fail"
