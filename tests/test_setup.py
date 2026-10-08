from pathlib import Path
from unittest.mock import patch

import pytest
import typer

from vardrrunner import config, identity
from vardrrunner.commands import setup


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(config, "JOURNAL_FILE", tmp_path / "journal.sqlite3")
    monkeypatch.setattr(identity, "identity_file", lambda: tmp_path / "identity.json")
    monkeypatch.setattr("vardrrunner.keychain.get_key", lambda _url: None)
    for name in (config.ENV_API_URL, config.ENV_API_KEY):
        monkeypatch.delenv(name, raising=False)


def _healthy_doctor(*_args, **_kwargs):
    raise typer.Exit(0)


def test_noninteractive_existing_auth_completes_and_sets_name(monkeypatch, capsys):
    monkeypatch.setenv(config.ENV_API_URL, "https://api.example.com")
    monkeypatch.setenv(config.ENV_API_KEY, "vmap_secret")
    with (
        patch("vardrrunner.commands.setup.doctor.run_doctor", side_effect=_healthy_doctor),
        patch("vardrrunner.commands.setup.service_command.install") as install,
    ):
        setup.initialize(name="runner-a", non_interactive=True)
    assert identity.load_or_create().name == "runner-a"
    install.assert_not_called()
    output = capsys.readouterr().out
    assert "setup complete" in output.lower()
    assert "vmap_secret" not in output


def test_interactive_missing_auth_uses_login_and_prompts(monkeypatch):
    def login(**_kwargs):
        monkeypatch.setenv(config.ENV_API_URL, "https://api.example.com")
        monkeypatch.setenv(config.ENV_API_KEY, "vmap_secret")

    with (
        patch("vardrrunner.commands.setup.auth.login_vardrmap", side_effect=login) as login_mock,
        patch("vardrrunner.commands.setup.typer.prompt", return_value="desk-runner"),
        patch("vardrrunner.commands.setup.typer.confirm", return_value=False),
        patch("vardrrunner.commands.setup.doctor.run_doctor", side_effect=_healthy_doctor),
    ):
        setup.initialize()
    login_mock.assert_called_once_with(api_url=None, api_key=None, allow_plaintext=False)
    assert identity.load_or_create().name == "desk-runner"


def test_noninteractive_missing_or_partial_auth_fails_without_prompt():
    with (
        patch("vardrrunner.commands.setup.auth.login_vardrmap") as login,
        pytest.raises(typer.Exit),
    ):
        setup.initialize(non_interactive=True)
    login.assert_not_called()
    with pytest.raises(typer.Exit):
        setup.initialize(api_url="https://api.example.com", non_interactive=True)


def test_login_that_does_not_leave_usable_auth_fails_cleanly():
    with (
        patch("vardrrunner.commands.setup.auth.login_vardrmap"),
        pytest.raises(typer.Exit),
    ):
        setup.initialize(api_url="https://api.example.com", api_key="vmap_secret")


def test_supplied_auth_and_service_options_are_forwarded(monkeypatch):
    def login(**_kwargs):
        monkeypatch.setenv(config.ENV_API_URL, "https://api.example.com")
        monkeypatch.setenv(config.ENV_API_KEY, "vmap_secret")

    env_file = Path("runner.env")
    with (
        patch("vardrrunner.commands.setup.auth.login_vardrmap", side_effect=login) as login_mock,
        patch("vardrrunner.commands.setup.service_command.install") as install,
        patch(
            "vardrrunner.commands.setup.doctor.run_doctor", side_effect=_healthy_doctor
        ) as doctor,
    ):
        setup.initialize(
            api_url="https://api.example.com",
            api_key="vmap_secret",
            allow_plaintext=True,
            production=True,
            install_service=True,
            start_service=False,
            env_file=env_file,
            non_interactive=True,
        )
    login_mock.assert_called_once_with(
        api_url="https://api.example.com",
        api_key="vmap_secret",
        allow_plaintext=True,
    )
    install.assert_called_once_with(env_file=env_file, start=False, dry_run=False)
    doctor.assert_called_once_with(as_json=False, production=True)


def test_production_interactive_defaults_to_service_install(monkeypatch):
    monkeypatch.setenv(config.ENV_API_URL, "https://api.example.com")
    monkeypatch.setenv(config.ENV_API_KEY, "vmap_secret")
    with (
        patch(
            "vardrrunner.commands.setup.typer.prompt", side_effect=lambda *_a, **kw: kw["default"]
        ),
        patch("vardrrunner.commands.setup.typer.confirm", return_value=True) as confirm,
        patch("vardrrunner.commands.setup.tools_command.install") as tools_install,
        patch("vardrrunner.commands.setup.service_command.install") as install,
        patch("vardrrunner.commands.setup.doctor.run_doctor", side_effect=_healthy_doctor),
    ):
        setup.initialize(production=True)
    confirm.assert_any_call("Install the native per-user background service?", default=True)
    install.assert_called_once()
    tools_install.assert_called_once_with([], all_tools=True, force=False)


def test_failed_health_check_keeps_setup_incomplete(monkeypatch, capsys):
    monkeypatch.setenv(config.ENV_API_URL, "https://api.example.com")
    monkeypatch.setenv(config.ENV_API_KEY, "vmap_secret")
    with (
        patch("vardrrunner.commands.setup.doctor.run_doctor", side_effect=typer.Exit(1)),
        pytest.raises(typer.Exit),
    ):
        setup.initialize(non_interactive=True)
    assert "Setup stopped" in capsys.readouterr().out


def test_identity_and_journal_failures_are_clean(monkeypatch):
    monkeypatch.setenv(config.ENV_API_URL, "https://api.example.com")
    monkeypatch.setenv(config.ENV_API_KEY, "vmap_secret")
    with (
        patch(
            "vardrrunner.commands.setup.identity.load_or_create",
            side_effect=identity.IdentityError("broken"),
        ),
        pytest.raises(typer.Exit),
    ):
        setup.initialize(non_interactive=True)
    with (
        patch("vardrrunner.commands.setup.Journal", side_effect=OSError("disk full")),
        pytest.raises(typer.Exit),
    ):
        setup.initialize(non_interactive=True)


def _with_auth(monkeypatch):
    monkeypatch.setenv(config.ENV_API_URL, "https://api.example.com")
    monkeypatch.setenv(config.ENV_API_KEY, "vmap_secret")


def test_interactive_setup_offers_tools_defaulting_to_yes(monkeypatch):
    _with_auth(monkeypatch)
    answers = {"Install pinned, verified scan tools now?": True}
    with (
        patch(
            "vardrrunner.commands.setup.typer.prompt", side_effect=lambda *_a, **kw: kw["default"]
        ),
        patch(
            "vardrrunner.commands.setup.typer.confirm",
            side_effect=lambda text, default: answers.get(text, False),
        ) as confirm,
        patch("vardrrunner.commands.setup.tools_command.install") as tools_install,
        patch("vardrrunner.commands.setup.doctor.run_doctor", side_effect=_healthy_doctor),
    ):
        setup.initialize()
    confirm.assert_any_call("Install pinned, verified scan tools now?", default=True)
    tools_install.assert_called_once_with([], all_tools=True, force=False)


def test_unattended_setup_never_downloads_tools_unasked(monkeypatch):
    _with_auth(monkeypatch)
    with (
        patch("vardrrunner.commands.setup.typer.confirm") as confirm,
        patch("vardrrunner.commands.setup.tools_command.install") as tools_install,
        patch("vardrrunner.commands.setup.doctor.run_doctor", side_effect=_healthy_doctor),
    ):
        setup.initialize(non_interactive=True)
    confirm.assert_not_called()
    tools_install.assert_not_called()


def test_unattended_setup_installs_tools_when_asked(monkeypatch):
    _with_auth(monkeypatch)
    with (
        patch("vardrrunner.commands.setup.tools_command.install") as tools_install,
        patch("vardrrunner.commands.setup.doctor.run_doctor", side_effect=_healthy_doctor),
    ):
        setup.initialize(non_interactive=True, install_tools=True)
    tools_install.assert_called_once_with([], all_tools=True, force=False)


def test_failed_tool_install_does_not_abort_setup(monkeypatch, capsys):
    _with_auth(monkeypatch)
    with (
        patch("vardrrunner.commands.setup.tools_command.install", side_effect=typer.Exit(1)),
        patch("vardrrunner.commands.setup.doctor.run_doctor", side_effect=_healthy_doctor),
    ):
        setup.initialize(non_interactive=True, install_tools=True)
    out = capsys.readouterr().out
    assert "could not be installed" in out and "setup complete" in out.lower()
