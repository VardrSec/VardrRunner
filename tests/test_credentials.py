"""Credential resolution (env > keychain > file), login/logout, and keychain fallback."""

from unittest.mock import MagicMock, patch

import pytest
import typer

from vardrrunner import config, credentials, keychain
from vardrrunner.commands import auth


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path / "runs")
    for var in (config.ENV_API_URL, config.ENV_API_KEY):
        monkeypatch.delenv(var, raising=False)
    yield


# --- resolution order ---------------------------------------------------------


def test_env_key_wins(monkeypatch):
    config.save({"api_url": "https://x", "api_key": "vmap_file"})
    monkeypatch.setenv(config.ENV_API_KEY, "vmap_env")
    monkeypatch.setattr("vardrrunner.keychain.get_key", lambda url: "vmap_kc")
    assert config.get_api_key() == "vmap_env"


def test_keychain_beats_file(monkeypatch):
    config.save({"api_url": "https://x", "api_key": "vmap_file"})
    monkeypatch.setattr("vardrrunner.keychain.get_key", lambda url: "vmap_kc")
    assert config.get_api_key() == "vmap_kc"


def test_file_is_last_resort(monkeypatch):
    config.save({"api_url": "https://x", "api_key": "vmap_file"})
    monkeypatch.setattr("vardrrunner.keychain.get_key", lambda url: None)
    assert config.get_api_key() == "vmap_file"


@pytest.mark.parametrize(
    "saved_url",
    [
        None,
        "http://map.example/team",
        "https://other.example/team",
        "https://map.example:8443/team",
        "https://map.example/team-other",
        "https://map.example/Team",
    ],
)
def test_file_key_requires_matching_saved_url(monkeypatch, saved_url):
    selected = "https://map.example/team"
    data = {"api_key": "vmap_file"}
    if saved_url is not None:
        data["api_url"] = saved_url
    config.save(data)
    monkeypatch.setenv(config.ENV_API_URL, selected)
    monkeypatch.setattr(keychain, "get_key", lambda url: None)
    monkeypatch.setattr(keychain, "available", lambda: False)

    with pytest.raises(typer.BadParameter, match="Not set up"):
        config.require_auth()
    assert config.credential_source() is None
    posture = credentials.inspect()
    assert posture.api_url == selected
    assert posture.source is None
    assert posture.plaintext_in_config


def test_file_key_accepts_same_map_base_with_trailing_slash(monkeypatch):
    config.save({"api_url": "https://map.example/team/", "api_key": "vmap_file"})
    monkeypatch.setenv(config.ENV_API_URL, "https://map.example/team")
    monkeypatch.setattr(keychain, "get_key", lambda url: None)
    assert config.require_auth() == ("https://map.example/team", "vmap_file")
    assert config.credential_source() == "config file"


def test_url_override_uses_selected_keychain_or_explicit_env_key(monkeypatch):
    selected = "https://second.example"
    config.save({"api_url": "https://first.example", "api_key": "vmap_file"})
    monkeypatch.setenv(config.ENV_API_URL, selected)
    store = {selected: "vmap_second"}
    monkeypatch.setattr(keychain, "get_key", store.get)
    assert config.require_auth() == (selected, "vmap_second")
    assert config.credential_source() == "keychain"
    monkeypatch.setenv(config.ENV_API_KEY, "vmap_env")
    assert config.require_auth() == (selected, "vmap_env")
    assert config.credential_source() == "environment"


def test_config_replacement_cannot_pair_old_url_with_new_key(monkeypatch):
    first = {"api_url": "https://first.example", "api_key": "vmap_first"}
    second = {"api_url": "https://second.example", "api_key": "vmap_second"}
    first_read = iter([first])
    monkeypatch.setattr(config, "load", lambda: next(first_read, second))
    monkeypatch.setattr(keychain, "get_key", lambda url: None)
    with pytest.raises(typer.BadParameter, match="Not set up"):
        config.require_auth()


@pytest.mark.parametrize(
    "env,kc,file_key,expected",
    [
        (True, True, True, "environment"),
        (False, True, True, "keychain"),
        (False, False, True, "config file"),
        (False, False, False, None),
    ],
)
def test_credential_source(monkeypatch, env, kc, file_key, expected):
    config.save({"api_url": "https://x", **({"api_key": "vmap_file"} if file_key else {})})
    if env:
        monkeypatch.setenv(config.ENV_API_KEY, "vmap_env")
    monkeypatch.setattr("vardrrunner.keychain.get_key", lambda url: "vmap_kc" if kc else None)
    assert config.credential_source() == expected


# --- login ---------------------------------------------------------


def test_login_stores_in_keychain_when_available(monkeypatch):
    monkeypatch.setattr("vardrrunner.commands.auth.keychain.available", lambda: True)
    set_mock = MagicMock(return_value=True)
    monkeypatch.setattr("vardrrunner.commands.auth.keychain.set_key", set_mock)
    client = MagicMock()
    client.whoami.return_value = {"username": "alice"}
    with patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client):
        auth.login(
            api_url="https://api.example.com",
            api_key="vmap_secret",
            allow_plaintext=True,
        )

    set_mock.assert_called_once_with("https://api.example.com", "vmap_secret")
    # URL persisted, but NOT the secret.
    saved = config.load()
    assert saved.get("api_url") == "https://api.example.com"
    assert "api_key" not in saved


def test_login_falls_back_to_file_without_keychain(monkeypatch):
    monkeypatch.setattr("vardrrunner.commands.auth.keychain.available", lambda: False)
    client = MagicMock()
    client.whoami.return_value = {"username": "alice"}
    with patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client):
        auth.login(
            api_url="https://api.example.com",
            api_key="vmap_secret",
            allow_plaintext=True,
        )

    saved = config.load()
    assert saved.get("api_key") == "vmap_secret"  # plaintext fallback


# --- logout ---------------------------------------------------------


def test_logout_removes_key_keeps_url(monkeypatch, capsys):
    config.save({"api_url": "https://api.example.com", "api_key": "vmap_file"})
    delete_mock = MagicMock(return_value=True)
    monkeypatch.setattr("vardrrunner.commands.auth.keychain.delete_key", delete_mock)

    auth.logout()

    delete_mock.assert_called_once_with("https://api.example.com")
    saved = config.load()
    assert "api_key" not in saved  # file key cleared
    assert saved.get("api_url") == "https://api.example.com"  # URL kept
    out = capsys.readouterr().out
    assert "Logged out" in out


def test_logout_warns_when_env_key_set(monkeypatch, capsys):
    config.save({"api_url": "https://api.example.com"})
    monkeypatch.setenv(config.ENV_API_KEY, "vmap_env")
    monkeypatch.setattr("vardrrunner.commands.auth.keychain.delete_key", lambda url: False)

    auth.logout()
    assert config.ENV_API_KEY in capsys.readouterr().out


# --- keychain wrapper graceful failure ---------------------------------------


def test_keychain_get_key_swallows_errors():
    with patch("keyring.get_password", side_effect=RuntimeError("locked")):
        assert keychain.get_key("https://x") is None


def test_keychain_set_key_returns_false_on_error():
    with patch("keyring.set_password", side_effect=RuntimeError("no backend")):
        assert keychain.set_key("https://x", "vmap_y") is False


def test_keychain_available_false_on_fail_backend():
    import keyring.backends.fail

    with patch("keyring.get_keyring", return_value=keyring.backends.fail.Keyring()):
        assert keychain.available() is False
