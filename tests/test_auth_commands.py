"""Tests for auth commands: login_vardrmap, logout, whoami."""

import os
from unittest.mock import MagicMock, patch

import pytest
import typer

from vardrrunner.commands import auth


class TestLoginVardrmap:
    def _run(self, url="https://api.example.com", key="vmap_validkey", whoami_return=None):
        whoami_return = whoami_return or {"username": "jorge", "github_id": 1}
        client = MagicMock()
        client.whoami.return_value = whoami_return
        with (
            patch("vardrrunner.commands.auth.config.validate_api_url"),
            patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client),
            patch("vardrrunner.commands.auth.keychain.available", return_value=True),
            patch("vardrrunner.commands.auth.keychain.set_key", return_value=True),
            patch("vardrrunner.commands.auth.config.save_url"),
        ):
            auth.login_vardrmap(api_url=url, api_key=key)
        return client

    def test_successful_login_with_keychain(self):
        client = self._run()
        client.whoami.assert_called_once()

    def test_invalid_key_prefix_exits(self):
        with pytest.raises(typer.Exit):
            auth.login_vardrmap(api_url="https://api.example.com", api_key="bad_key")

    def test_invalid_url_exits(self):
        with (
            patch(
                "vardrrunner.commands.auth.config.validate_api_url",
                side_effect=Exception("bad url"),
            ),
        ):
            with pytest.raises((typer.Exit, Exception)):
                auth.login_vardrmap(api_url="not-a-url", api_key="vmap_validkey")

    def test_auth_failure_exits(self):
        client = MagicMock()
        client.whoami.side_effect = RuntimeError("401 Unauthorized")
        with (
            patch("vardrrunner.commands.auth.config.validate_api_url"),
            patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client),
        ):
            with pytest.raises(typer.Exit):
                auth.login_vardrmap(api_url="https://api.example.com", api_key="vmap_validkey")

    def test_falls_back_to_config_when_no_keychain(self):
        client = MagicMock()
        client.whoami.return_value = {"username": "jorge"}
        with (
            patch("vardrrunner.commands.auth.config.validate_api_url"),
            patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client),
            patch("vardrrunner.commands.auth.keychain.available", return_value=False),
            patch("vardrrunner.commands.auth.config.save") as mock_save,
        ):
            auth.login_vardrmap(
                api_url="https://api.example.com",
                api_key="vmap_validkey",
                allow_plaintext=True,
            )
        mock_save.assert_called_once()

    def test_direct_call_does_not_treat_typer_default_as_plaintext_opt_in(self):
        client = MagicMock()
        client.whoami.return_value = {"username": "jorge"}
        with (
            patch("vardrrunner.commands.auth.config.validate_api_url"),
            patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client),
            patch("vardrrunner.commands.auth.keychain.available", return_value=False),
            patch("vardrrunner.commands.auth.config.save") as save,
            pytest.raises(typer.Exit),
        ):
            auth.login_vardrmap(api_url="https://api.example.com", api_key="vmap_validkey")
        save.assert_not_called()

    def test_keychain_is_rolled_back_when_url_save_fails(self):
        client = MagicMock()
        client.whoami.return_value = {"username": "jorge"}
        with (
            patch("vardrrunner.commands.auth.config.validate_api_url"),
            patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client),
            patch("vardrrunner.commands.auth.keychain.available", return_value=True),
            patch("vardrrunner.commands.auth.keychain.set_key", return_value=True),
            patch("vardrrunner.commands.auth.config.save_url", side_effect=OSError("disk full")),
            patch("vardrrunner.commands.auth.keychain.delete_key") as delete,
            pytest.raises(typer.Exit),
        ):
            auth.login_vardrmap(api_url="https://api.example.com", api_key="vmap_validkey")
        delete.assert_called_once_with("https://api.example.com")

    def test_plaintext_save_failure_exits_cleanly(self):
        client = MagicMock()
        client.whoami.return_value = {"username": "jorge"}
        with (
            patch("vardrrunner.commands.auth.config.validate_api_url"),
            patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client),
            patch("vardrrunner.commands.auth.keychain.available", return_value=False),
            patch("vardrrunner.commands.auth.config.save", side_effect=OSError("disk full")),
            pytest.raises(typer.Exit),
        ):
            auth.login_vardrmap(
                api_url="https://api.example.com",
                api_key="vmap_validkey",
                allow_plaintext=True,
            )

    def test_invalid_url_raises_invalid_api_url(self):
        from vardrrunner import config as cfg

        with (
            patch(
                "vardrrunner.commands.auth.config.validate_api_url",
                side_effect=cfg.InvalidApiUrl("bad"),
            ),
        ):
            with pytest.raises(typer.Exit):
                auth.login_vardrmap(api_url="http://bad.example.com", api_key="vmap_validkey")


class TestLogout:
    def test_removes_keychain_and_config(self, capsys):
        with (
            patch(
                "vardrrunner.commands.auth.config.get_api_url",
                return_value="https://api.example.com",
            ),
            patch("vardrrunner.commands.auth.keychain.delete_key", return_value=True),
            patch("vardrrunner.commands.auth.config.clear_file_key", return_value=True),
            patch.dict(os.environ, {}, clear=True),
        ):
            auth.logout()
        out = capsys.readouterr().out
        assert "Logged out" in out

    def test_no_key_found_prints_message(self, capsys):
        with (
            patch("vardrrunner.commands.auth.config.get_api_url", return_value=None),
            patch("vardrrunner.commands.auth.keychain.delete_key", return_value=False),
            patch("vardrrunner.commands.auth.config.clear_file_key", return_value=False),
        ):
            auth.logout()
        assert "No stored" in capsys.readouterr().out

    def test_warns_about_env_var(self, capsys):
        from vardrrunner import config as cfg

        with (
            patch(
                "vardrrunner.commands.auth.config.get_api_url",
                return_value="https://api.example.com",
            ),
            patch("vardrrunner.commands.auth.keychain.delete_key", return_value=True),
            patch("vardrrunner.commands.auth.config.clear_file_key", return_value=False),
            patch.dict(os.environ, {cfg.ENV_API_KEY: "vmap_fromenv"}),
        ):
            auth.logout()
        assert cfg.ENV_API_KEY in capsys.readouterr().out


class TestWhoami:
    def test_displays_user_info(self, capsys):
        client = MagicMock()
        client.whoami.return_value = {
            "github_id": 42,
            "username": "jorge",
            "email": "j@example.com",
        }
        with (
            patch(
                "vardrrunner.commands.auth.config.require_auth",
                return_value=("https://api.example.com", "vmap_key"),
            ),
            patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client),
        ):
            auth.whoami()
        out = capsys.readouterr().out
        assert "jorge" in out

    def test_api_error_exits(self):
        client = MagicMock()
        client.whoami.side_effect = RuntimeError("gone")
        with (
            patch(
                "vardrrunner.commands.auth.config.require_auth",
                return_value=("https://api.example.com", "vmap_key"),
            ),
            patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client),
        ):
            with pytest.raises(typer.Exit):
                auth.whoami()
