"""Credential posture and the fail-closed login path.

The behaviour under test is a deliberate breaking change: before v0.31.0,
`login` silently wrote the API key in cleartext whenever no OS keychain was
present. Silence was the problem — an operator provisioning a VPS got a working
runner and an unencrypted key with no decision made.
"""

import contextlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from rich.console import Console

from vardrrunner import config as config_mod
from vardrrunner import credentials
from vardrrunner.commands import auth
from vardrrunner.commands import credentials as cred_cmd

KEY = "vmap_AbCd1234EFgh5678"


@contextlib.contextmanager
def _login_env(keychain_ok: bool, set_key_ok: bool = True):
    """Patch the whole login surface; yields the two persistence mocks."""
    client = MagicMock()
    client.whoami.return_value = {"username": "operator"}
    with (
        patch("vardrrunner.commands.auth.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.auth.config.validate_api_url"),
        patch("vardrrunner.commands.auth.keychain.available", return_value=keychain_ok),
        patch("vardrrunner.commands.auth.keychain.set_key", return_value=set_key_ok),
        patch("vardrrunner.commands.auth.config.save") as save,
        patch("vardrrunner.commands.auth.config.save_url") as save_url,
    ):
        yield save, save_url


class TestLoginFailsClosed:
    def test_refuses_plaintext_without_the_opt_in(self):
        with _login_env(keychain_ok=False) as (save, _):
            with pytest.raises(typer.Exit) as exc:
                auth.login_vardrmap(api_url="https://a", api_key=KEY, allow_plaintext=False)
            assert exc.value.exit_code == 1
            save.assert_not_called()

    def test_writes_plaintext_only_with_the_explicit_flag(self):
        with _login_env(keychain_ok=False) as (save, _):
            auth.login_vardrmap(api_url="https://a", api_key=KEY, allow_plaintext=True)
            save.assert_called_once()
            assert save.call_args[0][0]["api_key"] == KEY

    def test_keychain_path_never_writes_the_key_to_the_file(self):
        with _login_env(keychain_ok=True) as (save, save_url):
            auth.login_vardrmap(api_url="https://a", api_key=KEY, allow_plaintext=False)
            save.assert_not_called()
            save_url.assert_called_once_with("https://a")

    def test_keychain_present_but_write_fails_still_refuses(self):
        """An available-but-broken keyring must not silently downgrade to cleartext."""
        with _login_env(keychain_ok=True, set_key_ok=False) as (save, _):
            with pytest.raises(typer.Exit):
                auth.login_vardrmap(api_url="https://a", api_key=KEY, allow_plaintext=False)
            save.assert_not_called()

    def test_refusal_message_offers_the_env_var_route(self):
        msg = credentials.plaintext_refusal_message(Path("/tmp/config.json"))
        assert "VARDRMAP_API_KEY" in msg
        assert "--allow-plaintext-credentials" in msg

    def test_refusal_message_contains_no_key(self):
        assert KEY not in credentials.plaintext_refusal_message(Path("/tmp/c.json"))


class TestInspect:
    def _status(self, **kw):
        defaults = dict(
            source="keychain",
            keychain_available=True,
            plaintext_in_config=False,
            config_file=Path("/tmp/config.json"),
            config_file_exists=True,
            config_mode="0o600",
            world_readable=False,
            api_url="https://a",
        )
        defaults.update(kw)
        return credentials.CredentialStatus(**defaults)

    def test_keychain_counts_as_encrypted_at_rest(self):
        assert self._status(source="keychain").at_rest_encrypted is True

    def test_environment_is_not_counted_as_encrypted(self):
        """An env var is not on disk via the runner, but it is not encryption —
        any process running as this user can read it."""
        assert self._status(source="environment").at_rest_encrypted is False

    def test_config_file_is_not_encrypted(self):
        assert self._status(source="config file").at_rest_encrypted is False

    def test_unauthenticated_when_no_source(self):
        assert self._status(source=None).is_authenticated is False

    def test_status_never_carries_the_key(self):
        assert KEY not in repr(self._status())

    def test_inspect_survives_a_corrupt_config_file(self):
        """A status command must report on a broken machine, not crash on it."""
        with (
            patch(
                "vardrrunner.credentials.config.load",
                side_effect=config_mod.InvalidConfigFile("bad"),
            ),
            patch("vardrrunner.credentials.keychain.available", return_value=False),
        ):
            s = credentials.inspect()
        assert s.plaintext_in_config is False and s.source is None and s.api_url is None


class TestCredentialsCommand:
    def _run(self, status):
        con = Console(record=True, width=200)
        with (
            patch("vardrrunner.commands.credentials.credentials.inspect", return_value=status),
            patch("vardrrunner.commands.credentials.console", con),
        ):
            try:
                cred_cmd.show_credentials()
            except typer.Exit:
                pass
        return con.export_text()

    def _status(self, **kw):
        defaults = dict(
            source="keychain",
            keychain_available=True,
            plaintext_in_config=False,
            config_file=Path("/tmp/config.json"),
            config_file_exists=True,
            config_mode="0o600",
            world_readable=False,
            api_url="https://a",
        )
        defaults.update(kw)
        return credentials.CredentialStatus(**defaults)

    def test_reports_source_and_encryption(self):
        out = self._run(self._status())
        assert "keychain" in out and "yes" in out

    def test_warns_on_world_readable_plaintext(self):
        out = self._run(
            self._status(
                source="config file",
                plaintext_in_config=True,
                world_readable=True,
                config_mode="0o644",
            )
        )
        assert "chmod 600" in out

    def test_notes_plaintext_without_alarm_when_permissions_are_tight(self):
        out = self._run(
            self._status(source="config file", plaintext_in_config=True, world_readable=False)
        )
        assert "cleartext" in out and "chmod 600" not in out

    def test_exits_nonzero_when_unauthenticated(self):
        with (
            patch(
                "vardrrunner.commands.credentials.credentials.inspect",
                return_value=self._status(source=None),
            ),
        ):
            with pytest.raises(typer.Exit) as e:
                cred_cmd.show_credentials()
            assert e.value.exit_code == 1

    def test_never_prints_a_key(self):
        assert KEY not in self._run(self._status(source="config file", plaintext_in_config=True))
