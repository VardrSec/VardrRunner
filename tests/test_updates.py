import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import typer

from vardrrunner import api, updates
from vardrrunner.commands import updates as updates_command

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def update_cache(tmp_path, monkeypatch):
    path = tmp_path / "update-check.json"
    monkeypatch.setattr(updates, "cache_file", lambda: path)
    return path


def test_fetches_and_writes_atomic_cache(update_cache):
    with patch(
        "vardrrunner.updates.api.fetch_release_metadata",
        return_value={"info": {"version": "99.0.0"}},
    ) as fetch:
        status = updates.check(now=lambda: NOW)
    assert status.update_available
    assert status.from_cache is False
    assert json.loads(update_cache.read_text())["latest"] == "99.0.0"
    fetch.assert_called_once()


def test_fresh_cache_avoids_network(update_cache):
    update_cache.write_text(json.dumps({"checked_at": NOW.isoformat(), "latest": "99.0.0"}))
    with patch("vardrrunner.updates.api.fetch_release_metadata") as fetch:
        status = updates.check(now=lambda: NOW + timedelta(hours=1))
    assert status.from_cache is True
    fetch.assert_not_called()


@pytest.mark.parametrize(
    "checked_at",
    [
        (NOW - timedelta(hours=25)).isoformat(),
        (NOW + timedelta(minutes=6)).isoformat(),
        "not-a-date",
    ],
)
def test_stale_future_or_corrupt_cache_is_ignored(update_cache, checked_at):
    update_cache.write_text(json.dumps({"checked_at": checked_at, "latest": "99.0.0"}))
    with patch(
        "vardrrunner.updates.api.fetch_release_metadata",
        return_value={"info": {"version": "0.1.0"}},
    ) as fetch:
        status = updates.check(now=lambda: NOW)
    assert status.latest == "0.1.0"
    fetch.assert_called_once()


def test_force_ignores_fresh_cache(update_cache):
    update_cache.write_text(json.dumps({"checked_at": NOW.isoformat(), "latest": "0.1.0"}))
    with patch(
        "vardrrunner.updates.api.fetch_release_metadata",
        return_value={"info": {"version": "99.0.0"}},
    ):
        assert updates.check(force=True, now=lambda: NOW).latest == "99.0.0"


@pytest.mark.parametrize(
    "payload",
    [{}, {"info": {}}, {"info": {"version": "latest"}}, {"info": []}],
)
def test_malformed_registry_metadata_is_a_domain_error(update_cache, payload):
    with patch("vardrrunner.updates.api.fetch_release_metadata", return_value=payload):
        with pytest.raises(updates.UpdateCheckError):
            updates.check(force=True, now=lambda: NOW)


def test_registry_failure_is_a_domain_error(update_cache):
    with patch(
        "vardrrunner.updates.api.fetch_release_metadata",
        side_effect=api.ReleaseMetadataError("offline"),
    ):
        with pytest.raises(updates.UpdateCheckError, match="release check failed"):
            updates.check(force=True, now=lambda: NOW)


def test_naive_clock_is_normalized(update_cache):
    with patch(
        "vardrrunner.updates.api.fetch_release_metadata",
        return_value={"info": {"version": "0.1.0"}},
    ):
        status = updates.check(force=True, now=lambda: NOW.replace(tzinfo=None))
    assert datetime.fromisoformat(status.checked_at).tzinfo is not None


def test_update_command_human_and_json_output(capsys):
    available = updates.UpdateStatus("1.0.0", "2.0.0", True, NOW.isoformat(), False)
    with patch("vardrrunner.commands.updates.updates.check", return_value=available):
        updates_command.check()
    assert "Update available" in capsys.readouterr().out

    current = updates.UpdateStatus("2.0.0", "2.0.0", False, NOW.isoformat(), True)
    with patch("vardrrunner.commands.updates.updates.check", return_value=current):
        updates_command.check(as_json=True)
    payload = json.loads(capsys.readouterr().out)
    assert payload["from_cache"] is True
    with patch("vardrrunner.commands.updates.updates.check", return_value=current):
        updates_command.check()
    assert "Up to date" in capsys.readouterr().out


def test_update_command_failure_exits(capsys):
    with (
        patch(
            "vardrrunner.commands.updates.updates.check",
            side_effect=updates.UpdateCheckError("offline"),
        ),
        pytest.raises(typer.Exit),
    ):
        updates_command.check()
    assert "Update check failed" in capsys.readouterr().out


def test_cached_reads_a_fresh_cache_without_network(update_cache):
    update_cache.write_text(json.dumps({"checked_at": NOW.isoformat(), "latest": "99.0.0"}))
    with patch("vardrrunner.updates.api.fetch_release_metadata") as fetch:
        status = updates.cached(now=lambda: NOW)
    assert status is not None and status.update_available and status.from_cache
    fetch.assert_not_called()


def test_cached_without_a_cache_is_none_and_offline(update_cache):
    with patch("vardrrunner.updates.api.fetch_release_metadata") as fetch:
        assert updates.cached(now=lambda: NOW.replace(tzinfo=None)) is None
    fetch.assert_not_called()


BASE = str(Path("/", "usr"))


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        (Path("/", "home", "u", ".local", "share", "pipx", "venvs", "vardrrunner"), "pipx upgrade"),
        (
            Path("/", "Users", "u", "AppData", "Local", "pipx", "pipx", "venvs", "vardrrunner"),
            "pipx upgrade",
        ),
        (
            Path("/", "home", "u", ".local", "share", "uv", "tools", "vardrrunner"),
            "uv tool upgrade",
        ),
        (
            Path("/", "Users", "u", "AppData", "Roaming", "uv", "tools", "vardrrunner"),
            "uv tool upgrade",
        ),
        (Path("/", "work", "project", ".venv"), "python -m pip install --upgrade vardrrunner"),
    ],
)
def test_upgrade_command_follows_the_installer(prefix, expected):
    command = updates.upgrade_command(prefix=str(prefix), base_prefix=BASE)
    assert expected in command
    assert " or " not in command


def test_upgrade_command_unknown_layout_names_both_supported_installers():
    command = updates.upgrade_command(prefix=BASE, base_prefix=BASE)
    assert "pipx upgrade vardrrunner" in command
    assert "uv tool upgrade vardrrunner" in command


def test_update_command_names_the_upgrade_command(capsys):
    available = updates.UpdateStatus("1.0.0", "2.0.0", True, NOW.isoformat(), False)
    with (
        patch("vardrrunner.commands.updates.updates.check", return_value=available),
        patch("vardrrunner.updates.upgrade_command", return_value="`uv tool upgrade vardrrunner`"),
    ):
        updates_command.check()
    out = capsys.readouterr().out
    assert "1.0.0 → 2.0.0" in out
    assert "uv tool upgrade vardrrunner" in out
