"""Stable runner identity lifecycle and CLI presentation."""

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
import typer

from vardrrunner import identity
from vardrrunner.commands import identity as identity_cmd


def test_identity_is_created_once_and_stable(tmp_path, monkeypatch):
    path = tmp_path / "identity.json"
    monkeypatch.setattr(identity, "identity_file", lambda: path)
    with patch("vardrrunner.identity.socket.gethostname", return_value="worker-a"):
        first = identity.load_or_create()
        second = identity.load_or_create()
    assert first == second
    assert uuid.UUID(first.runner_id)
    assert first.name == "worker-a"
    assert json.loads(path.read_text())["identity_schema_version"] == 1


def test_environment_name_overrides_without_rewriting(tmp_path, monkeypatch):
    path = tmp_path / "identity.json"
    monkeypatch.setattr(identity, "identity_file", lambda: path)
    with patch("vardrrunner.identity.socket.gethostname", return_value="host"):
        saved = identity.load_or_create()
    monkeypatch.setenv(identity.ENV_RUNNER_NAME, "SOC runner")
    overridden = identity.load_or_create()
    assert overridden.runner_id == saved.runner_id
    assert overridden.name == "SOC runner"
    assert json.loads(path.read_text())["name"] == "host"


def test_corrupt_identity_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "identity.json"
    path.write_text("not json")
    monkeypatch.setattr(identity, "identity_file", lambda: path)
    with pytest.raises(identity.IdentityError, match="cannot read"):
        identity.load_or_create()
    assert path.read_text() == "not json"


@pytest.mark.parametrize("name", ["", "x" * 129, "bad\nname"])
def test_invalid_names_are_rejected(name, tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "identity_file", lambda: tmp_path / "identity.json")
    with patch("vardrrunner.identity.socket.gethostname", return_value="host"):
        identity.load_or_create()
    with pytest.raises(identity.IdentityError):
        identity.rename(name)


def test_rename_preserves_uuid(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "identity_file", lambda: tmp_path / "identity.json")
    with patch("vardrrunner.identity.socket.gethostname", return_value="host"):
        original = identity.load_or_create()
    renamed = identity.rename("blue-team-runner")
    assert renamed.runner_id == original.runner_id
    assert identity.load_or_create().name == "blue-team-runner"


def test_show_and_set_name_commands(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(identity, "identity_file", lambda: tmp_path / "identity.json")
    with patch("vardrrunner.identity.socket.gethostname", return_value="host"):
        identity_cmd.show()
    identity_cmd.set_name("renamed")
    output = capsys.readouterr().out
    assert "Runner ID" in output
    assert "renamed" in output


def test_identity_command_errors_exit(monkeypatch):
    with patch(
        "vardrrunner.commands.identity.identity.load_or_create",
        side_effect=identity.IdentityError("broken"),
    ):
        with pytest.raises(typer.Exit):
            identity_cmd.show()
    with patch(
        "vardrrunner.commands.identity.identity.rename",
        side_effect=identity.IdentityError("broken"),
    ):
        with pytest.raises(typer.Exit):
            identity_cmd.set_name("x")


def test_concurrent_creation_has_one_stable_uuid(tmp_path, monkeypatch):
    path = tmp_path / "identity.json"
    monkeypatch.setattr(identity, "identity_file", lambda: path)
    with (
        patch("vardrrunner.identity.socket.gethostname", return_value="host"),
        ThreadPoolExecutor(max_workers=4) as pool,
    ):
        values = list(pool.map(lambda _: identity.load_or_create(), range(8)))
    assert len({value.runner_id for value in values}) == 1


def test_invalid_identity_shapes_are_rejected():
    with pytest.raises(identity.IdentityError, match="JSON object"):
        identity._validated([])
    with pytest.raises(identity.IdentityError, match="invalid UUID"):
        identity._validated({"runner_id": "bad", "name": "x", "hostname": "h"})
    with pytest.raises(identity.IdentityError, match="hostname"):
        identity._validated({"runner_id": str(uuid.uuid4()), "name": "x", "hostname": ""})


def test_create_and_rename_io_failures_are_classified(tmp_path, monkeypatch):
    path = tmp_path / "identity.json"
    monkeypatch.setattr(identity, "identity_file", lambda: path)
    with (
        patch("vardrrunner.identity.socket.gethostname", return_value="host"),
        patch("vardrrunner.identity._create_exclusive", side_effect=OSError("disk")),
    ):
        with pytest.raises(identity.IdentityError, match="cannot create"):
            identity.load_or_create()
    with patch("vardrrunner.identity.socket.gethostname", return_value="host"):
        identity.load_or_create()
    with patch("vardrrunner.identity.manifests.write_atomic_json", side_effect=OSError("disk")):
        with pytest.raises(identity.IdentityError, match="cannot update"):
            identity.rename("new")


def test_exclusive_create_reports_existing_file(tmp_path):
    path = tmp_path / "identity.json"
    path.write_text("existing")
    value = identity.RunnerIdentity(str(uuid.uuid4()), "name", "host")
    assert identity._create_exclusive(path, value) is False
