"""Exercise the public Mapless metadata CLI across independent processes."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def standalone_cli(tmp_path):
    profile = tmp_path / "profile"
    profile.mkdir()
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "PATHEXT"}
    }
    environment.update(
        HOME=str(profile),
        USERPROFILE=str(profile),
        APPDATA=str(profile / "appdata"),
        LOCALAPPDATA=str(profile / "localappdata"),
        XDG_CONFIG_HOME=str(profile / "config"),
        XDG_CACHE_HOME=str(profile / "cache"),
        TEMP=str(temporary),
        TMP=str(temporary),
        TMPDIR=str(temporary),
        PYTHONIOENCODING="utf-8",
        PYTHON_DOTENV_DISABLED="1",
        PYTHON_KEYRING_BACKEND="keyring.backends.fail.Keyring",
        NO_COLOR="1",
        TERM="dumb",
    )
    # Reject network access and tool launches in the child, including imports.
    # No Map URL, API credential, real keychain or inherited application env.
    entrypoint = """
import sys
def refuse_activity(event, arguments):
    if event in {"socket.connect", "socket.getaddrinfo", "subprocess.Popen"}:
        raise RuntimeError("Standalone metadata attempted external activity")
sys.addaudithook(refuse_activity)
from vardrrunner.cli import app
app()
"""

    def invoke(*arguments):
        return subprocess.run(
            [sys.executable, "-c", entrypoint, *arguments],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
            check=False,
        )

    return invoke, profile / ".vardrmap"


def test_absent_workspace_reads_never_initialize_state(standalone_cli):
    invoke, state = standalone_cli
    listing = invoke("workspace", "list")
    assert listing.returncode == 0, listing.stderr
    assert json.loads(listing.stdout) == []
    missing = invoke("workspace", "show", "a" * 32)
    assert missing.returncode == 1
    assert "Cannot read workspace" in missing.stdout
    assert not state.exists()


def test_workspace_survives_process_restart_without_map_or_credentials(standalone_cli):
    invoke, state = standalone_cli
    created = invoke("workspace", "create", "Local assessment")
    assert created.returncode == 0, created.stderr
    workspace = json.loads(created.stdout)
    shown = invoke("workspace", "show", workspace["workspace_id"])
    assert shown.returncode == 0, shown.stderr
    assert json.loads(shown.stdout) == workspace
    listed = invoke("workspace", "list", "--limit", "1")
    assert listed.returncode == 0, listed.stderr
    assert json.loads(listed.stdout) == [workspace]
    assert (state / "runner-journal.sqlite3").is_file()
    assert not (state / "config.json").exists()
    assert not (state / "runner-identity.json").exists()
    assert not (state / "tools").exists()


def test_invalid_workspace_label_refuses_before_creating_state(standalone_cli):
    invoke, state = standalone_cli
    result = invoke("workspace", "create", " invalid label ")
    assert result.returncode == 1
    assert "Cannot create workspace" in result.stdout
    assert not state.exists()
