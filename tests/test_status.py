"""
Tests for vardrrunner status command.
All network calls and tool checks are mocked.
"""

from unittest.mock import MagicMock, patch

import requests

from vardrrunner.commands.status import run_status


def _patch_status(
    config_data=None,
    config_exists=True,
    whoami_result=None,
    whoami_exc=None,
    programs_result=None,
    programs_exc=None,
    tool_available=True,
):
    """Helper: patch all external calls for run_status()."""
    cfg = (
        config_data if config_data is not None else {"api_url": "http://api", "api_key": "vmap_abc"}
    )

    patches = [
        patch("vardrrunner.commands.status.config.load", return_value=cfg),
        patch("vardrrunner.commands.status.config.CONFIG_FILE"),
        patch("vardrrunner.commands.status.runner.tool_available", return_value=tool_available),
    ]

    # CONFIG_FILE.exists() return value
    mock_config_file = MagicMock()
    mock_config_file.exists.return_value = config_exists
    patches[1] = patch("vardrrunner.commands.status.config.CONFIG_FILE", mock_config_file)

    client_mock = MagicMock()
    if whoami_exc:
        client_mock.whoami.side_effect = whoami_exc
    else:
        client_mock.whoami.return_value = whoami_result or {"username": "jorge", "github_id": "123"}

    if programs_exc:
        client_mock.engagements.side_effect = programs_exc
    else:
        client_mock.engagements.return_value = (
            programs_result if programs_result is not None else [{"id": "p1"}, {"id": "p2"}]
        )

    patches.append(
        patch("vardrrunner.commands.status.api.VardrMapClient", return_value=client_mock)
    )

    return patches, client_mock


# ---------------------------------------------------------------------------
# Not logged in
# ---------------------------------------------------------------------------


def test_status_no_config(capsys):
    with (
        patch("vardrrunner.commands.status.config.load", return_value={}),
        patch("vardrrunner.commands.status.config.CONFIG_FILE") as mock_cf,
        patch("vardrrunner.commands.status.runner.tool_available", return_value=True),
    ):
        mock_cf.exists.return_value = False
        run_status()
    # should not raise; should print login hint


def test_status_missing_api_key(capsys):
    with (
        patch("vardrrunner.commands.status.config.load", return_value={"api_url": "http://api"}),
        patch("vardrrunner.commands.status.config.CONFIG_FILE") as mock_cf,
        patch("vardrrunner.commands.status.runner.tool_available", return_value=True),
    ):
        mock_cf.exists.return_value = True
        run_status()
    # should not crash; stops after config section


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_status_all_ok():
    patches, client = _patch_status(
        whoami_result={"username": "jorge", "github_id": "42"},
        programs_result=[{"id": "p1"}, {"id": "p2"}, {"id": "p3"}],
        tool_available=True,
    )
    with patches[0], patches[1], patches[2], patches[3]:
        run_status()
    client.whoami.assert_called_once()
    client.engagements.assert_called_once()


def test_status_one_program():
    patches, client = _patch_status(
        whoami_result={"username": "jorge", "github_id": "42"},
        programs_result=[{"id": "p1"}],
    )
    with patches[0], patches[1], patches[2], patches[3]:
        run_status()  # "1 engagement available" — singular — should not crash


# ---------------------------------------------------------------------------
# Auth failures
# ---------------------------------------------------------------------------


def test_status_http_error_401():
    err = requests.HTTPError(response=MagicMock(status_code=401))
    patches, client = _patch_status(whoami_exc=err)
    with patches[0], patches[1], patches[2], patches[3]:
        run_status()  # should not raise; shows failure row


def test_status_network_unreachable():
    patches, client = _patch_status(whoami_exc=requests.ConnectionError("refused"))
    with patches[0], patches[1], patches[2], patches[3]:
        run_status()  # should not raise


def test_status_programs_fetch_fails():
    err = requests.HTTPError(response=MagicMock(status_code=500))
    patches, client = _patch_status(programs_exc=err)
    with patches[0], patches[1], patches[2], patches[3]:
        run_status()  # authenticated but engagements call fails — should not raise


# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------


def test_status_tool_missing():
    def selective_available(name):
        return name != "nuclei"

    patches, _ = _patch_status()
    with (
        patches[0],
        patches[1],
        patches[3],
        patch("vardrrunner.commands.status.runner.tool_available", side_effect=selective_available),
    ):
        run_status()  # nuclei missing — should not raise


def test_status_all_tools_missing():
    patches, _ = _patch_status(tool_available=False)
    with patches[0], patches[1], patches[2], patches[3]:
        run_status()  # all tools missing — should not raise


# ---------------------------------------------------------------------------
# API key never printed
# ---------------------------------------------------------------------------


def test_status_does_not_print_api_key(capsys):
    patches, _ = _patch_status(config_data={"api_url": "http://api", "api_key": "vmap_supersecret"})
    with patches[0], patches[1], patches[2], patches[3]:
        run_status()
    captured = capsys.readouterr()
    assert "vmap_supersecret" not in captured.out
    assert "vmap_supersecret" not in captured.err
