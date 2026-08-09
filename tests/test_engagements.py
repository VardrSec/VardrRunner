"""Tests for the engagements commands: list_engagements and show_scope."""

from unittest.mock import MagicMock, patch

import pytest
import typer

from vardrrunner.commands import engagements as prog_cmd


def _mock_auth(url="https://api.example.com", key="vmap_test"):
    return patch("vardrrunner.commands.engagements.config.require_auth", return_value=(url, key))


class TestListPrograms:
    def test_prints_programs(self, capsys):
        client = MagicMock()
        client.engagements.return_value = [
            {
                "id": "p1",
                "name": "TestProg",
                "platform": "hackerone",
                "findings_count": 5,
                "scans_count": 2,
            }
        ]
        with (
            _mock_auth(),
            patch("vardrrunner.commands.engagements.api.VardrMapClient", return_value=client),
        ):
            prog_cmd.list_engagements()

        out = capsys.readouterr().out
        assert "TestProg" in out

    def test_no_programs_prints_dim_message(self, capsys):
        client = MagicMock()
        client.engagements.return_value = []
        with (
            _mock_auth(),
            patch("vardrrunner.commands.engagements.api.VardrMapClient", return_value=client),
        ):
            prog_cmd.list_engagements()

        out = capsys.readouterr().out
        assert "No engagements" in out

    def test_api_error_exits_1(self):
        client = MagicMock()
        client.engagements.side_effect = RuntimeError("network error")
        with (
            _mock_auth(),
            patch("vardrrunner.commands.engagements.api.VardrMapClient", return_value=client),
        ):
            with pytest.raises(typer.Exit):
                prog_cmd.list_engagements()

    def test_program_with_missing_optional_fields(self, capsys):
        client = MagicMock()
        client.engagements.return_value = [{"id": "p1", "name": "Min"}]
        with (
            _mock_auth(),
            patch("vardrrunner.commands.engagements.api.VardrMapClient", return_value=client),
        ):
            prog_cmd.list_engagements()
        out = capsys.readouterr().out
        assert "Min" in out


class TestShowScope:
    def test_in_scope_items_displayed(self, capsys):
        client = MagicMock()
        client.scope.return_value = {
            "in": [{"value": "*.example.com", "kind": "domain"}],
            "out": [],
        }
        with (
            _mock_auth(),
            patch("vardrrunner.commands.engagements.api.VardrMapClient", return_value=client),
        ):
            prog_cmd.show_scope("p1")

        out = capsys.readouterr().out
        assert "*.example.com" in out
        assert "In scope" in out

    def test_out_scope_items_displayed(self, capsys):
        client = MagicMock()
        client.scope.return_value = {
            "in": [],
            "out": [{"value": "internal.example.com", "kind": "domain"}],
        }
        with (
            _mock_auth(),
            patch("vardrrunner.commands.engagements.api.VardrMapClient", return_value=client),
        ):
            prog_cmd.show_scope("p1")

        out = capsys.readouterr().out
        assert "internal.example.com" in out
        assert "Out of scope" in out

    def test_empty_scope_prints_message(self, capsys):
        client = MagicMock()
        client.scope.return_value = {"in": [], "out": []}
        with (
            _mock_auth(),
            patch("vardrrunner.commands.engagements.api.VardrMapClient", return_value=client),
        ):
            prog_cmd.show_scope("p1")

        out = capsys.readouterr().out
        assert "No scope" in out

    def test_api_error_exits_1(self):
        client = MagicMock()
        client.scope.side_effect = RuntimeError("gone")
        with (
            _mock_auth(),
            patch("vardrrunner.commands.engagements.api.VardrMapClient", return_value=client),
        ):
            with pytest.raises(typer.Exit):
                prog_cmd.show_scope("p1")
