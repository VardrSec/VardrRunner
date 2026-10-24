"""
Tests for the interactive console (vardrrunner/shell.py).

Commands are run through the real Typer app with their command modules mocked, so these
also prove that the console reaches the same wiring as a one-shot invocation.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import typer
from rich.console import Console

from vardrrunner import __version__, shell, updates
from vardrrunner.cli import app

ENGAGEMENT = "3f2a9c1e-0000-4000-8000-000000000001"
OTHER = "3f2a9c1e-0000-4000-8000-000000000002"
CHECKED_AT = "2026-10-24T00:00:00+00:00"


@pytest.fixture(autouse=True)
def recording_console(monkeypatch):
    """Capture console output at a width that fits the shield."""
    recorder = Console(record=True, width=120, force_terminal=False, color_system=None)
    monkeypatch.setattr(shell, "console", recorder)
    return recorder


def _output(recorder: Console) -> str:
    return recorder.export_text()


@pytest.fixture
def session():
    return shell.Session(typer.main.get_command(app))


def _first(seq):
    return seq[0]


# --------------------------------------------------------------------------- #
# Line splitting
# --------------------------------------------------------------------------- #


class TestSplit:
    def test_keeps_windows_backslashes(self):
        assert shell.split(r"import nuclei -f C:\scans\out.jsonl") == [
            "import",
            "nuclei",
            "-f",
            r"C:\scans\out.jsonl",
        ]

    def test_honors_quotes(self):
        assert shell.split('identity set-name "red team box"') == [
            "identity",
            "set-name",
            "red team box",
        ]

    def test_keeps_hash_in_urls(self):
        assert shell.split("run httpx --target https://a.example/#frag") == [
            "run",
            "httpx",
            "--target",
            "https://a.example/#frag",
        ]

    def test_unclosed_quote_raises(self):
        with pytest.raises(ValueError):
            shell.split('identity set-name "unterminated')


# --------------------------------------------------------------------------- #
# Engagement defaults
# --------------------------------------------------------------------------- #


class TestEngagement:
    def test_use_sets_engagement_and_prompt(self, session):
        assert session.handle(f"use {ENGAGEMENT}") is True
        assert session.engagement == ENGAGEMENT
        assert session.prompt() == "vardrrunner(3f2a9c1e) > "

    def test_back_clears_engagement(self, session):
        session.handle(f"use {ENGAGEMENT}")
        session.handle("back")
        assert session.engagement is None
        assert session.prompt() == "vardrrunner > "

    def test_use_rejects_non_uuid(self, session, recording_console):
        session.handle("use not-an-id")
        assert session.engagement is None
        assert "Not an engagement ID" in _output(recording_console)

    def test_use_without_argument_prints_usage(self, session, recording_console):
        session.handle("use")
        assert "Usage: use <engagement-id>" in _output(recording_console)

    def test_fills_positional_engagement(self, session):
        session.handle(f"use {ENGAGEMENT}")
        with patch("vardrrunner.commands.engagements.show_scope") as show_scope:
            session.handle("scope")
        show_scope.assert_called_once_with(ENGAGEMENT)

    def test_fills_engagement_option(self, session):
        session.handle(f"use {ENGAGEMENT}")
        with patch("vardrrunner.commands.imports.import_file") as import_file:
            session.handle(r"import nuclei -f C:\scans\out.jsonl")
        assert import_file.call_args.args[:2] == ("nuclei", ENGAGEMENT)
        assert str(import_file.call_args.args[2]) == r"C:\scans\out.jsonl"

    def test_typed_engagement_wins(self, session):
        session.handle(f"use {ENGAGEMENT}")
        with patch("vardrrunner.commands.imports.import_file") as import_file:
            session.handle(f"import nuclei -e {OTHER} -f out.jsonl")
        assert import_file.call_args.args[1] == OTHER

    def test_without_engagement_required_option_still_errors(self, session, capsys):
        with patch("vardrrunner.commands.imports.import_file") as import_file:
            assert session.handle("import nuclei -f out.jsonl") is True
        import_file.assert_not_called()
        assert "Missing option '--engagement'" in capsys.readouterr().err

    def test_defaults_cover_nested_groups_only_where_taken(self):
        defaults = shell.engagement_defaults(typer.main.get_command(app), ENGAGEMENT)
        assert defaults["scope"] == {"engagement_id": ENGAGEMENT}
        assert defaults["import"]["nuclei"] == {"engagement_id": ENGAGEMENT}
        assert "heartbeat" not in defaults


# --------------------------------------------------------------------------- #
# Running commands
# --------------------------------------------------------------------------- #


class TestHandle:
    def test_runs_command_without_program_name(self, session):
        with patch("vardrrunner.commands.heartbeat.send_heartbeat") as send:
            session.handle("heartbeat")
        send.assert_called_once()

    def test_leading_program_name_is_accepted(self, session):
        with patch("vardrrunner.commands.heartbeat.send_heartbeat") as send:
            session.handle("vardrrunner heartbeat")
        send.assert_called_once()

    @pytest.mark.parametrize("line", ["", "   ", "vardrrunner"])
    def test_empty_lines_do_nothing(self, session, line):
        assert session.handle(line) is True

    @pytest.mark.parametrize("word", ["exit", "quit", "EXIT"])
    def test_exit_words_leave(self, session, word):
        assert session.handle(word) is False

    def test_mcp_is_refused(self, session, recording_console):
        with patch("vardrrunner.mcp_server.run") as run:
            session.handle("mcp")
        run.assert_not_called()
        assert "can't run inside the console" in _output(recording_console)

    def test_unknown_command_keeps_session(self, session, capsys):
        assert session.handle("nonsense") is True
        assert "No such command 'nonsense'" in capsys.readouterr().err

    def test_group_without_subcommand_shows_its_help(self, session, capsys):
        assert session.handle("jobs") is True
        assert "list" in capsys.readouterr().out

    def test_unclosed_quote_keeps_session(self, session, recording_console):
        assert session.handle('identity set-name "oops') is True
        assert "Could not read that line" in _output(recording_console)

    def test_failing_command_exit_keeps_session(self, session):
        with patch("vardrrunner.commands.heartbeat.send_heartbeat", side_effect=typer.Exit(1)):
            assert session.handle("heartbeat") is True

    def test_abort_keeps_session(self, session, recording_console):
        with patch("vardrrunner.commands.heartbeat.send_heartbeat", side_effect=typer.Abort()):
            assert session.handle("heartbeat") is True
        assert "Aborted." in _output(recording_console)

    def test_ctrl_c_during_command_keeps_session(self, session, recording_console):
        with patch("vardrrunner.commands.heartbeat.send_heartbeat", side_effect=KeyboardInterrupt):
            assert session.handle("heartbeat") is True
        assert "Interrupted." in _output(recording_console)

    def test_ordinary_failure_is_not_called_an_interrupt(self, session, recording_console):
        with patch("vardrrunner.commands.heartbeat.send_heartbeat", side_effect=typer.Exit(1)):
            session.handle("heartbeat")
        assert "Interrupted." not in _output(recording_console)

    def test_system_exit_keeps_session(self, session):
        with patch("vardrrunner.commands.heartbeat.send_heartbeat", side_effect=SystemExit(3)):
            assert session.handle("heartbeat") is True

    def test_unexpected_error_is_redacted(self, session, recording_console):
        secret = "vmap_supersecretkey1234567890"
        with patch(
            "vardrrunner.commands.heartbeat.send_heartbeat",
            side_effect=RuntimeError(f"boom api_key={secret}"),
        ):
            assert session.handle("heartbeat") is True
        out = _output(recording_console)
        assert "Error:" in out
        assert secret not in out

    def test_help_lists_console_commands_and_app_commands(self, session, recording_console):
        session.handle("help")
        out = _output(recording_console)
        assert "Console commands" in out
        assert "use <engagement-id>" in out

    def test_banner_command_reprints_banner(self, session, recording_console):
        session.handle("banner")
        assert f"VardrRunner {__version__}" in _output(recording_console)


class TestUpdateInsideConsole:
    def test_newer_install_closes_the_console(self, session, recording_console):
        with (
            patch("vardrrunner.commands.updates.upgrade"),
            patch("vardrrunner.shell.updates.installed_version", return_value="99.0.0"),
        ):
            assert session.handle("update") is False
        out = _output(recording_console)
        assert "VardrRunner 99.0.0 is installed" in out
        assert "run `vardrrunner` to reopen it" in out

    def test_newer_install_ends_the_loop(self, recording_console):
        lines = iter(["update", "heartbeat"])
        with (
            patch("vardrrunner.shell._reader", return_value=(lambda _p: next(lines), False)),
            patch("vardrrunner.commands.updates.upgrade"),
            patch("vardrrunner.shell.updates.installed_version", return_value="99.0.0"),
            patch("vardrrunner.commands.heartbeat.send_heartbeat") as send,
        ):
            shell.run(app)
        send.assert_not_called()
        assert shell.is_running() is False

    @pytest.mark.parametrize("installed", [__version__, None])
    def test_unchanged_or_unknown_install_stays_open(self, session, recording_console, installed):
        with (
            patch("vardrrunner.commands.updates.upgrade"),
            patch("vardrrunner.shell.updates.installed_version", return_value=installed),
        ):
            assert session.handle("update") is True
        assert "is installed" not in _output(recording_console)

    def test_update_check_does_not_probe_installed_version(self, session):
        with (
            patch("vardrrunner.commands.updates.check"),
            patch("vardrrunner.shell.updates.installed_version") as installed,
        ):
            session.handle("update check")
        installed.assert_not_called()


# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #


class TestBanner:
    def _render(self, recorder: Console, **kwargs) -> str:
        recorder.print(shell.banner(**kwargs))
        return _output(recorder)

    def test_shows_product_author_and_website(self, recording_console):
        with patch("vardrrunner.shell._author", return_value="Jorge Aquino"):
            out = self._render(recording_console, choose=_first)
        assert f"VardrRunner {__version__}" in out
        assert "A product of VardrSec" in out
        assert "https://www.vardrsec.com" in out
        assert "Author: Jorge Aquino" in out

    def test_counts_come_from_the_code(self, recording_console):
        from vardrrunner import handlers, pipelines, runner

        out = self._render(recording_console, choose=_first)
        assert (
            f"{len(runner.ALLOWED_TOOLS)} tools · {len(pipelines.PIPELINES)} pipelines · "
            f"{len(handlers.REGISTRY)} job types"
        ) in out

    def test_shows_vardrmap_host_never_the_key(self, recording_console, monkeypatch):
        monkeypatch.setenv("VARDRMAP_URL", "https://user:pw@api.example.com/v1")
        monkeypatch.setenv("VARDRMAP_API_KEY", "vmap_supersecret")
        out = self._render(recording_console, choose=_first)
        assert "VardrMap: api.example.com" in out
        assert "vmap_supersecret" not in out
        assert "pw" not in out.split("VardrMap:")[1].splitlines()[0]

    def test_logged_out_hint(self, recording_console, monkeypatch):
        monkeypatch.delenv("VARDRMAP_URL", raising=False)
        with patch("vardrrunner.shell.config.load", return_value={}):
            out = self._render(recording_console, choose=_first)
        assert "Not set up. Run `init`." in out

    def test_cached_update_notice(self, recording_console):
        newer = updates.UpdateStatus(__version__, "99.0.0", True, CHECKED_AT, True)
        with patch("vardrrunner.shell.updates.cached", return_value=newer):
            out = self._render(recording_console, choose=_first)
        assert f"Update available: {__version__} → 99.0.0" in out

    def test_never_runs_a_release_check(self, recording_console):
        with patch("vardrrunner.shell.updates.check") as check:
            self._render(recording_console, choose=_first)
        check.assert_not_called()

    def test_shield_beside_text_when_wide(self, recording_console):
        out = self._render(recording_console, choose=_first)
        first_line = next(line for line in out.splitlines() if line.strip())
        assert first_line.lstrip().startswith(".::")
        assert "VardrRunner" in first_line

    def test_narrow_terminal_drops_shield(self, monkeypatch):
        narrow = Console(record=True, width=70, color_system=None)
        monkeypatch.setattr(shell, "console", narrow)
        out = self._render(narrow, choose=_first)
        assert ".::::" not in out
        assert f"VardrRunner {__version__}" in out

    def test_sourced_quote_is_credited_plainly(self, recording_console):
        quote = next(q for q in shell.QUOTES if q.sourced and len(q.text) < 80)
        out = self._render(
            recording_console, choose=lambda seq: quote if seq is shell.QUOTES else seq[0]
        )
        assert quote.text in out
        assert f"— {quote.author}" in out
        assert "attributed to" not in out

    def test_unsourced_quote_says_attributed(self, recording_console):
        quote = next(q for q in shell.QUOTES if not q.sourced)
        out = self._render(
            recording_console, choose=lambda seq: quote if seq is shell.QUOTES else seq[0]
        )
        assert f"— attributed to {quote.author}" in out

    def test_shows_a_tip_and_how_to_leave(self, recording_console):
        out = self._render(recording_console, choose=_first)
        assert f"Tip: {shell.TIPS[0]}" in out
        assert "Type `help` for commands, `exit` to leave." in out

    def test_shield_is_ascii(self):
        # Legacy code pages can draw it, so it needs no fallback.
        assert all(line.isascii() for line in shell.SHIELD)


class TestQuotes:
    def test_every_quote_has_text_and_author(self):
        for quote in shell.QUOTES:
            assert quote.text.strip()
            assert quote.author.strip()

    def test_no_duplicates(self):
        texts = [quote.text for quote in shell.QUOTES]
        assert len(texts) == len(set(texts))

    def test_about_five_per_general(self):
        authors = {quote.author for quote in shell.QUOTES}
        assert authors == {
            "Napoleon Bonaparte",
            "George S. Patton",
            "Erwin Rommel",
            "Heinz Guderian",
        }
        for author in authors:
            assert sum(quote.author == author for quote in shell.QUOTES) == 5


class TestAuthor:
    def test_reads_package_metadata(self):
        with patch("vardrrunner.shell.metadata.metadata") as read:
            read.return_value.get_all.return_value = ["A. Person"]
            assert shell._author() == "A. Person"

    def test_no_author_field_omits_author(self):
        with patch("vardrrunner.shell.metadata.metadata") as read:
            read.return_value.get_all.return_value = None
            assert shell._author() is None

    def test_missing_package_omits_author(self):
        from importlib import metadata

        with patch(
            "vardrrunner.shell.metadata.metadata",
            side_effect=metadata.PackageNotFoundError("vardrrunner"),
        ):
            assert shell._author() is None


# --------------------------------------------------------------------------- #
# Completion and the read loop
# --------------------------------------------------------------------------- #


class TestCompletion:
    def test_tree_has_commands_subcommands_and_long_options(self):
        tree = shell.completion_tree(typer.main.get_command(app))
        assert "heartbeat" in tree
        assert set(tree["jobs"]) >= {"list", "run"}
        assert "--engagement" in tree["import"]["nuclei"]
        assert "-e" not in tree["import"]["nuclei"]

    def test_tree_omits_hidden_and_blocked_commands(self):
        tree = shell.completion_tree(typer.main.get_command(app))
        assert "programs" not in tree
        assert "mcp" not in tree

    def test_reader_uses_prompt_toolkit_with_memory_history(self, session):
        from prompt_toolkit.history import InMemoryHistory

        with patch("prompt_toolkit.PromptSession") as prompt_session:
            read, completes = shell._reader(session)
        assert completes is True
        assert isinstance(prompt_session.call_args.kwargs["history"], InMemoryHistory)
        assert read is prompt_session.return_value.prompt

    def test_reader_falls_back_to_input(self, session, monkeypatch):
        import builtins
        import sys

        monkeypatch.setitem(sys.modules, "prompt_toolkit", None)
        read, completes = shell._reader(session)
        assert read is builtins.input
        assert completes is False


class TestRealPromptSession:
    def test_prompt_toolkit_session_reads_and_runs_lines(self):
        """Drive `run` through a real PromptSession and completer, not a stub reader."""
        from prompt_toolkit.application import create_app_session
        from prompt_toolkit.input import create_pipe_input
        from prompt_toolkit.output import DummyOutput

        with (
            create_pipe_input() as pipe,
            create_app_session(input=pipe, output=DummyOutput()),
            patch("vardrrunner.commands.heartbeat.send_heartbeat") as send,
        ):
            pipe.send_text("heartbeat\r")
            pipe.send_text(f"use {ENGAGEMENT}\r")
            pipe.send_text("exit\r")
            shell.run(app)
        send.assert_called_once()
        assert shell.is_running() is False


class TestRun:
    def _run(self, lines, completes=False):
        feed = iter(lines)

        def read(_prompt):
            item = next(feed)
            if isinstance(item, BaseException) or (
                isinstance(item, type) and issubclass(item, BaseException)
            ):
                raise item
            return item

        with patch("vardrrunner.shell._reader", return_value=(read, completes)):
            shell.run(app)

    def test_exit_ends_loop_and_clears_running(self):
        seen = []
        with patch("vardrrunner.commands.heartbeat.send_heartbeat") as send:
            send.side_effect = lambda *a, **k: seen.append(shell.is_running())
            self._run(["heartbeat", "exit"])
        assert seen == [True]
        assert shell.is_running() is False

    def test_ctrl_d_ends_loop(self):
        self._run([EOFError])
        assert shell.is_running() is False

    def test_ctrl_c_at_prompt_continues(self):
        with patch("vardrrunner.commands.heartbeat.send_heartbeat") as send:
            self._run([KeyboardInterrupt, "heartbeat", "quit"])
        send.assert_called_once()

    def test_suggests_extra_without_completion(self, recording_console):
        self._run(["exit"], completes=False)
        assert "vardrrunner[shell]" in _output(recording_console)

    def test_no_extra_hint_with_completion(self, recording_console):
        self._run(["exit"], completes=True)
        assert "vardrrunner[shell]" not in _output(recording_console)

    def test_running_flag_resets_after_error(self):
        with pytest.raises(RuntimeError):
            self._run([RuntimeError("reader broke")])
        assert shell.is_running() is False


def test_bare_invocation_inside_console_does_not_nest(session, monkeypatch):
    """`--` alone reaches the callback with no subcommand; it must not open a second console."""
    monkeypatch.setattr(shell, "_running", True)
    with (
        patch("vardrrunner.cli._interactive", return_value=True),
        patch("vardrrunner.cli.shell.run") as run,
    ):
        assert session.handle("--") is True
    run.assert_not_called()
