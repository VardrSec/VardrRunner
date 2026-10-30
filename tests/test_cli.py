"""Tests for the CLI entry point — ensures every command route is wired correctly.

Uses typer.testing.CliRunner to invoke commands with mocked underlying functions.
This covers cli.py which is otherwise 0% — the logic lives in the command modules
(tested elsewhere); here we only verify the wiring.
"""

import re
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vardrrunner import configs
from vardrrunner.cli import app
from vardrrunner.commands import run as run_cmd

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def invoke(*args):
    return runner.invoke(app, list(args))


def plain(output: str) -> str:
    """Help text without ANSI escapes. Typer forces color on GitHub Actions, which splits
    option names and borders with escape codes."""
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\]8;[^\x1b]*\x1b\\\\", "", output)


# ---------------------------------------------------------------------------
# Top-level commands
# ---------------------------------------------------------------------------


class TestStatusCommand:
    def test_delegates_to_run_status(self):
        with patch("vardrrunner.commands.status.run_status") as mock:
            invoke("status")
        mock.assert_called_once()


class TestBareInvocation:
    def test_without_a_terminal_prints_help_and_exits_2(self):
        # CliRunner's streams are not terminals, which is what a script or pipe sees.
        with patch("vardrrunner.cli.shell.run") as run:
            result = invoke()
        assert result.exit_code == 2
        assert "Usage" in result.stdout
        assert "heartbeat" in result.stdout
        run.assert_not_called()

    def test_in_a_terminal_opens_the_console(self):
        with (
            patch("vardrrunner.cli._interactive", return_value=True),
            patch("vardrrunner.cli.shell.run") as run,
        ):
            result = invoke()
        assert result.exit_code == 0
        run.assert_called_once_with(app)

    @pytest.mark.parametrize(("stdin_tty", "stdout_tty"), [(False, True), (True, False)])
    def test_interactive_needs_both_streams_to_be_terminals(self, stdin_tty, stdout_tty):
        from vardrrunner import cli

        with (
            patch("vardrrunner.cli.sys.stdin") as stdin,
            patch("vardrrunner.cli.sys.stdout") as stdout,
        ):
            stdin.isatty.return_value = stdin_tty
            stdout.isatty.return_value = stdout_tty
            assert cli._interactive() is False
            stdin.isatty.return_value = stdout.isatty.return_value = True
            assert cli._interactive() is True

    def test_input_from_a_pipe_does_not_open_the_console(self):
        with (
            patch("vardrrunner.cli._interactive", return_value=False),
            patch("vardrrunner.cli.shell.run") as run,
        ):
            result = invoke()
        assert result.exit_code == 2
        run.assert_not_called()

    def test_a_subcommand_never_opens_the_console(self):
        with (
            patch("vardrrunner.cli._interactive", return_value=True),
            patch("vardrrunner.cli.shell.run") as run,
            patch("vardrrunner.cli.heartbeat_cmd.send_heartbeat") as send,
        ):
            result = invoke("heartbeat")
        assert result.exit_code == 0
        send.assert_called_once_with(quiet=False)
        run.assert_not_called()

    def test_inside_the_console_does_not_nest(self):
        with (
            patch("vardrrunner.cli._interactive", return_value=True),
            patch("vardrrunner.cli.shell.is_running", return_value=True),
            patch("vardrrunner.cli.shell.run") as run,
        ):
            result = invoke()
        assert result.exit_code == 2
        run.assert_not_called()


class TestVersionOption:
    @pytest.mark.parametrize("flag", ["--version", "-V"])
    def test_prints_version_offline_and_exits(self, flag):
        from vardrrunner import __version__

        with (
            patch("vardrrunner.updates.api.fetch_release_metadata") as fetch,
            patch("vardrrunner.cli.process_runner.cleanup_sensitive_temp_dirs") as cleanup,
        ):
            result = invoke(flag)
        assert result.exit_code == 0
        assert result.stdout.strip() == f"vardrrunner {__version__}"
        fetch.assert_not_called()  # ADR 0012: only an explicit check contacts the registry
        cleanup.assert_not_called()

    def test_names_a_newer_release_already_cached(self):
        from vardrrunner import updates

        newer = updates.UpdateStatus("0.1.0", "9.9.9", True, "2026-10-24T00:00:00+00:00", True)
        with patch("vardrrunner.cli.updates.cached", return_value=newer):
            result = invoke("--version")
        assert result.exit_code == 0
        assert "Update available: 0.1.0 → 9.9.9" in result.stdout
        assert "vardrrunner update" in result.stdout

    def test_up_to_date_cache_adds_nothing(self):
        from vardrrunner import __version__, updates

        current = updates.UpdateStatus(
            __version__, __version__, False, "2026-10-24T00:00:00+00:00", True
        )
        with patch("vardrrunner.cli.updates.cached", return_value=current):
            result = invoke("--version")
        assert "Update available" not in result.stdout


class TestInitCommand:
    def test_all_options_are_forwarded(self):
        with patch("vardrrunner.commands.setup.initialize") as mock:
            invoke(
                "init",
                "--url",
                "https://api.example.com",
                "--key",
                "vmap_secret",
                "--name",
                "runner-a",
                "--production",
                "--allow-plaintext-credentials",
                "--non-interactive",
            )
        mock.assert_called_once_with(
            api_url="https://api.example.com",
            api_key="vmap_secret",
            name="runner-a",
            production=True,
            allow_plaintext=True,
            non_interactive=True,
            install_tools=None,
        )

    @pytest.mark.parametrize(
        "flags, expected",
        [((), None), (("--install-tools",), True), (("--no-install-tools",), False)],
    )
    def test_init_install_tools_flag(self, flags, expected):
        with patch("vardrrunner.commands.setup.initialize") as mock:
            invoke("init", "--non-interactive", *flags)
        _, kwargs = mock.call_args
        assert kwargs["install_tools"] is expected


class TestDoctorCommand:
    def test_delegates_to_run_doctor(self):
        with patch("vardrrunner.commands.doctor.run_doctor") as mock:
            mock.side_effect = SystemExit(0)
            invoke("doctor")
        mock.assert_called_once()

    def test_json_flag_passed(self):
        with patch("vardrrunner.commands.doctor.run_doctor") as mock:
            mock.side_effect = SystemExit(0)
            invoke("doctor", "--json")
        mock.assert_called_once_with(as_json=True, production=False, platform=False, offline=False)

    def test_production_flag_passed(self):
        with patch("vardrrunner.commands.doctor.run_doctor") as mock:
            mock.side_effect = SystemExit(0)
            invoke("doctor", "--production")
        mock.assert_called_once_with(as_json=False, production=True, platform=False, offline=False)

    def test_platform_and_offline_flags_passed(self):
        with patch("vardrrunner.commands.doctor.run_doctor") as mock:
            mock.side_effect = SystemExit(0)
            invoke("doctor", "--platform", "--offline", "--json")
        mock.assert_called_once_with(as_json=True, production=False, platform=True, offline=True)


class TestHeartbeatCommand:
    def test_delegates_to_send_heartbeat(self):
        with patch("vardrrunner.commands.heartbeat.send_heartbeat") as mock:
            invoke("heartbeat")
        mock.assert_called_once_with(quiet=False)


class TestLogoutCommand:
    def test_delegates_to_logout(self):
        with patch("vardrrunner.commands.auth.logout") as mock:
            invoke("logout")
        mock.assert_called_once()


class TestWhoamiCommand:
    def test_delegates_to_whoami(self):
        with patch("vardrrunner.commands.auth.whoami") as mock:
            invoke("whoami")
        mock.assert_called_once()


class TestIdentityCommands:
    def test_show(self):
        with patch("vardrrunner.commands.identity.show") as mock:
            invoke("identity", "show")
        mock.assert_called_once()

    def test_set_name(self):
        with patch("vardrrunner.commands.identity.set_name") as mock:
            invoke("identity", "set-name", "runner-a")
        mock.assert_called_once_with("runner-a")


class TestToolsCommands:
    def test_install_named_tools(self):
        with patch("vardrrunner.commands.tools.install") as mock:
            invoke("tools", "install", "httpx", "nuclei")
        mock.assert_called_once_with(["httpx", "nuclei"], all_tools=False, force=False)

    def test_install_all_force(self):
        with patch("vardrrunner.commands.tools.install") as mock:
            invoke("tools", "install", "--all", "--force")
        mock.assert_called_once_with([], all_tools=True, force=True)

    def test_list_verify(self):
        with (
            patch("vardrrunner.commands.tools.list_tools") as list_mock,
            patch("vardrrunner.commands.tools.verify") as verify_mock,
        ):
            invoke("tools", "list")
            invoke("tools", "verify")
        list_mock.assert_called_once_with()
        verify_mock.assert_called_once_with()

    def test_remove(self):
        with patch("vardrrunner.commands.tools.remove") as mock:
            invoke("tools", "remove", "httpx")
        mock.assert_called_once_with("httpx")

    def test_purge_confirms_by_default(self):
        with patch("vardrrunner.commands.tools.purge") as mock:
            invoke("tools", "purge")
        mock.assert_called_once_with(yes=False)

    @pytest.mark.parametrize("flag", ["--yes", "-y"])
    def test_purge_yes(self, flag):
        with patch("vardrrunner.commands.tools.purge") as mock:
            invoke("tools", "purge", flag)
        mock.assert_called_once_with(yes=True)


class TestUpdateCommands:
    def test_check_options(self):
        with (
            patch("vardrrunner.commands.updates.check") as mock,
            patch("vardrrunner.commands.updates.upgrade") as upgrade,
        ):
            result = invoke("update", "check", "--json")
        assert result.exit_code == 0
        mock.assert_called_once_with(as_json=True)
        upgrade.assert_not_called()  # the group callback must never install on `update check`

    def test_bare_update_installs(self):
        with patch("vardrrunner.commands.updates.upgrade") as upgrade:
            result = invoke("update")
        assert result.exit_code == 0
        upgrade.assert_called_once_with()


class TestAuditCommands:
    def test_list_delegates(self):
        with patch("vardrrunner.commands.audit.list_runs") as mock:
            invoke("audit", "list", "--limit", "12", "--json")
        mock.assert_called_once_with(since=None, limit=12, as_json=True)

    def test_show_delegates(self):
        with patch("vardrrunner.commands.audit.show_run") as mock:
            invoke("audit", "show", "run-1")
        mock.assert_called_once_with("run-1")

    def test_export_delegates(self, tmp_path):
        output = tmp_path / "audit.json"
        with patch("vardrrunner.commands.audit.export_runs") as mock:
            invoke("audit", "export", "--output", str(output), "--limit", "50")
        mock.assert_called_once_with(output=output, since=None, limit=50)


# ---------------------------------------------------------------------------
# Engagement / scope
# ---------------------------------------------------------------------------


class TestEngagementsCommand:
    def test_engagements(self):
        with patch("vardrrunner.commands.engagements.list_engagements") as mock:
            invoke("engagements")
        mock.assert_called_once()


class TestScopeCommand:
    def test_delegates_to_show_scope(self):
        with patch("vardrrunner.commands.engagements.show_scope") as mock:
            invoke("scope", "prog-1")
        mock.assert_called_once_with("prog-1")


# ---------------------------------------------------------------------------
# Import sub-app
# ---------------------------------------------------------------------------


class TestImportCommands:
    def test_import_nuclei(self, tmp_path):
        f = tmp_path / "nuclei.jsonl"
        f.write_text("{}\n")
        with patch("vardrrunner.commands.imports.import_file") as mock:
            invoke("import", "nuclei", "--engagement", "p1", "--file", str(f))
        mock.assert_called_once_with("nuclei", "p1", Path(str(f)))

    def test_import_httpx(self, tmp_path):
        f = tmp_path / "httpx.jsonl"
        f.write_text("{}\n")
        with patch("vardrrunner.commands.imports.import_file") as mock:
            invoke("import", "httpx", "--engagement", "p1", "--file", str(f))
        mock.assert_called_once_with("httpx", "p1", Path(str(f)))

    def test_import_ffuf_is_not_a_command(self, tmp_path):
        """`ffuf` left SUPPORTED_TOOLS in v0.21.1 but stayed registered in cli.py
        until v0.28.0, so it showed in --help and always errored. The previous
        version of this test mocked import_file and therefore never noticed."""
        f = tmp_path / "ffuf.json"
        f.write_text("{}\n")
        with patch("vardrrunner.commands.imports.import_file") as mock:
            result = invoke("import", "ffuf", "--engagement", "p1", "--file", str(f))
        assert result.exit_code != 0
        mock.assert_not_called()

    def test_import_help_lists_only_supported_tools(self):
        result = invoke("import", "--help")
        assert "nuclei" in result.output
        assert "httpx" in result.output
        assert "ffuf" not in result.output


# ---------------------------------------------------------------------------
# Jobs sub-app
# ---------------------------------------------------------------------------


class TestJobsCommands:
    def test_jobs_list(self):
        with patch("vardrrunner.commands.jobs.list_jobs") as mock:
            invoke("jobs", "list")
        mock.assert_called_once()

    def test_jobs_run(self):
        with patch("vardrrunner.commands.jobs.run_jobs") as mock:
            invoke("jobs", "run")
        mock.assert_called_once()

    def test_jobs_run_yes_flag(self):
        with patch("vardrrunner.commands.jobs.run_jobs") as mock:
            invoke("jobs", "run", "--yes")
        mock.assert_called_once_with(yes=True)


# ---------------------------------------------------------------------------
# Run sub-app
# ---------------------------------------------------------------------------


class TestRunCommands:
    def test_run_httpx(self):
        with patch("vardrrunner.commands.run.run_httpx") as mock:
            invoke("run", "httpx", "--engagement", "p1", "--target", "https://a.com", "--yes")
        mock.assert_called_once()

    def test_run_subfinder(self):
        with patch("vardrrunner.commands.run.run_subfinder") as mock:
            invoke("run", "subfinder", "--engagement", "p1", "--yes")
        mock.assert_called_once()

    def test_run_nuclei(self):
        with patch("vardrrunner.commands.run.run_nuclei") as mock:
            invoke("run", "nuclei", "--engagement", "p1", "--target", "https://a.com", "--yes")
        mock.assert_called_once()

    def test_run_nmap(self):
        with patch("vardrrunner.commands.run.run_nmap") as mock:
            invoke("run", "nmap", "--engagement", "p1", "--target", "10.0.0.1", "--yes")
        mock.assert_called_once()

    def test_run_dnsx(self):
        with patch("vardrrunner.commands.run.run_dnsx") as mock:
            invoke("run", "dnsx", "--engagement", "p1", "--target", "a.example.com", "--yes")
        mock.assert_called_once()

    def test_run_katana_options(self):
        with patch("vardrrunner.commands.run.run_katana") as mock:
            invoke(
                "run",
                "katana",
                "--engagement",
                "p1",
                "--from-recon",
                "--limit",
                "20",
                "--depth",
                "5",
                "--js-crawl",
                "--yes",
            )
        mock.assert_called_once_with(
            engagement_id="p1",
            scope=False,
            from_recon=True,
            target=None,
            targets_file=None,
            limit=20,
            depth=5,
            js_crawl=True,
            yes=True,
            max_targets=run_cmd.MAX_TARGETS_DEFAULT,
        )

    def test_run_ffuf_defaults(self):
        with patch("vardrrunner.commands.run.run_ffuf") as mock:
            invoke("run", "ffuf", "--engagement", "p1", "--scope")
        mock.assert_called_once_with(
            engagement_id="p1",
            scope=True,
            from_recon=False,
            target=None,
            targets_file=None,
            limit=100,
            wordlist="common",
            extensions=None,
            match_codes=None,
            rate=configs.FFUF_DEFAULT_RATE,
            yes=False,
            max_targets=run_cmd.MAX_TARGETS_DEFAULT,
        )

    def test_run_ffuf_options(self):
        with patch("vardrrunner.commands.run.run_ffuf") as mock:
            invoke(
                "run",
                "ffuf",
                "-e",
                "p1",
                "--from-recon",
                "--limit",
                "20",
                "--wordlist",
                "api-paths",
                "--extensions",
                ".php,.bak",
                "--match-codes",
                "200,403",
                "--rate",
                "15",
                "-y",
            )
        mock.assert_called_once_with(
            engagement_id="p1",
            scope=False,
            from_recon=True,
            target=None,
            targets_file=None,
            limit=20,
            wordlist="api-paths",
            extensions=".php,.bak",
            match_codes="200,403",
            rate=15,
            yes=True,
            max_targets=run_cmd.MAX_TARGETS_DEFAULT,
        )

    @pytest.mark.parametrize("rate", ["0", "-5", str(configs.FFUF_MAX_RATE + 1)])
    def test_run_ffuf_rejects_an_out_of_range_rate(self, rate):
        """The rate cap is a safety control, so its bounds are enforced at the CLI."""
        with patch("vardrrunner.commands.run.run_ffuf") as mock:
            result = invoke("run", "ffuf", "-e", "p1", "--scope", "--rate", rate)
        assert result.exit_code != 0
        mock.assert_not_called()

    def test_run_dalfox_defaults(self):
        with patch("vardrrunner.commands.run.run_dalfox") as mock:
            invoke("run", "dalfox", "--engagement", "p1", "--from-recon")
        mock.assert_called_once_with(
            engagement_id="p1",
            scope=False,
            from_recon=True,
            target=None,
            targets_file=None,
            limit=100,
            worker=10,
            delay=0,
            mining=True,
            yes=False,
            max_targets=run_cmd.MAX_TARGETS_DEFAULT,
        )

    def test_run_dalfox_options(self):
        with patch("vardrrunner.commands.run.run_dalfox") as mock:
            invoke(
                "run",
                "dalfox",
                "-e",
                "p1",
                "--target",
                "https://a.test/?q=1",
                "--worker",
                "5",
                "--delay",
                "250",
                "--no-mining",
                "-y",
            )
        mock.assert_called_once_with(
            engagement_id="p1",
            scope=False,
            from_recon=False,
            target="https://a.test/?q=1",
            targets_file=None,
            limit=100,
            worker=5,
            delay=250,
            mining=False,
            yes=True,
            max_targets=run_cmd.MAX_TARGETS_DEFAULT,
        )

    @pytest.mark.parametrize(
        "flag,value",
        [("--worker", "0"), ("--worker", "101"), ("--delay", "-1"), ("--delay", "10001")],
    )
    def test_run_dalfox_rejects_out_of_range_load_controls(self, flag, value):
        """These bound the traffic a job puts on a client's host."""
        with patch("vardrrunner.commands.run.run_dalfox") as mock:
            result = invoke("run", "dalfox", "-e", "p1", "--scope", flag, value)
        assert result.exit_code != 0
        mock.assert_not_called()

    def test_run_gau_defaults(self):
        with patch("vardrrunner.commands.run.run_gau") as mock:
            invoke("run", "gau", "--engagement", "p1")
        mock.assert_called_once_with(
            engagement_id="p1",
            subs=True,
            providers=None,
            yes=False,
            max_targets=run_cmd.MAX_TARGETS_DEFAULT,
        )

    def test_run_gau_options(self):
        with patch("vardrrunner.commands.run.run_gau") as mock:
            invoke(
                "run",
                "gau",
                "-e",
                "p1",
                "--no-subs",
                "--providers",
                "otx,wayback",
                "--max-targets",
                "3",
                "-y",
            )
        mock.assert_called_once_with(
            engagement_id="p1",
            subs=False,
            providers="otx,wayback",
            yes=True,
            max_targets=3,
        )

    def test_run_naabu(self):
        with patch("vardrrunner.commands.run.run_naabu") as mock:
            invoke("run", "naabu", "--engagement", "p1", "--target", "10.0.0.1", "--yes")
        mock.assert_called_once()

    # The guardrail shipped in v0.22.1 but the option reached cli.py only in
    # v0.28.0 — the tests above assert call count, not kwargs, so they passed
    # throughout. These assert the wiring itself.
    @pytest.mark.parametrize(
        "tool,target",
        [
            ("httpx", "https://a.com"),
            ("nuclei", "https://a.com"),
            ("nmap", "10.0.0.1"),
            ("dnsx", "a.example.com"),
            ("naabu", "10.0.0.1"),
            ("katana", "https://a.com"),
        ],
    )
    def test_run_max_targets_is_passed_through(self, tool, target):
        with patch(f"vardrrunner.commands.run.run_{tool}") as mock:
            invoke(
                "run", tool, "--engagement", "p1", "--target", target, "--max-targets", "7", "--yes"
            )
        _, kwargs = mock.call_args
        assert kwargs.get("max_targets") == 7

    def test_run_subfinder_max_targets_is_passed_through(self):
        with patch("vardrrunner.commands.run.run_subfinder") as mock:
            invoke("run", "subfinder", "--engagement", "p1", "--max-targets", "7", "--yes")
        _, kwargs = mock.call_args
        assert kwargs.get("max_targets") == 7

    def test_run_max_targets_defaults_to_the_shared_cap(self):
        with patch("vardrrunner.commands.run.run_httpx") as mock:
            invoke("run", "httpx", "--engagement", "p1", "--target", "https://a.com", "--yes")
        _, kwargs = mock.call_args
        assert kwargs.get("max_targets") == run_cmd.MAX_TARGETS_DEFAULT

    @pytest.mark.parametrize("tool", ["httpx", "nuclei", "nmap", "dnsx", "naabu"])
    def test_run_rejects_negative_max_targets(self, tool):
        """Rejected at parse time, so it never reaches the command module."""
        with patch(f"vardrrunner.commands.run.run_{tool}") as mock:
            result = invoke(
                "run", tool, "--engagement", "p1", "--target", "x", "--max-targets", "-1", "--yes"
            )
        assert result.exit_code != 0
        mock.assert_not_called()

    def test_pipeline_rejects_negative_max_targets_at_parse_time(self):
        with patch("vardrrunner.commands.pipeline.run_pipeline") as mock:
            result = invoke(
                "pipeline", "run", "quick", "--engagement", "p1", "--max-targets", "-1", "--yes"
            )
        assert result.exit_code != 0
        mock.assert_not_called()

    def test_run_max_targets_zero_disables_the_cap(self):
        with patch("vardrrunner.commands.run.run_httpx") as mock:
            invoke(
                "run",
                "httpx",
                "--engagement",
                "p1",
                "--target",
                "https://a.com",
                "--max-targets",
                "0",
                "--yes",
            )
        _, kwargs = mock.call_args
        assert kwargs.get("max_targets") == 0


# ---------------------------------------------------------------------------
# Pipeline sub-app
# ---------------------------------------------------------------------------


class TestPipelineCommands:
    def test_pipeline_list(self):
        with patch("vardrrunner.commands.pipeline.list_pipelines") as mock:
            invoke("pipeline", "list")
        mock.assert_called_once()

    def test_pipeline_run(self):
        with patch("vardrrunner.commands.pipeline.run_pipeline") as mock:
            invoke("pipeline", "run", "recon", "--engagement", "p1", "--yes")
        mock.assert_called_once()

    def test_pipeline_run_with_severity(self):
        with patch("vardrrunner.commands.pipeline.run_pipeline") as mock:
            invoke("pipeline", "run", "recon", "--engagement", "p1", "--severity", "high", "--yes")
        _, kwargs = mock.call_args
        assert kwargs.get("severity") == "high"

    def test_pipeline_run_dry_run_flag(self):
        with patch("vardrrunner.commands.pipeline.run_pipeline") as mock:
            invoke("pipeline", "run", "quick", "--engagement", "p1", "--dry-run", "--yes")
        _, kwargs = mock.call_args
        assert kwargs.get("dry_run") is True

    def test_pipeline_run_json_flag(self):
        with patch("vardrrunner.commands.pipeline.run_pipeline") as mock:
            invoke("pipeline", "run", "quick", "--engagement", "p1", "--json", "--yes")
        _, kwargs = mock.call_args
        assert kwargs.get("as_json") is True

    def test_pipeline_run_max_targets_flag(self):
        with patch("vardrrunner.commands.pipeline.run_pipeline") as mock:
            invoke("pipeline", "run", "quick", "--engagement", "p1", "--max-targets", "7", "--yes")
        _, kwargs = mock.call_args
        assert kwargs.get("max_targets") == 7

    def test_pipeline_run_max_targets_defaults_to_the_shared_cap(self):
        with patch("vardrrunner.commands.pipeline.run_pipeline") as mock:
            invoke("pipeline", "run", "quick", "--engagement", "p1", "--yes")
        _, kwargs = mock.call_args
        assert kwargs.get("max_targets") == run_cmd.MAX_TARGETS_DEFAULT


class TestOutputStreamHardening:
    """Windows piped/redirected output uses a legacy code page; printing must not crash."""

    class _Stream:
        def __init__(self, encoding, reconfigurable=True):
            self.encoding = encoding
            self.calls = []
            if reconfigurable:
                self.reconfigure = lambda **kw: self.calls.append(kw)

    @pytest.mark.parametrize(
        "encoding, expected",
        [("cp1252", [{"errors": "replace"}]), ("utf-8", []), ("not-a-codec", []), (None, [])],
    )
    def test_replaces_only_when_symbols_cannot_be_encoded(self, monkeypatch, encoding, expected):
        from vardrrunner import cli

        out, err = self._Stream(encoding), self._Stream(encoding)
        monkeypatch.setattr(cli.sys, "stdout", out)
        monkeypatch.setattr(cli.sys, "stderr", err)
        cli._harden_output_streams()
        assert out.calls == expected and err.calls == expected

    def test_streams_without_reconfigure_are_left_alone(self, monkeypatch):
        from vardrrunner import cli

        monkeypatch.setattr(cli.sys, "stdout", self._Stream("cp1252", reconfigurable=False))
        monkeypatch.setattr(cli.sys, "stderr", self._Stream("cp1252", reconfigurable=False))
        cli._harden_output_streams()  # must not raise


class TestMcpCommand:
    """`vardrrunner mcp` imports mcp_server lazily, so these tests control what that
    import finds. `from vardrrunner import mcp_server` looks at the *attribute* on the
    package before sys.modules, so once any earlier test has imported the real module
    the attribute shadows a sys.modules patch and the result depends on test order.
    The fixture removes the attribute for the test and restores whatever was there."""

    @pytest.fixture(autouse=True)
    def _isolate_mcp_server_import(self, monkeypatch):
        import sys

        import vardrrunner

        monkeypatch.delattr(vardrrunner, "mcp_server", raising=False)
        monkeypatch.delitem(sys.modules, "vardrrunner.mcp_server", raising=False)

    def test_mcp_runs_the_server_when_installed(self, monkeypatch):
        import sys
        from unittest.mock import MagicMock

        fake_mod = MagicMock()
        monkeypatch.setitem(sys.modules, "mcp.server", MagicMock())
        monkeypatch.setitem(sys.modules, "vardrrunner.mcp_server", fake_mod)
        result = invoke("mcp")
        fake_mod.run.assert_called_once_with()
        assert result.exit_code == 0

    def test_mcp_without_the_extra_prints_install_hint(self, monkeypatch):
        import sys

        # sys.modules[name] = None makes importing that name raise ImportError. Block only
        # the SDK and leave the real mcp_server importable: that module imports cleanly
        # without the extra, which is how a missing extra used to escape as a traceback.
        monkeypatch.setitem(sys.modules, "mcp.server", None)
        result = invoke("mcp")
        assert result.exit_code == 1
        assert "vardrrunner[mcp]" in result.stdout
        assert result.exception is None or isinstance(result.exception, SystemExit)


class TestTestCasesCommands:
    """Wiring for `test-cases draft|save`. Asserts the arguments that reach the command, and the
    out-of-range values for options that bound what is requested or confirm a review."""

    def test_draft_defaults(self):
        with patch("vardrrunner.commands.test_cases.draft_cases") as mock:
            result = invoke(
                "test-cases", "draft", "eng", "--output", "out.json", "--endpoint", "ep1"
            )
        assert result.exit_code == 0
        mock.assert_called_once_with("eng", None, ["ep1"], Path("out.json"), "", 0, 50)

    def test_draft_options_reach_the_command(self):
        with patch("vardrrunner.commands.test_cases.draft_cases") as mock:
            invoke(
                "test-cases",
                "draft",
                "eng",
                "--output",
                "out.json",
                "--openapi",
                "api.json",
                "--base-url",
                "https://api.example.test",
                "--offset",
                "5",
                "--limit",
                "20",
            )
        mock.assert_called_once_with(
            "eng", Path("api.json"), [], Path("out.json"), "https://api.example.test", 5, 20
        )

    def test_draft_endpoint_is_repeatable(self):
        with patch("vardrrunner.commands.test_cases.draft_cases") as mock:
            invoke(
                "test-cases",
                "draft",
                "eng",
                "--output",
                "o.json",
                "--endpoint",
                "a",
                "--endpoint",
                "b",
            )
        assert mock.call_args.args[2] == ["a", "b"]

    @pytest.mark.parametrize(
        "flag, value", [("--limit", "0"), ("--limit", "101"), ("--offset", "-1")]
    )
    def test_draft_rejects_out_of_range_paging(self, flag, value):
        with patch("vardrrunner.commands.test_cases.draft_cases") as mock:
            result = invoke(
                "test-cases", "draft", "eng", "--output", "o.json", "--endpoint", "a", flag, value
            )
        assert result.exit_code == 2
        mock.assert_not_called()

    def test_draft_requires_an_output_path(self):
        with patch("vardrrunner.commands.test_cases.draft_cases") as mock:
            result = invoke("test-cases", "draft", "eng", "--endpoint", "a")
        assert result.exit_code == 2
        mock.assert_not_called()

    @pytest.mark.parametrize("flags, expected", [((), False), (("--reviewed",), True)])
    def test_save_passes_the_review_confirmation_through(self, flags, expected):
        with patch("vardrrunner.commands.test_cases.save_cases") as mock:
            invoke("test-cases", "save", "eng", "--file", "reviewed.json", *flags)
        mock.assert_called_once_with("eng", Path("reviewed.json"), expected)

    def test_save_requires_a_file(self):
        with patch("vardrrunner.commands.test_cases.save_cases") as mock:
            result = invoke("test-cases", "save", "eng", "--reviewed")
        assert result.exit_code == 2
        mock.assert_not_called()


class TestRenamedAndRemovedNames:
    """v0.52.0 dropped the names left from when engagements were "programs", and flattened
    `login vardrmap` to `login`. The old forms must fail before anything runs."""

    @pytest.mark.parametrize(
        "args",
        [
            ("programs",),
            ("run", "httpx", "--program", "eng-1", "--scope"),
            ("run", "httpx", "-p", "eng-1", "--scope"),
            ("import", "nuclei", "--program", "eng-1", "-f", "out.jsonl"),
            ("update", "check", "--force"),
            ("login", "vardrmap"),
        ],
    )
    def test_old_forms_fail_and_run_nothing(self, args):
        from contextlib import ExitStack

        with ExitStack() as stack:
            blocked = [
                stack.enter_context(patch(target))
                for target in (
                    "vardrrunner.commands.engagements.list_engagements",
                    "vardrrunner.commands.run.run_httpx",
                    "vardrrunner.commands.imports.import_file",
                    "vardrrunner.commands.updates.check",
                    "vardrrunner.commands.auth.api.VardrMapClient",
                )
            ]
            result = invoke(*args)
        assert result.exit_code == 2
        for mock in blocked:
            mock.assert_not_called()

    def test_short_engagement_option_is_e(self):
        with patch("vardrrunner.commands.imports.import_file") as mock:
            result = invoke("import", "nuclei", "-e", "eng-1", "-f", "out.jsonl")
        assert result.exit_code == 0
        assert mock.call_args.args[:2] == ("nuclei", "eng-1")

    def test_login_is_a_top_level_command(self):
        result = invoke("login", "--help")
        assert result.exit_code == 0
        for flag in ("--url", "--key", "--allow-plaintext-credentials"):
            assert flag in plain(result.output)


class TestManualInvocationOnly:
    """The background modes were removed (ADR 0016, v0.51.0). Their old entry points must
    fail as unknown commands or options before anything runs."""

    @pytest.mark.parametrize(
        "args",
        [
            ("service", "install"),
            ("service", "install", "--run-jobs"),
            ("service", "uninstall"),
            ("service", "status"),
            ("daemon", "start"),
            ("daemon", "start", "--detach", "--run-jobs"),
            ("daemon", "stop"),
            ("daemon", "status"),
            ("engagement-list",),
            ("init", "--install-service"),
            ("init", "--start-service"),
            ("init", "--no-start-service"),
            ("init", "--env-file", "legacy.env"),
            ("init", "--production", "--non-interactive", "--install-service"),
        ],
    )
    def test_removed_entrypoints_are_unknown_and_start_nothing(self, args):
        from contextlib import ExitStack

        with ExitStack() as stack:
            blocked = [
                stack.enter_context(patch(target))
                for target in (
                    "subprocess.Popen",
                    "subprocess.run",
                    "vardrrunner.commands.setup.initialize",
                    "vardrrunner.commands.jobs.execute_pending_jobs",
                    "vardrrunner.recovery.reconcile",
                    "vardrrunner.commands.heartbeat.send_heartbeat",
                    "vardrrunner.commands.engagements.list_engagements",
                )
            ]
            result = invoke(*args)
        assert result.exit_code == 2
        assert "No such command" in result.output or "No such option" in result.output
        for mock in blocked:
            mock.assert_not_called()

    def test_help_lists_no_removed_commands(self):
        result = invoke("--help")
        assert result.exit_code == 0
        # A command row is a name followed by two or more spaces and its help, whatever
        # border (`│`, `|`, `┃`, none) Rich draws.
        listed = set(
            re.findall(r"^[^\w\n]*([a-z][\w-]*)\s{2,}\S", plain(result.output), re.MULTILINE)
        )
        assert {"daemon", "service", "engagement-list"}.isdisjoint(listed)
        assert "engagements" in listed

    def test_init_help_offers_no_service_options(self):
        result = invoke("init", "--help")
        assert result.exit_code == 0
        for flag in ("--install-service", "--start-service", "--env-file"):
            assert flag not in result.output


class TestCredentialsCommands:
    def test_bare_credentials_still_shows_posture(self):
        with patch("vardrrunner.commands.credentials.show_credentials") as show:
            result = invoke("credentials")
        assert result.exit_code == 0
        show.assert_called_once_with()

    @pytest.mark.parametrize(
        ("flag", "env", "keychain"),
        [("--env", "OWNER_TOKEN", None), ("--keychain", None, "OWNER_TOKEN")],
    )
    def test_approve_passes_every_option(self, flag, env, keychain):
        with patch("vardrrunner.commands.credentials.approve") as approve:
            result = invoke(
                "credentials",
                "approve",
                "-e",
                "eng-1",
                "--origin",
                "https://api.test",
                flag,
                "OWNER_TOKEN",
            )
        assert result.exit_code == 0, result.output
        approve.assert_called_once_with("eng-1", "https://api.test", env, keychain)

    def test_revoke_passes_every_option(self):
        with patch("vardrrunner.commands.credentials.revoke") as revoke:
            result = invoke(
                "credentials",
                "revoke",
                "--engagement",
                "eng-1",
                "--origin",
                "https://api.test",
                "--env",
                "OWNER_TOKEN",
            )
        assert result.exit_code == 0, result.output
        revoke.assert_called_once_with("eng-1", "https://api.test", "OWNER_TOKEN", None)

    def test_approvals_lists(self):
        with patch("vardrrunner.commands.credentials.list_approvals") as listing:
            result = invoke("credentials", "approvals")
        assert result.exit_code == 0
        listing.assert_called_once_with()

    def test_approve_requires_engagement_and_origin(self):
        result = invoke("credentials", "approve", "--env", "OWNER_TOKEN")
        assert result.exit_code == 2


class TestCredentialApprovalCommands:
    def test_approve_and_revoke_round_trip(self):
        from vardrrunner import config

        result = invoke(
            "credentials",
            "approve",
            "-e",
            "eng-1",
            "--origin",
            "https://API.test:443/x",
            "--env",
            "OWNER_TOKEN",
        )
        assert result.exit_code == 0, result.output
        assert config.credential_approvals() == [
            {
                "engagement_id": "eng-1",
                "origin": "https://api.test",
                "source": "env",
                "name": "OWNER_TOKEN",
            }
        ]
        assert "OWNER_TOKEN" in invoke("credentials", "approvals").output
        result = invoke(
            "credentials",
            "revoke",
            "-e",
            "eng-1",
            "--origin",
            "https://api.test",
            "--env",
            "OWNER_TOKEN",
        )
        assert result.exit_code == 0
        assert config.credential_approvals() == []

    @pytest.mark.parametrize("args", [(), ("--env", "A", "--keychain", "b")])
    def test_exactly_one_reference_is_required(self, args):
        result = invoke(
            "credentials", "approve", "-e", "eng-1", "--origin", "https://api.test", *args
        )
        assert result.exit_code == 2

    def test_an_invalid_approval_exits_2(self):
        result = invoke(
            "credentials", "approve", "-e", "eng-1", "--origin", "ftp://x", "--env", "A"
        )
        assert result.exit_code == 2
        assert "http(s)" in result.output

    def test_revoking_nothing_exits_1(self):
        result = invoke(
            "credentials", "revoke", "-e", "eng-1", "--origin", "https://api.test", "--env", "A"
        )
        assert result.exit_code == 1

    def test_empty_listing_explains_what_happens(self):
        assert "will fail until" in invoke("credentials", "approvals").output
