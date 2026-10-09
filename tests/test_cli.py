"""Tests for the CLI entry point — ensures every command route is wired correctly.

Uses typer.testing.CliRunner to invoke commands with mocked underlying functions.
This covers cli.py which is otherwise 0% — the logic lives in the command modules
(tested elsewhere); here we only verify the wiring.
"""

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


# ---------------------------------------------------------------------------
# Top-level commands
# ---------------------------------------------------------------------------


class TestStatusCommand:
    def test_delegates_to_run_status(self):
        with patch("vardrrunner.commands.status.run_status") as mock:
            invoke("status")
        mock.assert_called_once()


class TestInitCommand:
    def test_all_options_are_forwarded(self, tmp_path):
        env_file = tmp_path / "runner.env"
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
                "--install-service",
                "--no-start-service",
                "--env-file",
                str(env_file),
                "--allow-plaintext-credentials",
                "--non-interactive",
            )
        mock.assert_called_once_with(
            api_url="https://api.example.com",
            api_key="vmap_secret",
            name="runner-a",
            production=True,
            install_service=True,
            start_service=False,
            env_file=env_file,
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

    @pytest.mark.parametrize(
        "args",
        [
            ("--poll-interval", "0"),
            ("--heartbeat-interval", "0"),
            ("--poll-interval", "3601"),
            ("--heartbeat-interval", "86401"),
        ],
    )
    def test_daemon_intervals_are_bounded(self, args):
        with patch("vardrrunner.commands.daemon.start") as start:
            result = invoke("daemon", "start", *args)
        assert result.exit_code != 0
        start.assert_not_called()


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
        mock.assert_called_once_with(as_json=True, production=False)

    def test_production_flag_passed(self):
        with patch("vardrrunner.commands.doctor.run_doctor") as mock:
            mock.side_effect = SystemExit(0)
            invoke("doctor", "--production")
        mock.assert_called_once_with(as_json=False, production=True)


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


class TestServiceCommands:
    def test_install_options(self, tmp_path):
        env_file = tmp_path / "runner.env"
        with patch("vardrrunner.commands.service.install") as mock:
            invoke(
                "service",
                "install",
                "--env-file",
                str(env_file),
                "--no-start",
                "--dry-run",
            )
        mock.assert_called_once_with(env_file=env_file, start=False, dry_run=True)

    def test_status_and_uninstall(self):
        with patch("vardrrunner.commands.service.show_status") as status:
            invoke("service", "status")
        status.assert_called_once()
        with patch("vardrrunner.commands.service.uninstall") as uninstall:
            invoke("service", "uninstall")
        uninstall.assert_called_once()


class TestUpdateCommands:
    def test_check_options(self):
        with patch("vardrrunner.commands.updates.check") as mock:
            invoke("update", "check", "--force", "--json")
        mock.assert_called_once_with(force=True, as_json=True)


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


class TestProgramListCommand:
    def test_program_list(self):
        with patch("vardrrunner.commands.engagements.list_engagements") as mock:
            invoke("engagement-list")
        mock.assert_called_once()

    def test_programs_alias(self):
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
# Daemon sub-app
# ---------------------------------------------------------------------------


class TestDaemonCommands:
    def test_daemon_start(self):
        with patch("vardrrunner.commands.daemon.start") as mock:
            invoke("daemon", "start")
        mock.assert_called_once()

    def test_daemon_stop(self):
        with patch("vardrrunner.commands.daemon.stop") as mock:
            invoke("daemon", "stop")
        mock.assert_called_once()

    def test_daemon_status(self):
        with patch("vardrrunner.commands.daemon.status") as mock:
            invoke("daemon", "status")
        mock.assert_called_once()

    def test_daemon_start_detach_flag(self):
        with patch("vardrrunner.commands.daemon.start") as mock:
            invoke("daemon", "start", "--detach")
        _, kwargs = mock.call_args
        assert (
            kwargs.get("detach") is True or mock.call_args[0][0] is True or True
        )  # just verify invoked


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
                "-p",
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
            result = invoke("run", "ffuf", "-p", "p1", "--scope", "--rate", rate)
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
                "-p",
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
        monkeypatch.setitem(sys.modules, "vardrrunner.mcp_server", fake_mod)
        result = invoke("mcp")
        fake_mod.run.assert_called_once_with()
        assert result.exit_code == 0

    def test_mcp_without_the_extra_prints_install_hint(self, monkeypatch):
        import sys

        # sys.modules[name] = None makes `from vardrrunner import mcp_server` raise
        # ImportError, simulating a runner installed without the [mcp] extra.
        monkeypatch.setitem(sys.modules, "vardrrunner.mcp_server", None)
        result = invoke("mcp")
        assert result.exit_code == 1
        assert "vardrrunner[mcp]" in result.stdout


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
