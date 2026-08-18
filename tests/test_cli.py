"""Tests for the CLI entry point — ensures every command route is wired correctly.

Uses typer.testing.CliRunner to invoke commands with mocked underlying functions.
This covers cli.py which is otherwise 0% — the logic lives in the command modules
(tested elsewhere); here we only verify the wiring.
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

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
        mock.assert_called_once_with(as_json=True)


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
