"""
Tests for the VardrRunner daemon: PID helpers, stop, status, _detach, and the
main polling loop. All signal delivery and subprocess calls are mocked.

Platform-dependent paths (Windows vs POSIX) are tested by monkeypatching the
module-level _IS_WINDOWS flag rather than relying on the host OS.
"""

import json
import os
import signal
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from vardrrunner.commands import daemon as daemon_mod
from vardrrunner.commands.jobs import execute_pending_jobs

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def pid_file(tmp_path, monkeypatch):
    """Redirect PID_FILE to a temp path so tests don't touch ~/.vardrrunner.pid."""
    pf = tmp_path / ".vardrrunner.pid"
    monkeypatch.setattr(daemon_mod, "PID_FILE", pf)
    return pf


def _fake_event_factory(stop_after: int):
    """Build a threading.Event stand-in whose is_set() flips True after N checks."""
    iterations = {"n": 0}

    class FakeEvent:
        def is_set(self):
            r = iterations["n"] >= stop_after
            iterations["n"] += 1
            return r

        def wait(self, timeout=None):
            return False

        def set(self):
            pass

    return FakeEvent


# ---------------------------------------------------------------------------
# _read_pid
# ---------------------------------------------------------------------------


class TestReadPid:
    def test_no_file_returns_none(self, pid_file):
        assert daemon_mod._read_pid() is None

    def test_valid_file_returns_int(self, pid_file):
        pid_file.write_text("12345")
        assert daemon_mod._read_pid() == 12345

    def test_invalid_content_returns_none(self, pid_file):
        pid_file.write_text("not-a-pid")
        assert daemon_mod._read_pid() is None

    def test_empty_file_returns_none(self, pid_file):
        pid_file.write_text("")
        assert daemon_mod._read_pid() is None

    @pytest.mark.parametrize("value", ["0", "-1"])
    def test_nonpositive_pid_returns_none(self, pid_file, value):
        pid_file.write_text(value)
        assert daemon_mod._read_pid() is None


class TestPidClaim:
    def test_claim_is_exclusive_and_owner_only(self, pid_file):
        daemon_mod._claim_pid_file(os.getpid())
        assert daemon_mod._read_pid() == os.getpid()
        if os.name != "nt":
            assert pid_file.stat().st_mode & 0o077 == 0
        with pytest.raises(daemon_mod.DaemonStateError, match="already running"):
            daemon_mod._claim_pid_file(os.getpid())

    def test_stale_file_is_replaced(self, pid_file):
        pid_file.write_text("2000000000")
        daemon_mod._claim_pid_file(os.getpid())
        assert daemon_mod._read_pid() == os.getpid()

    def test_stale_file_removal_failure_is_classified(self, pid_file):
        pid_file.write_text("bad")
        with (
            patch.object(Path, "unlink", side_effect=OSError("locked")),
            pytest.raises(daemon_mod.DaemonStateError, match="remove stale"),
        ):
            daemon_mod._claim_pid_file(os.getpid())

    def test_pid_create_failure_is_classified(self, pid_file):
        with (
            patch("vardrrunner.commands.daemon.os.open", side_effect=OSError("denied")),
            pytest.raises(daemon_mod.DaemonStateError, match="create"),
        ):
            daemon_mod._claim_pid_file(os.getpid())

    def test_pid_write_failure_cleans_up_and_is_classified(self, pid_file):
        with (
            patch("vardrrunner.commands.daemon.os.fdopen", side_effect=OSError("disk full")),
            pytest.raises(daemon_mod.DaemonStateError, match="open"),
        ):
            daemon_mod._claim_pid_file(os.getpid())
        assert not pid_file.exists()

    def test_pid_flush_failure_cleans_up_and_is_classified(self, pid_file):
        with (
            patch("vardrrunner.commands.daemon.os.fsync", side_effect=OSError("disk full")),
            pytest.raises(daemon_mod.DaemonStateError, match="write"),
        ):
            daemon_mod._claim_pid_file(os.getpid())
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# _process_alive
# ---------------------------------------------------------------------------


class TestProcessAlive:
    def test_self_is_alive(self):
        assert daemon_mod._process_alive(os.getpid()) is True

    def test_nonexistent_pid_returns_false(self):
        assert daemon_mod._process_alive(2_000_000_000) is False

    def test_posix_permission_error_means_alive(self, monkeypatch):
        """On POSIX, EPERM from kill(pid, 0) means the process exists."""
        monkeypatch.setattr(daemon_mod, "_IS_WINDOWS", False)
        with patch("vardrrunner.commands.daemon.os.kill", side_effect=PermissionError):
            assert daemon_mod._process_alive(1234) is True

    def test_posix_lookup_error_means_dead(self, monkeypatch):
        monkeypatch.setattr(daemon_mod, "_IS_WINDOWS", False)
        with patch("vardrrunner.commands.daemon.os.kill", side_effect=ProcessLookupError):
            assert daemon_mod._process_alive(1234) is False

    def test_windows_never_calls_os_kill(self, monkeypatch):
        """os.kill on Windows is TerminateProcess — the probe must never use it."""
        monkeypatch.setattr(daemon_mod, "_IS_WINDOWS", True)
        fake_kernel32 = MagicMock()
        fake_kernel32.OpenProcess.return_value = 0  # process not found
        fake_ctypes = MagicMock()
        fake_ctypes.windll.kernel32 = fake_kernel32
        with (
            patch.dict("sys.modules", {"ctypes": fake_ctypes}),
            patch("vardrrunner.commands.daemon.os.kill") as mock_kill,
        ):
            assert daemon_mod._process_alive(1234) is False
        mock_kill.assert_not_called()


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------


class TestStop:
    def test_no_pid_file_exits_1(self, pid_file):
        with pytest.raises(typer.Exit):
            daemon_mod.stop()

    def test_stale_pid_removes_file_and_exits(self, pid_file):
        pid_file.write_text("2000000000")
        with pytest.raises(typer.Exit):
            daemon_mod.stop()
        assert not pid_file.exists()

    def test_live_pid_removes_pid_file(self, pid_file):
        """Removing the PID file is the cross-platform graceful stop signal."""
        pid_file.write_text("1234")
        with patch.object(daemon_mod, "_process_alive", return_value=True):
            daemon_mod.stop()
        assert not pid_file.exists()

    def test_posix_also_sends_sigterm(self, pid_file, monkeypatch):
        monkeypatch.setattr(daemon_mod, "_IS_WINDOWS", False)
        pid_file.write_text("1234")
        with (
            patch.object(daemon_mod, "_process_alive", return_value=True),
            patch("vardrrunner.commands.daemon.os.kill") as mock_kill,
        ):
            daemon_mod.stop()
        mock_kill.assert_called_once_with(1234, signal.SIGTERM)

    def test_windows_does_not_call_os_kill(self, pid_file, monkeypatch):
        """On Windows os.kill would hard-kill mid-job — stop must rely on the PID file only."""
        monkeypatch.setattr(daemon_mod, "_IS_WINDOWS", True)
        pid_file.write_text("1234")
        with (
            patch.object(daemon_mod, "_process_alive", return_value=True),
            patch("vardrrunner.commands.daemon.os.kill") as mock_kill,
        ):
            daemon_mod.stop()
        mock_kill.assert_not_called()
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_no_pid_file_does_not_raise(self, pid_file):
        daemon_mod.status()  # should not raise

    def test_live_pid_does_not_raise(self, pid_file):
        pid_file.write_text(str(os.getpid()))
        daemon_mod.status()
        assert pid_file.exists()  # status must never remove a live daemon's PID file

    def test_stale_pid_removes_file(self, pid_file):
        pid_file.write_text("2000000000")
        daemon_mod.status()
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# _detach
# ---------------------------------------------------------------------------


class TestDetach:
    def test_spawns_daemon_process(self, tmp_path):
        log = tmp_path / "daemon.log"
        with (
            patch("vardrrunner.commands.daemon.shutil.which", return_value="vardrrunner"),
            patch("vardrrunner.commands.daemon.subprocess.Popen") as MockPopen,
        ):
            MockPopen.return_value = MagicMock(pid=9999)
            daemon_mod._detach(poll_interval=5, heartbeat_interval=60, log_file=log)

        args, _ = MockPopen.call_args
        cmd = args[0]
        assert cmd[0] == "vardrrunner"
        assert "daemon" in cmd
        assert "start" in cmd
        assert "--poll-interval" in cmd
        assert "--log-file" in cmd

    def test_defaults_log_to_home(self, tmp_path, monkeypatch):
        monkeypatch.setattr(daemon_mod, "DEFAULT_LOG", tmp_path / "daemon.log")
        with (
            patch("vardrrunner.commands.daemon.shutil.which", return_value="vardrrunner"),
            patch("vardrrunner.commands.daemon.subprocess.Popen") as MockPopen,
        ):
            MockPopen.return_value = MagicMock(pid=1)
            daemon_mod._detach(poll_interval=5, heartbeat_interval=60, log_file=None)

        args, _ = MockPopen.call_args
        assert str(tmp_path / "daemon.log") in args[0]

    def test_posix_uses_start_new_session(self, tmp_path, monkeypatch):
        monkeypatch.setattr(daemon_mod, "_IS_WINDOWS", False)
        with (
            patch("vardrrunner.commands.daemon.shutil.which", return_value="vardrrunner"),
            patch("vardrrunner.commands.daemon.subprocess.Popen") as MockPopen,
        ):
            MockPopen.return_value = MagicMock(pid=1)
            daemon_mod._detach(poll_interval=5, heartbeat_interval=60, log_file=tmp_path / "d.log")

        _, kwargs = MockPopen.call_args
        assert kwargs.get("start_new_session") is True
        assert "creationflags" not in kwargs

    def test_windows_uses_detached_process_flags(self, tmp_path, monkeypatch):
        """Windows needs DETACHED_PROCESS so the daemon survives terminal close."""
        monkeypatch.setattr(daemon_mod, "_IS_WINDOWS", True)
        # These constants only exist in subprocess on Windows builds
        monkeypatch.setattr(daemon_mod.subprocess, "DETACHED_PROCESS", 0x8, raising=False)
        monkeypatch.setattr(daemon_mod.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200, raising=False)
        with (
            patch("vardrrunner.commands.daemon.shutil.which", return_value="vardrrunner"),
            patch("vardrrunner.commands.daemon.subprocess.Popen") as MockPopen,
        ):
            MockPopen.return_value = MagicMock(pid=1)
            daemon_mod._detach(poll_interval=5, heartbeat_interval=60, log_file=tmp_path / "d.log")

        _, kwargs = MockPopen.call_args
        assert kwargs.get("creationflags") == (0x8 | 0x200)
        assert "start_new_session" not in kwargs


# ---------------------------------------------------------------------------
# start (foreground loop)
# ---------------------------------------------------------------------------


def _run_start(pid_file, stop_after: int, execute=None, heartbeat_report=None):
    """Run daemon_mod.start with all externals mocked; loop exits after N cycles."""
    execute = execute if execute is not None else MagicMock(return_value=0)
    with (
        patch("vardrrunner.commands.daemon.threading.Event", _fake_event_factory(stop_after)),
        patch("vardrrunner.commands.daemon.threading.Thread") as MockThread,
        patch("vardrrunner.commands.daemon.signal.signal"),
        patch(
            "vardrrunner.commands.daemon.config.require_auth", return_value=("http://api", "key")
        ),
        patch("vardrrunner.commands.daemon.api.VardrMapClient"),
        patch("vardrrunner.commands.daemon.execute_pending_jobs", execute),
        patch("vardrrunner.commands.daemon.send_heartbeat", return_value=heartbeat_report),
    ):
        daemon_mod.start(detach=False, poll_interval=1, heartbeat_interval=60, log_file=None)
    return execute, MockThread


class TestStart:
    def test_writes_and_removes_pid_file(self, pid_file):
        """Daemon writes PID on entry and removes it in the finally block."""
        _run_start(pid_file, stop_after=1)
        assert not pid_file.exists()

    @pytest.mark.parametrize(("poll", "heartbeat"), [(0, 60), (5, 0)])
    def test_rejects_invalid_intervals(self, pid_file, poll, heartbeat):
        with pytest.raises(typer.Exit):
            daemon_mod.start(
                detach=False,
                poll_interval=poll,
                heartbeat_interval=heartbeat,
                log_file=None,
            )
        assert not pid_file.exists()

    def test_calls_execute_pending_jobs(self, pid_file):
        execute, _ = _run_start(pid_file, stop_after=1)
        execute.assert_called_once()
        assert callable(execute.call_args.kwargs["should_stop"])

    def test_compatibility_block_pauses_claims(self, pid_file, capsys):
        from vardrrunner import compatibility

        report = compatibility.CompatibilityReport(
            compatibility.CompatibilityLevel.BLOCK, ("upgrade required",)
        )
        execute, _ = _run_start(pid_file, stop_after=1, heartbeat_report=report)
        execute.assert_not_called()
        assert "claims paused" in capsys.readouterr().out

    def test_invalid_resource_policy_fails_before_pid(self, pid_file):
        from vardrrunner import resources

        with (
            patch(
                "vardrrunner.commands.daemon.config.require_auth",
                return_value=("http://api", "key"),
            ),
            patch(
                "vardrrunner.commands.daemon.resources.load_limits",
                side_effect=resources.ResourceLimitError("bad limit"),
            ),
            pytest.raises(typer.Exit),
        ):
            daemon_mod.start(detach=False, poll_interval=5, heartbeat_interval=60, log_file=None)
        assert not pid_file.exists()

    def test_starts_heartbeat_thread(self, pid_file):
        _, MockThread = _run_start(pid_file, stop_after=1)
        MockThread.assert_called_once()
        MockThread.return_value.start.assert_called_once()

    def test_exits_when_not_authenticated(self, pid_file):
        with patch(
            "vardrrunner.commands.daemon.config.require_auth", side_effect=RuntimeError("no creds")
        ):
            with pytest.raises(typer.Exit):
                daemon_mod.start(
                    detach=False, poll_interval=5, heartbeat_interval=60, log_file=None
                )

    def test_refuses_to_start_when_already_running(self, pid_file):
        """A second daemon must not silently overwrite a live daemon's PID file."""
        pid_file.write_text("1234")
        with patch.object(daemon_mod, "_process_alive", return_value=True):
            with pytest.raises(typer.Exit):
                daemon_mod.start(
                    detach=False, poll_interval=5, heartbeat_interval=60, log_file=None
                )
        assert pid_file.read_text() == "1234"  # untouched

    def test_starts_over_stale_pid_file(self, pid_file):
        """A dead process's leftover PID file must not block startup."""
        pid_file.write_text("2000000000")
        _run_start(pid_file, stop_after=1)
        assert not pid_file.exists()  # ran and cleaned up

    def test_detach_delegates_to_detach(self, pid_file, tmp_path):
        log = tmp_path / "daemon.log"
        with patch("vardrrunner.commands.daemon._detach") as mock_detach:
            daemon_mod.start(detach=True, poll_interval=5, heartbeat_interval=60, log_file=log)
        mock_detach.assert_called_once_with(
            poll_interval=5,
            heartbeat_interval=60,
            log_file=log,
            log_format=daemon_mod.LogFormat.TEXT,
        )

    def test_poll_error_does_not_crash_daemon(self, pid_file):
        """A transient API error is caught and the loop continues."""
        call_count = {"n": 0}

        def flaky_execute(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("temporary network error")
            return 0

        _run_start(pid_file, stop_after=2, execute=MagicMock(side_effect=flaky_execute))
        assert call_count["n"] == 2  # tried twice despite first failure

    def test_poll_backoff_message_mentions_retry(self, pid_file, capsys):
        """The backoff message should tell operators when the next retry will happen."""

        def always_fail(*args, **kwargs):
            raise RuntimeError("backend down")

        _run_start(pid_file, stop_after=1, execute=MagicMock(side_effect=always_fail))
        out = capsys.readouterr().out
        assert "retry in" in out

    def test_pid_file_removal_stops_loop(self, pid_file):
        """Deleting the PID file (what `stop` does) ends the loop gracefully."""

        def remove_pid_file(*args, **kwargs):
            pid_file.unlink(missing_ok=True)
            return 0

        # Event never fires — only the PID-file check can end the loop
        execute, _ = _run_start(
            pid_file, stop_after=99, execute=MagicMock(side_effect=remove_pid_file)
        )
        execute.assert_called_once()
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# _RotatingLogFile
# ---------------------------------------------------------------------------


class TestRotatingLogFile:
    def test_writes_timestamped_lines(self, tmp_path):
        log = tmp_path / "daemon.log"
        f = daemon_mod._RotatingLogFile(log)
        f.write("hello from daemon\n")
        f.flush()
        f.close()

        content = log.read_text(encoding="utf-8")
        assert "hello from daemon" in content
        # Timestamp prefix: YYYY-MM-DDTHH:MM:SS
        import re

        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", content)

    def test_buffers_partial_writes(self, tmp_path):
        log = tmp_path / "daemon.log"
        f = daemon_mod._RotatingLogFile(log)
        f.write("part one ")
        f.write("part two\n")
        f.close()

        content = log.read_text(encoding="utf-8")
        assert "part one part two" in content

    def test_json_lines_are_structured_and_redacted(self, tmp_path):
        log = tmp_path / "daemon.jsonl"
        f = daemon_mod._RotatingLogFile(
            log, log_format=daemon_mod.LogFormat.JSON, runner_id="runner-123"
        )
        f.write("request token=vmap_abcdefgh failed\n")
        f.close()
        payload = json.loads(log.read_text(encoding="utf-8"))
        assert payload["log_schema_version"] == 1
        assert payload["event"] == "console"
        assert payload["runner_id"] == "runner-123"
        assert payload["pid"] == os.getpid()
        assert "vmap_abcdefgh" not in payload["message"]

    def test_returns_byte_count(self, tmp_path):
        log = tmp_path / "daemon.log"
        f = daemon_mod._RotatingLogFile(log)
        n = f.write("test\n")
        f.close()
        assert n == 5

    def test_no_crash_when_runs_dir_absent(self, tmp_path):
        log = tmp_path / "subdir" / "daemon.log"
        log.parent.mkdir()
        f = daemon_mod._RotatingLogFile(log)
        f.write("ok\n")
        f.close()
        assert log.exists()

    def test_start_writes_to_log_file(self, pid_file, tmp_path):
        log = tmp_path / "daemon.log"

        with (
            patch("vardrrunner.commands.daemon.threading.Event", _fake_event_factory(1)),
            patch("vardrrunner.commands.daemon.threading.Thread"),
            patch("vardrrunner.commands.daemon.signal.signal"),
            patch(
                "vardrrunner.commands.daemon.config.require_auth",
                return_value=("http://api", "key"),
            ),
            patch("vardrrunner.commands.daemon.api.VardrMapClient"),
            patch("vardrrunner.commands.daemon.execute_pending_jobs", return_value=0),
            patch("vardrrunner.commands.daemon.send_heartbeat"),
        ):
            daemon_mod.start(detach=False, poll_interval=1, heartbeat_interval=60, log_file=log)

        content = log.read_text(encoding="utf-8")
        assert "Daemon started" in content

    def test_log_file_contains_no_markup_brackets(self, pid_file, tmp_path):
        """Rich markup tags must not appear literally in the log file."""
        log = tmp_path / "daemon.log"

        with (
            patch("vardrrunner.commands.daemon.threading.Event", _fake_event_factory(1)),
            patch("vardrrunner.commands.daemon.threading.Thread"),
            patch("vardrrunner.commands.daemon.signal.signal"),
            patch(
                "vardrrunner.commands.daemon.config.require_auth",
                return_value=("http://api", "key"),
            ),
            patch("vardrrunner.commands.daemon.api.VardrMapClient"),
            patch("vardrrunner.commands.daemon.execute_pending_jobs", return_value=0),
            patch("vardrrunner.commands.daemon.send_heartbeat"),
        ):
            daemon_mod.start(detach=False, poll_interval=1, heartbeat_interval=60, log_file=log)

        content = log.read_text(encoding="utf-8")
        assert "[green]" not in content
        assert "[dim]" not in content

    def test_rotating_log_file_isatty_returns_false(self, tmp_path):
        log = tmp_path / "daemon.log"
        f = daemon_mod._RotatingLogFile(log)
        assert f.isatty() is False
        f.close()


# ---------------------------------------------------------------------------
# execute_pending_jobs
# ---------------------------------------------------------------------------


class TestExecutePendingJobs:
    def test_empty_queue_returns_zero(self):
        client = MagicMock()
        client.pending_jobs.return_value = []
        con = MagicMock()
        assert execute_pending_jobs(client, con) == 0

    def test_returns_job_count(self, tmp_path):
        output_file = tmp_path / "httpx.jsonl"
        output_file.write_text('{"url":"https://example.com"}\n')

        job = {
            "id": "job-d01",
            "engagement_id": "prog-1",
            "tool_type": "httpx",
            "target_source": "scope",
            "config": {"limit": 50},
        }
        client = MagicMock()
        client.pending_jobs.return_value = [job]
        client.scope.return_value = {"in": [{"value": "app.example.com"}], "out": []}
        client.import_file.return_value = {"import_record": {"imported_count": 1}}

        with (
            patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
            patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
            patch("vardrrunner.commands.jobs.runner.run_httpx", return_value=0),
        ):
            con = MagicMock()
            result = execute_pending_jobs(client, con)

        assert result == 1
        client.claim_job.assert_called_once_with("job-d01")
        client.complete_job.assert_called_once_with("job-d01", "done")
