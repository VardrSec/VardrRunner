"""
vardrrunner daemon — long-running background worker.

start  : run the job-poll + heartbeat loop (foreground or detached)
stop   : request a graceful shutdown of a running daemon
status : show whether a daemon is running

Cross-platform shutdown protocol: removing the PID file is the stop signal.
The daemon re-reads the PID file every poll cycle and exits cleanly when it
is gone (or no longer contains its own PID). This works identically on
Windows and POSIX; on POSIX we additionally send SIGTERM so an idle daemon
wakes immediately instead of waiting out the poll interval.

WARNING for future edits: os.kill(pid, sig) on Windows is NOT a signal API —
any sig other than CTRL_C_EVENT/CTRL_BREAK_EVENT calls TerminateProcess and
unconditionally kills the target. Never use os.kill(pid, 0) as a liveness
probe on Windows.
"""

import logging
import logging.handlers
import os
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import api, config, redaction
from vardrrunner.commands.heartbeat import send_heartbeat
from vardrrunner.commands.jobs import execute_pending_jobs
from vardrrunner.journal import Journal
from vardrrunner.recovery import reconcile

console = Console()

PID_FILE = Path.home() / ".vardrrunner.pid"
DEFAULT_LOG = Path.home() / ".vardrrunner.log"

_IS_WINDOWS = os.name == "nt"

# Rotate at 5 MB, keep 3 backups (≈ 20 MB total log budget).
_LOG_MAX_BYTES = 5 * 1024 * 1024
_LOG_BACKUP_COUNT = 3


class _RotatingLogFile:
    """File-like object backed by a RotatingFileHandler so Rich Console can write to it.

    Rich calls write() with arbitrary chunks (may or may not end with '\\n'). We buffer
    until a newline arrives, then emit each complete line to the logger so the
    timestamp formatter runs once per logical line rather than per chunk.
    """

    def __init__(self, path: Path) -> None:
        handler = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
        )
        self._logger = logging.getLogger(f"vardrrunner.daemon.{id(self)}")
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._handler = handler
        self._buf = ""

    def write(self, data: str) -> int:
        self._buf += data
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                self._logger.info(line)
        return len(data)

    def flush(self) -> None:
        if self._buf.strip():
            self._logger.info(self._buf)
            self._buf = ""

    def isatty(self) -> bool:
        return False

    def close(self) -> None:
        self.flush()
        self._handler.close()
        self._logger.removeHandler(self._handler)


# ── PID helpers ──────────────────────────────────────────────────────────────


def _read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def _process_alive(pid: int) -> bool:
    """Check whether a process exists without affecting it."""
    if _IS_WINDOWS:
        # Query the process handle instead of os.kill — see module docstring.
        import ctypes

        STILL_ACTIVE = 259
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]  # Windows-only
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)  # POSIX: signal 0 is a pure existence probe
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another user
    return True


# ── Commands ─────────────────────────────────────────────────────────────────


def start(
    detach: bool = typer.Option(
        False,
        "--detach",
        "-d",
        help="Run in background and write PID to ~/.vardrrunner.pid",
    ),
    poll_interval: int = typer.Option(5, "--poll-interval", help="Seconds between job polls"),
    heartbeat_interval: int = typer.Option(
        60, "--heartbeat-interval", help="Seconds between heartbeats"
    ),
    log_file: Path | None = typer.Option(
        None,
        "--log-file",
        help="Append output to file (defaults to ~/.vardrrunner.log when --detach is used)",
    ),
) -> None:
    """Start the daemon: continuously poll for jobs and send heartbeats."""
    existing = _read_pid()
    if existing and _process_alive(existing):
        console.print(
            f"[red]Daemon already running (PID {existing}).[/red] "
            "Stop it first: vardrrunner daemon stop"
        )
        raise typer.Exit(1)

    if detach:
        _detach(
            poll_interval=poll_interval, heartbeat_interval=heartbeat_interval, log_file=log_file
        )
        return

    try:
        config.require_auth()
    except Exception as e:
        console.print(f"[red]Not authenticated:[/red] {redaction.redact_rich_exception(e)}")
        raise typer.Exit(1) from e

    # Opening and migrating the journal is a startup gate. The daemon must not
    # claim work it cannot durably account for.
    try:
        journal_store = Journal(config.journal_file())
    except Exception as e:
        console.print(
            f"[red]Execution journal unavailable:[/red] {redaction.redact_rich_exception(e)}"
        )
        raise typer.Exit(1) from e

    out = console
    _log = None
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        _log = _RotatingLogFile(log_file)
        out = Console(file=_log, highlight=False)  # type: ignore[arg-type]

    pid = os.getpid()
    PID_FILE.write_text(str(pid))
    out.print(
        f"[green]Daemon started[/green] · PID {pid} "
        f"· poll {poll_interval}s · heartbeat {heartbeat_interval}s"
    )
    out.print("[dim]Press Ctrl+C to stop.[/dim]")

    _stop = threading.Event()

    def _on_signal(sig, _frame):
        out.print(f"\n[yellow]Signal {sig} — finishing current job then stopping…[/yellow]")
        _stop.set()

    # SIGINT covers Ctrl+C on both platforms; SIGTERM only fires on POSIX
    # (Windows termination is handled by the PID-file check below).
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    def _shutdown_requested() -> bool:
        # PID file removed or replaced by another process = graceful stop request
        return _stop.is_set() or _read_pid() != pid

    # Heartbeat runs on its own interval independent of job duration
    def _hb_loop():
        send_heartbeat(quiet=True)
        while not _stop.wait(timeout=heartbeat_interval):
            send_heartbeat(quiet=True)

    hb_thread = threading.Thread(target=_hb_loop, daemon=True, name="vardrrunner-heartbeat")
    hb_thread.start()

    _error_streak = 0
    # Engagements whose stop-work switch refused a claim. Held for the life of
    # the daemon so a halted engagement is not re-claimed and re-refused every
    # poll_interval seconds; restarting the daemon re-checks it.
    _stop_work_blocked: dict[str, float] = {}
    try:
        while not _shutdown_requested():
            try:
                url, key = config.require_auth()
                client = api.VardrMapClient(url, key)
                reconcile(journal_store, client, url, out)
                count = execute_pending_jobs(
                    client,
                    out,
                    blocked_engagements=_stop_work_blocked,
                    journal_store=journal_store,
                    backend_url=url,
                )
                if count:
                    out.print(f"[dim]Cycle complete — {count} job(s) executed.[/dim]")
                _error_streak = 0
            except Exception as e:
                # Transient API/network errors must never kill the loop; back off
                # exponentially (5s → 10s → 20s … capped at 5 min) so a downed
                # backend is polled politely instead of hammered every 5 seconds.
                _error_streak += 1
                backoff = min(poll_interval * (2 ** (_error_streak - 1)), 300)
                out.print(
                    f"[red]Poll error:[/red] {redaction.redact_exception(e)}  (retry in {backoff}s)"
                )
                _stop.wait(timeout=backoff)
                continue
            _stop.wait(timeout=poll_interval)
    finally:
        _stop.set()  # release the heartbeat thread promptly
        # Only remove the PID file if it is still ours — stop() may have
        # already removed it, or a new daemon may have replaced it.
        if _read_pid() == pid:
            PID_FILE.unlink(missing_ok=True)
        out.print("[dim]Daemon stopped.[/dim]")
        if _log:
            _log.close()


def stop() -> None:
    """Request a graceful daemon shutdown.

    Removes the PID file (the cross-platform stop signal — the daemon checks
    it every poll cycle and exits after finishing the current job). On POSIX,
    also sends SIGTERM so an idle daemon wakes immediately.
    """
    pid = _read_pid()
    if pid is None:
        console.print("[yellow]No daemon running (no PID file).[/yellow]")
        raise typer.Exit(1)
    if not _process_alive(pid):
        console.print(f"[yellow]PID {pid} is not running — removing stale PID file.[/yellow]")
        PID_FILE.unlink(missing_ok=True)
        raise typer.Exit(1)

    PID_FILE.unlink(missing_ok=True)
    if not _IS_WINDOWS:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    console.print(
        f"[green]Stop requested[/green] — daemon (PID {pid}) will finish its "
        "current job and exit within one poll interval."
    )


def status() -> None:
    """Show whether the daemon is currently running."""
    pid = _read_pid()
    if pid is None:
        console.print("[dim]Daemon not running (no PID file).[/dim]")
        return
    if _process_alive(pid):
        console.print(f"[green]Daemon running[/green] · PID {pid}")
    else:
        console.print(f"[yellow]Stale PID file (process {pid} not found) — cleaning up.[/yellow]")
        PID_FILE.unlink(missing_ok=True)


def _detach(poll_interval: int, heartbeat_interval: int, log_file: Path | None) -> None:
    """Re-launch self without --detach so the child runs as a foreground daemon."""
    exe = shutil.which("vardrrunner") or sys.argv[0]
    if log_file is None:
        log_file = DEFAULT_LOG

    cmd = [
        exe,
        "daemon",
        "start",
        "--poll-interval",
        str(poll_interval),
        "--heartbeat-interval",
        str(heartbeat_interval),
        "--log-file",
        str(log_file),
    ]

    log_file.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_file, "a")

    # Detach from this terminal so closing it doesn't kill the daemon:
    # Windows needs DETACHED_PROCESS (start_new_session is POSIX-only).
    popen_kwargs: dict = {}
    if _IS_WINDOWS:
        # DETACHED_PROCESS / CREATE_NEW_PROCESS_GROUP are Windows-only — absent when
        # mypy type-checks on Linux (CI), so ignore the attr-defined error there.
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        popen_kwargs["creationflags"] = flags
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(
        cmd,
        stdout=fh,
        stderr=fh,
        close_fds=True,
        **popen_kwargs,
    )
    console.print(f"[green]Daemon started[/green] · PID {proc.pid} · log {log_file}")
