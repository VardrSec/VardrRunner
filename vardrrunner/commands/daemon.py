"""
vardrrunner daemon — legacy worker cleanup.

start  : rejected; scans require an explicit manual command
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

import json
import logging
import logging.handlers
import os
import signal
import stat
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import redaction

console = Console()

PID_FILE = Path.home() / ".vardrrunner.pid"
DEFAULT_LOG = Path.home() / ".vardrrunner.log"

_IS_WINDOWS = os.name == "nt"

# Rotate at 5 MB, keep 3 backups (≈ 20 MB total log budget).
_LOG_MAX_BYTES = 5 * 1024 * 1024
_LOG_BACKUP_COUNT = 3


class DaemonStateError(RuntimeError):
    """The daemon PID ownership file cannot be claimed safely."""


class LogFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


class _JsonLineFormatter(logging.Formatter):
    """One redacted JSON object per daemon console line."""

    def __init__(self, runner_id: str = "") -> None:
        super().__init__()
        self.runner_id = runner_id

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "log_schema_version": 1,
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "event": getattr(record, "event", "console"),
            "runner_id": self.runner_id,
            "pid": os.getpid(),
            "message": redaction.redact_text(record.getMessage()),
        }
        return json.dumps(redaction.redact(payload), sort_keys=True)


class _RotatingLogFile:
    """File-like object backed by a RotatingFileHandler so Rich Console can write to it.

    Rich calls write() with arbitrary chunks (may or may not end with '\\n'). We buffer
    until a newline arrives, then emit each complete line to the logger so the
    timestamp formatter runs once per logical line rather than per chunk.
    """

    def __init__(
        self, path: Path, log_format: LogFormat = LogFormat.TEXT, runner_id: str = ""
    ) -> None:
        handler = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        if log_format is LogFormat.JSON:
            handler.setFormatter(_JsonLineFormatter(runner_id))
        else:
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
        pid = int(PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None
    return pid if pid > 0 else None


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


def _claim_pid_file(pid: int) -> None:
    """Atomically claim daemon ownership, replacing at most one stale file."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(2):
        try:
            fd = os.open(
                PID_FILE,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                stat.S_IRUSR | stat.S_IWUSR,
            )
        except FileExistsError as exc:
            existing = _read_pid()
            if existing is not None and _process_alive(existing):
                raise DaemonStateError(f"daemon already running (PID {existing})") from exc
            if attempt == 1:
                raise DaemonStateError("could not replace stale daemon PID file") from exc
            try:
                PID_FILE.unlink()
            except OSError as unlink_error:
                raise DaemonStateError("could not remove stale daemon PID file") from unlink_error
            continue
        except OSError as exc:
            raise DaemonStateError("could not create daemon PID file") from exc

        try:
            handle = os.fdopen(fd, "w", encoding="ascii", newline="\n")
        except Exception as exc:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                PID_FILE.unlink(missing_ok=True)
            except OSError:
                pass
            raise DaemonStateError("could not open daemon PID file") from exc
        try:
            with handle:
                handle.write(f"{pid}\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception as exc:
            try:
                PID_FILE.unlink(missing_ok=True)
            except OSError:
                pass
            raise DaemonStateError("could not write daemon PID file") from exc
        return
    raise DaemonStateError("could not claim daemon PID file")  # pragma: no cover


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
    log_format: LogFormat = LogFormat.TEXT,
    run_jobs: bool = False,
) -> None:
    """Reject legacy worker startup without polling, recovery, or process creation."""
    console.print(
        "[red]Background workers are no longer supported.[/red] "
        "Run scans explicitly with `vardrrunner run <tool>`, `vardrrunner pipeline run`, "
        "or `vardrrunner jobs run`. Use `vardrrunner heartbeat` to report availability once. "
        "Remove any older startup service with `vardrrunner service uninstall`."
    )
    raise typer.Exit(2)


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
