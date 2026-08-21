"""
Safe subprocess runner. Only tools in ALLOWED_TOOLS can be executed.
Commands are built as argument lists — shell=True is never used.
"""

import json
import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

# Allowlist maps subcommand names to their executable names.
# Add new tools here only — never allow arbitrary executables.
ALLOWED_TOOLS = {
    "httpx": "httpx",
    "nuclei": "nuclei",
    "subfinder": "subfinder",
    "nmap": "nmap",
    "dnsx": "dnsx",
    "naabu": "naabu",
    # Job type "vardrgate_api_test" maps to the "vardrgate" binary on PATH.
    "vardrgate_api_test": "vardrgate",
}

# Wall-clock ceiling for a single tool run. A hung tool must never freeze the
# daemon forever — the run is killed and the job marked failed. Override per run
# (job config `timeout`) or globally via the VARDRRUNNER_TOOL_TIMEOUT env var.
DEFAULT_TOOL_TIMEOUT = 1800  # 30 minutes
_SENSITIVE_TEMP_PREFIX = "vardrrunner-vardrgate-"


class ToolTimeout(Exception):
    """Raised when a tool subprocess exceeds its timeout. The process is killed."""


class ToolError(Exception):
    """Raised when a tool subprocess exits with a non-zero return code."""


_PROCESS_OBSERVER: ContextVar[Callable[[int], None] | None] = ContextVar(
    "vardrrunner_process_observer", default=None
)


@contextmanager
def observe_process(callback: Callable[[int], None]) -> Iterator[None]:
    """Report the spawned tool PID to the current execution context.

    Job execution uses this to durably record the child process. Direct CLI
    runs do not install an observer and retain the simpler ``subprocess.run``
    path.
    """
    token = _PROCESS_OBSERVER.set(callback)
    try:
        yield
    finally:
        _PROCESS_OBSERVER.reset(token)


def _resolve_timeout(override: int | None) -> int:
    """Pick the effective timeout: explicit override > env var > default."""
    if override and override > 0:
        return override
    raw = os.environ.get("VARDRRUNNER_TOOL_TIMEOUT")
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            logging.warning(
                "VARDRRUNNER_TOOL_TIMEOUT=%r is not a valid integer — using default %ds",
                raw,
                DEFAULT_TOOL_TIMEOUT,
            )
    return DEFAULT_TOOL_TIMEOUT


def _terminate_process_tree(process: subprocess.Popen) -> None:
    """Terminate a tool and its descendants, then reap the parent process."""
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
        else:
            if result.returncode != 0:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)  # type: ignore[attr-defined]
        except ProcessLookupError:
            pass
        except OSError:
            process.kill()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _spawn_tool(cmd: list[str]) -> subprocess.Popen:
    """Start a tool in a process group that can be terminated as one unit."""
    if os.name == "nt":
        return subprocess.Popen(
            cmd,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,  # type: ignore[attr-defined]
        )
    return subprocess.Popen(cmd, start_new_session=True)


def _pid_alive(pid: int) -> bool:
    """Best-effort liveness check used only to protect active private temp dirs."""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        process_query_limited_information = 0x1000
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def cleanup_sensitive_temp_dirs() -> None:
    """Remove abandoned private VardrGate job directories without touching active runs."""
    try:
        root = Path(tempfile.gettempdir()).resolve()
        entries = tuple(root.iterdir())
    except OSError:
        return
    for candidate in entries:
        if not candidate.name.startswith(_SENSITIVE_TEMP_PREFIX):
            continue
        suffix = candidate.name.removeprefix(_SENSITIVE_TEMP_PREFIX)
        pid_text, separator, nonce = suffix.partition("-")
        if not separator or not nonce or not pid_text.isdigit():
            continue
        try:
            is_junction = getattr(candidate, "is_junction", lambda: False)()
            if candidate.is_symlink() or is_junction or not candidate.is_dir():
                continue
            resolved = candidate.resolve()
            if resolved.parent != root or _pid_alive(int(pid_text)):
                continue
            shutil.rmtree(resolved)
        except OSError:
            logging.warning("Could not remove an abandoned sensitive VardrGate temp directory")


def _remove_private_job(directory: Path, path: Path) -> None:
    """Remove the one expected private job file and its now-empty directory."""
    path.unlink(missing_ok=True)
    directory.rmdir()


def _write_private_job(payload: dict) -> tuple[Path, Path]:
    """Write a VardrGate job into a user-private, crash-recoverable directory."""
    cleanup_sensitive_temp_dirs()
    directory = Path(tempfile.mkdtemp(prefix=f"{_SENSITIVE_TEMP_PREFIX}{os.getpid()}-")).resolve()
    path = directory / "job.json"
    try:
        if os.name != "nt":
            directory.chmod(stat.S_IRWXU)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            _remove_private_job(directory, path)
        except OSError as cleanup_error:
            raise ToolError(
                "could not remove incomplete sensitive VardrGate job data"
            ) from cleanup_error
        raise
    return path, directory


def _run_tool(cmd: list[str], temp_file: str | None, tool: str, timeout: int | None) -> None:
    """Run an allowlisted command with a timeout, always cleaning up the temp file.

    Raises ToolTimeout (after killing the process) if the run exceeds the limit.
    Raises ToolError on any non-zero exit code — callers must not treat failure as success.
    """
    seconds = _resolve_timeout(timeout)
    observer = _PROCESS_OBSERVER.get()
    try:
        process = _spawn_tool(cmd)
        if observer is not None:
            try:
                observer(process.pid)
            except Exception:
                _terminate_process_tree(process)
                raise
        try:
            returncode = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process)
            raise
    except subprocess.TimeoutExpired as e:
        raise ToolTimeout(
            f"{tool} timed out after {seconds}s and its process tree was killed"
        ) from e
    finally:
        if temp_file:
            Path(temp_file).unlink(missing_ok=True)
    if returncode != 0:
        raise ToolError(f"{tool} exited with code {returncode}")


def tool_available(name: str) -> bool:
    """Return True if the tool binary exists on PATH."""
    return shutil.which(ALLOWED_TOOLS.get(name, "")) is not None


# ProjectDiscovery tools use -version; nmap uses --version.
_VERSION_ARGS: dict[str, list[str]] = {
    "httpx": ["-version"],
    "nuclei": ["-version"],
    "subfinder": ["-version"],
    "dnsx": ["-version"],
    "naabu": ["-version"],
    "nmap": ["--version"],
}


def tool_version(name: str) -> str | None:
    """Return the version string for an installed tool, or None."""
    binary = ALLOWED_TOOLS.get(name, "")
    if not binary or not shutil.which(binary):
        return None
    args = _VERSION_ARGS.get(name, ["-version"])
    try:
        result = subprocess.run(
            [binary] + args, capture_output=True, text=True, timeout=5, check=False
        )
        output = (result.stdout or "") + (result.stderr or "")
        # Try vX.Y.Z first (ProjectDiscovery), then bare X.Y.Z (nmap-style).
        match = re.search(r"v\d+\.\d+\.\d+", output) or re.search(
            r"\b(\d+\.\d+(?:\.\d+)?)\b", output
        )
        return match.group(0) if match else "unknown"
    except Exception:
        return None


def check_tool(name: str) -> None:
    """Raise SystemExit with a helpful message if the tool is not installed."""
    if not tool_available(name):
        import typer

        raise typer.BadParameter(
            f"'{name}' not found on PATH. Install it and make sure it is executable.",
            param_hint=name,
        )


def strip_url_to_host(url: str) -> str:
    """Extract the hostname from a URL so nmap receives a hostname/IP, not a full URL.

    Examples:
        "https://app.example.com/path"  → "app.example.com"
        "http://10.0.0.1:8080"          → "10.0.0.1"
        "app.example.com"               → "app.example.com"  (already bare, unchanged)
    """
    stripped = url.strip()
    if not stripped:
        return stripped
    if "://" not in stripped:
        # Bare hostname/IP — no scheme to parse; return as-is
        return stripped.split("/")[0].split(":")[0]
    parsed = urllib.parse.urlparse(stripped)
    # hostname attribute lowercases and strips brackets from IPv6
    return parsed.hostname or stripped


def run_httpx(targets: list[str], output_path: Path, timeout: int | None = None) -> None:
    """Run httpx against a list of targets. Output is JSONL written to output_path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(targets))
        targets_file = tmp.name

    cmd = [
        ALLOWED_TOOLS["httpx"],
        "-l",
        targets_file,
        "-json",
        "-o",
        str(output_path),
        "-silent",
    ]
    return _run_tool(cmd, targets_file, "httpx", timeout)


def run_nuclei(
    targets: list[str],
    output_path: Path,
    severity: str | None = None,
    templates: str | None = None,
    timeout: int | None = None,
) -> None:
    """Run nuclei against a list of targets. Output is JSONL written to output_path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(targets))
        targets_file = tmp.name

    cmd = [
        ALLOWED_TOOLS["nuclei"],
        "-l",
        targets_file,
        "-json-export",
        str(output_path),
        "-silent",
    ]
    if severity:
        cmd += ["-severity", severity]
    if templates:
        cmd += ["-t", templates]

    return _run_tool(cmd, targets_file, "nuclei", timeout)


def run_nmap(
    targets: list[str],
    output_path: Path,
    top_ports: int = 100,
    timing: int = 3,
    timeout: int | None = None,
) -> None:
    """Run nmap with service detection against a list of targets.

    Safe profile only: --top-ports N, -sV with low intensity, -T{0-4}.
    Output is XML written to output_path. Never uses -A, -O, -p-, --script, or -T5.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(targets))
        targets_file = tmp.name

    safe_timing = max(0, min(4, timing))  # clamp 0-4; never allow T5
    cmd = [
        ALLOWED_TOOLS["nmap"],
        "-iL",
        targets_file,
        "--top-ports",
        str(top_ports),
        "-sV",
        "--version-intensity",
        "2",
        f"-T{safe_timing}",
        "-oX",
        str(output_path),
        "--open",
    ]
    return _run_tool(cmd, targets_file, "nmap", timeout)


def parse_nmap_xml(xml_path: Path) -> list[dict]:
    """Parse nmap XML output into a list of service dicts for the services API."""
    services: list[dict] = []
    try:
        tree = ET.parse(xml_path)  # nosec B314
        root = tree.getroot()
    except ET.ParseError:
        return services

    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        host_ip = addr_el.get("addr", "")

        hostname_el = host_el.find("hostnames/hostname[@type='user']")
        if hostname_el is None:
            hostname_el = host_el.find("hostnames/hostname")
        host_name = hostname_el.get("name", "") if hostname_el is not None else ""
        host = host_name or host_ip

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = int(port_el.get("portid", "0"))
            protocol = port_el.get("protocol", "tcp")
            svc_el = port_el.find("service")
            service_name = product = version = ""
            if svc_el is not None:
                service_name = svc_el.get("name", "")
                product = svc_el.get("product", "")
                version = svc_el.get("version", "")
            services.append(
                {
                    "host": host,
                    "port": portid,
                    "protocol": protocol,
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "state": "open",
                    "source": "nmap",
                }
            )
    return services


def run_subfinder(domains: list[str], output_path: Path, timeout: int | None = None) -> None:
    """Run subfinder against a list of root domains. Output is one host per line."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(domains))
        domains_file = tmp.name

    cmd = [
        ALLOWED_TOOLS["subfinder"],
        "-dL",
        domains_file,
        "-o",
        str(output_path),
        "-silent",
    ]
    return _run_tool(cmd, domains_file, "subfinder", timeout)


def run_dnsx(hosts: list[str], output_path: Path, timeout: int | None = None) -> None:
    """Resolve a list of hosts with dnsx. Output is the resolvable hosts, one per line."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(hosts))
        hosts_file = tmp.name

    cmd = [
        ALLOWED_TOOLS["dnsx"],
        "-l",
        hosts_file,
        "-o",
        str(output_path),
        "-silent",
    ]
    return _run_tool(cmd, hosts_file, "dnsx", timeout)


def run_naabu(
    hosts: list[str], output_path: Path, top_ports: int = 100, timeout: int | None = None
) -> None:
    """Port-scan a list of hosts with naabu (top-N ports). Output is JSON lines."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(hosts))
        hosts_file = tmp.name

    cmd = [
        ALLOWED_TOOLS["naabu"],
        "-list",
        hosts_file,
        "-top-ports",
        str(top_ports),
        "-json",
        "-o",
        str(output_path),
        "-silent",
    ]
    return _run_tool(cmd, hosts_file, "naabu", timeout)


def run_vardrgate(job: dict, output_path: Path, timeout: int | None = None) -> None:
    """Run a VardrGate API authorization test job locally.

    ``job`` is the VardrGate job envelope (``{"config": {"test_case": ..., "execution": ...}}``).
    It is written to a private temp file and passed to ``vardrgate run``; the sanitized
    result JSON is written to ``output_path``. Cleanup is verified before success returns.
    """
    job_file, job_dir = _write_private_job(job)

    cmd = [
        ALLOWED_TOOLS["vardrgate_api_test"],
        "run",
        "--job",
        str(job_file),
        "--out",
        str(output_path),
    ]
    active_error: BaseException | None = None
    try:
        return _run_tool(cmd, None, "vardrgate", timeout)
    except BaseException as exc:
        active_error = exc
        raise
    finally:
        try:
            _remove_private_job(job_dir, job_file)
        except OSError as cleanup_error:
            if active_error is None:
                raise ToolError("could not remove sensitive VardrGate job data") from cleanup_error
            logging.error("Could not remove sensitive VardrGate job data after a failed run")


def parse_naabu_json(json_path: Path) -> list[dict]:
    """Parse naabu JSON-lines output into service dicts for the services API."""
    services: list[dict] = []
    try:
        text = json_path.read_text()
    except OSError:
        return services

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        host = obj.get("host") or obj.get("ip")
        port = obj.get("port")
        if not host or not port:
            continue
        services.append(
            {
                "host": host,
                "port": int(port),
                "protocol": obj.get("protocol", "tcp"),
                "service_name": "",
                "product": "",
                "version": "",
                "state": "open",
                "source": "naabu",
            }
        )
    return services
