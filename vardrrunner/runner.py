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
import ssl
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from vardrrunner import config, configs, toolchain

# Allowlist maps subcommand names to their executable names.
# Add new tools here only — never allow arbitrary executables.
ALLOWED_TOOLS = {
    "httpx": "httpx",
    "nuclei": "nuclei",
    "subfinder": "subfinder",
    "nmap": "nmap",
    "dnsx": "dnsx",
    "naabu": "naabu",
    "katana": "katana",
    "gau": "gau",
    "ffuf": "ffuf",
    "dalfox": "dalfox",
    # Job type "vardrgate_api_test" maps to the "vardrgate" binary on PATH.
    "vardrgate_api_test": "vardrgate",
}

# Wall-clock ceiling for a single tool run. A hung tool must never freeze the
# daemon forever — the run is killed and the job marked failed. Override per run
# (job config `timeout`) or globally via the VARDRRUNNER_TOOL_TIMEOUT env var.
DEFAULT_TOOL_TIMEOUT = 1800  # 30 minutes

# dalfox's `--workers` is per target and it scans several targets at once, so the
# two multiply. Left at its defaults (50 and 50) a job could put 2,500 requests
# in flight at a client's host. Pinning the target half low keeps the operator's
# `worker` setting meaningful: the ceiling is `worker * this`.
DALFOX_MAX_CONCURRENT_TARGETS = 5

# dalfox's documented exit codes: 0 = scan completed, nothing found; 1 = scan
# completed, findings reported; 2 = input / configuration / runtime error (which
# also covers a run that could not finish cleanly). Only 0 and 1 are a completed
# scan. Observed on dalfox 3.2.4, not just read from the documentation: 0 on a page
# that reflects nothing, 1 on a reflected-XSS page, 2 on an unreachable target — which
# still writes a valid, empty report, so the report alone can never decide success.
# tests/test_smoke_dalfox.py (opt-in) pins all three against the real binary.
DALFOX_EXIT_CLEAN = 0
DALFOX_EXIT_FINDINGS = 1
DALFOX_OK_EXIT_CODES = (DALFOX_EXIT_CLEAN, DALFOX_EXIT_FINDINGS)
_SENSITIVE_TEMP_PREFIX = "vardrrunner-vardrgate-"


class ToolTimeout(Exception):
    """Raised when a tool subprocess exceeds its timeout. The process is killed."""


class ToolError(Exception):
    """Raised when a tool subprocess exits with a non-zero return code."""


def program(name: str) -> str:
    """The executable to run for an allowlisted tool.

    A verified managed install from ``~/.vardrmap/tools`` when there is one,
    otherwise the bare binary name so the OS resolves it on PATH, as before.
    A managed binary that fails verification raises ToolError and is never run.
    """
    try:
        return toolchain.resolve(name, ALLOWED_TOOLS[name])
    except toolchain.ToolchainError as exc:
        raise ToolError(str(exc)) from exc


def _is_managed_program(prog: str) -> bool:
    """True when ``prog`` is a managed install under ~/.vardrmap/tools, not a PATH name."""
    parent = Path(prog).parent
    if parent == Path("."):
        return False
    try:
        return parent.resolve() == config.tools_dir().resolve()
    except OSError:
        return False


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
    """Start a tool in a process group that can be terminated as one unit.

    stdin is always empty. ProjectDiscovery tools read extra targets from stdin
    whenever it is not a terminal, so inheriting a pipe that never closes (a
    supervisor, a script, CI) makes them wait forever. Targets always arrive in
    files, so no tool needs stdin.
    """
    if os.name == "nt":
        return subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,  # type: ignore[attr-defined]
        )
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL, start_new_session=True)


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
    _run_tool_status(cmd, temp_file, tool, timeout)


def _run_tool_status(
    cmd: list[str],
    temp_file: str | None,
    tool: str,
    timeout: int | None,
    ok_codes: tuple[int, ...] = (0,),
) -> int:
    """Run an allowlisted command and return its exit code, which must be in ``ok_codes``.

    ``_run_tool`` is this with ``ok_codes=(0,)``. A tool that uses its exit code to
    *report* something rather than only to signal failure needs more than 0 here —
    dalfox exits 1 for "scan succeeded, findings reported" — and the caller then
    reads the returned code. Any code outside ``ok_codes`` raises ToolError, so an
    unlisted code can never be mistaken for success.

    Raises ToolTimeout (after killing the process) if the run exceeds the limit.
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
    if returncode not in ok_codes:
        raise ToolError(f"{tool} exited with code {returncode}")
    return returncode


def _executable(name: str) -> str | None:
    """Resolved executable for ``name``, or None if it is missing or fails verification."""
    binary = ALLOWED_TOOLS.get(name, "")
    if not binary:
        return None
    try:
        return shutil.which(toolchain.resolve(name, binary))
    except toolchain.ToolchainError:
        return None


def tool_available(name: str) -> bool:
    """Return True if the tool is installed (verified managed copy, or on PATH)."""
    return _executable(name) is not None


# ProjectDiscovery tools use -version; nmap uses --version.
_VERSION_ARGS: dict[str, list[str]] = {
    "httpx": ["-version"],
    "nuclei": ["-version"],
    "subfinder": ["-version"],
    "dnsx": ["-version"],
    "naabu": ["-version"],
    "katana": ["-version"],
    "gau": ["--version"],
    "ffuf": ["-V"],
    "dalfox": ["--version"],
    "nmap": ["--version"],
}


def tool_version(name: str) -> str | None:
    """Return the version string for an installed tool, or None."""
    binary = _executable(name)
    if binary is None:
        return None
    args = _VERSION_ARGS.get(name, ["-version"])
    try:
        result = subprocess.run(
            [binary] + args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
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

        hint = (
            f"Run `vardrrunner tools install {name}`."
            if toolchain.manageable(name)
            else "Install it and make sure it is executable."
        )
        raise typer.BadParameter(f"'{name}' is not installed. {hint}", param_hint=name)


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


def base_url(target: str) -> str:
    """Reduce a target to the site root ffuf fuzzes under, or "" if it is unusable.

    Content discovery starts at the root, so a recon URL's path is dropped:
    "https://app.example.com/login" → "https://app.example.com". A bare host gets
    https, matching how the rest of the runner treats scope entries.

        "app.example.com"                → "https://app.example.com"
        "http://10.0.0.1:8080/a/b"       → "http://10.0.0.1:8080"
        "*.example.com"                  → ""   (a wildcard is not a host)
        "mailto:a@b.com"                 → ""   (not a web target)

    Anything that does not reduce to a plain http(s) host — and optional port —
    returns "" and is dropped by the caller. Two cases are worth naming, because
    both arrive in real recon and both survive a naive scheme prefix: a
    `mailto:`/`javascript:` entry parses as userinfo plus a host once "https://"
    is prepended, and a URL carrying credentials would otherwise have them
    replayed at the target. Neither is fuzzed.
    """
    stripped = target.strip().rstrip("/")
    if not stripped or "*" in stripped:
        return ""
    if "://" not in stripped:
        stripped = f"https://{stripped}"
    try:
        parsed = urllib.parse.urlparse(stripped)
        port = parsed.port  # raises ValueError on a non-numeric port
    except ValueError:
        return ""
    host = parsed.hostname
    if parsed.scheme not in ("http", "https") or not host:
        return ""
    if parsed.username or parsed.password:
        return ""
    if ":" in host:  # hostname drops IPv6 brackets; put them back
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}:{port}" if port else f"{parsed.scheme}://{host}"


def resolve_wordlist(name: str) -> Path:
    """The local file for a wordlist *name*, under ~/.vardrmap/wordlists.

    A job names a wordlist; it never supplies a path. The name's shape admits no
    separator (``configs.WORDLIST_NAME``), so it cannot climb out of this
    directory, and the parent is re-checked here as defence in depth. A symlink
    *inside* the directory is honoured — pointing `common.txt` at a SecLists file
    elsewhere is the operator's own decision, made on their own machine, and is
    not something the backend can influence.
    """
    if not configs.WORDLIST_NAME.match(name or ""):
        raise ToolError(f"{name!r} is not a valid wordlist name")
    directory = config.wordlists_dir()
    path = directory / f"{name}.txt"
    if path.parent != directory:
        raise ToolError(f"wordlist {name!r} would resolve outside {directory}")
    if not path.is_file():
        raise ToolError(
            f"wordlist {name!r} is not installed: expected {path}. Put a wordlist there "
            f"(a symlink to an existing one is fine) and queue the job again."
        )
    if path.stat().st_size == 0:
        raise ToolError(f"wordlist {name!r} is empty: {path}")
    return path


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Treat a redirect as an answer. ffuf does not follow redirects by default, so a
    3xx proves the host is up, and following it could fail on an unrelated second host."""

    def redirect_request(self, *args, **kwargs):
        return None


def _unverified_tls() -> ssl.SSLContext:
    """A TLS context that does not verify the server's certificate.

    **Matches pinned ffuf, which does not verify either** — checked against the real
    binary 2.3.0 with a self-signed certificate, an expired one and a hostname-
    mismatched one: it scanned all three and found the same paths. This probe asks
    "would ffuf be able to look?", so it must succeed wherever ffuf does. A verifying
    probe failed jobs on exactly the self-signed hosts pentests are full of, and an
    earlier revision of this code did so on the strength of an untested assumption.

    Safe here: the probe sends one GET with a fixed User-Agent and no credentials,
    cookies or request body, and trusts nothing it receives. A protocol-level failure
    (not speaking TLS at all, a failed handshake) still counts as unreachable.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def probe_reachable(url: str, timeout: float = 10.0) -> str | None:
    """Return None if ``url`` answers over HTTP, else a short reason it could not be reached.

    **Why this exists.** ffuf exits 0 and writes a valid, empty report for a host that
    refuses the connection — with ``-s``, ``-se`` and ``-sa`` alike — so neither the exit
    code nor the report can tell "there was nothing there" from "it could not look". A
    false "found nothing" in an engagement's record is worse than a failed job, so each
    target is checked once before it is fuzzed.

    **Any HTTP response counts as reachable**, including 404, 403, 500 and redirects: the
    question is only whether something answered. A connection error, timeout or failed
    TLS *handshake* is "unreachable". An untrusted certificate is not — see
    ``_unverified_tls``. Cost: one GET per target, identified by its User-Agent. It does
    not close the window between the probe and the fuzz, only the common case.
    """
    request = urllib.request.Request(
        url, method="GET", headers={"User-Agent": "VardrRunner-reachability-probe"}
    )
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_unverified_tls())
    )
    try:
        with opener.open(request, timeout=timeout):
            return None
    except urllib.error.HTTPError:
        return None  # the server answered; the status is not our concern here
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        return f"{reason.__class__.__name__}: {reason}"
    except (TimeoutError, OSError) as exc:
        return f"{exc.__class__.__name__}: {exc}"


def run_ffuf(
    target: str,
    output_path: Path,
    wordlist: Path,
    extensions: tuple[str, ...] = (),
    match_codes: str | None = None,
    rate: int = 50,
    timeout: int | None = None,
) -> None:
    """Fuzz one site root for content with ffuf. Output is ffuf's JSON report.

    One target per call, deliberately. ffuf can fuzz many hosts in a single run
    via its ``-w path:KEYWORD`` syntax, but a Windows wordlist path already
    contains a colon (``C:\\...``) and ffuf's own documentation does not say
    which colon separates the keyword. A bare ``-w <path>`` with ffuf's default
    ``FUZZ`` keyword is the canonical form and has no such ambiguity, so the
    handler loops instead. ``timeout`` therefore bounds each target, not the job.

    ``-ac`` (auto-calibration) is always on: a site that answers every path with
    200 would otherwise import thousands of phantom endpoints into shared recon.
    ``-rate`` is always passed — this is the one tool here that puts sustained
    load on a client's host, so its request rate is never left unbounded.
    """
    cmd = [
        program("ffuf"),
        "-w",
        str(wordlist),
        "-u",
        f"{target}/FUZZ",
        "-of",
        "json",
        "-o",
        str(output_path),
        "-rate",
        str(rate),
        "-ac",
        "-s",
        "-noninteractive",
    ]
    if extensions:
        cmd += ["-e", ",".join(extensions)]
    if match_codes:
        cmd += ["-mc", match_codes]
    return _run_tool(cmd, None, "ffuf", timeout)


def run_httpx(targets: list[str], output_path: Path, timeout: int | None = None) -> None:
    """Run httpx against a list of targets. Output is JSONL written to output_path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(targets))
        targets_file = tmp.name

    cmd = [
        program("httpx"),
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

    prog = program("nuclei")
    cmd = [
        prog,
        "-l",
        targets_file,
        "-json-export",
        str(output_path),
        "-silent",
    ]
    # For a managed nuclei, keep its templates under ~/.vardrmap/data so the whole
    # install lives in one place the operator can find and delete. A PATH nuclei is
    # left alone: it already has templates wherever the operator installed them, and
    # redirecting would force a fresh multi-hundred-MB download.
    if _is_managed_program(prog):
        template_dir = config.data_dir() / "nuclei-templates"
        template_dir.mkdir(parents=True, exist_ok=True)
        cmd += ["-update-template-dir", str(template_dir)]
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
        program("nmap"),
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
        program("subfinder"),
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
        program("dnsx"),
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
        program("naabu"),
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


def run_katana(
    targets: list[str],
    output_path: Path,
    depth: int = 3,
    js_crawl: bool = False,
    timeout: int | None = None,
) -> None:
    """Crawl a list of URLs with katana. Output is JSON lines.

    katana's default field scope keeps the crawl on each target's root domain, so
    a crawl does not wander onto third-party sites a page links to.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(targets))
        targets_file = tmp.name

    cmd = [
        program("katana"),
        "-list",
        targets_file,
        "-jsonl",
        "-o",
        str(output_path),
        "-depth",
        str(depth),
        "-silent",
        "-no-color",
        "-disable-update-check",
    ]
    if js_crawl:
        cmd.append("-js-crawl")
    return _run_tool(cmd, targets_file, "katana", timeout)


def run_gau(
    domains: list[str],
    output_path: Path,
    subs: bool = True,
    providers: tuple[str, ...] = (),
    timeout: int | None = None,
) -> None:
    """Fetch known URLs for domains from public archives with gau. Output is JSON lines.

    gau sends nothing to the target itself: it queries archive providers
    (Wayback Machine, Common Crawl, AlienVault OTX, urlscan) about it. It takes
    domains as arguments; target shape validation has already refused values
    that could be read as options.
    """
    cmd = [program("gau"), "--json", "--o", str(output_path)]
    if subs:
        cmd.append("--subs")
    if providers:
        cmd += ["--providers", ",".join(providers)]
    cmd += ["--", *domains]
    return _run_tool(cmd, None, "gau", timeout)


def run_dalfox(
    targets: list[str],
    output_path: Path,
    worker: int = 10,
    delay: int = 0,
    mining: bool = True,
    timeout: int | None = None,
) -> int:
    """Scan a list of URLs for XSS with dalfox. Output is its JSON report.

    **Returns dalfox's exit code, which carries information.** dalfox documents
    ``0`` as "success, no findings", ``1`` as "success, findings reported" and
    ``2`` as an input, configuration or runtime error. So ``0`` and ``1`` are both
    a completed scan and are returned for the caller to reconcile against the
    report; anything else — ``2`` included — raises ``ToolError``. Treating every
    non-zero exit as failure, as every other tool here rightly does, would fail a
    job exactly when dalfox succeeds in finding something.

    The exit code alone proves nothing about the report, and the report alone
    proves nothing about the exit code: ``DalfoxHandler.execute`` requires them to
    agree.

    Load is bounded in two places, because ``--workers`` is per *target* and
    dalfox scans several targets at once: left at its defaults (50 workers, 50
    concurrent targets) a job could have 2,500 requests in flight at a client's
    host. ``--max-concurrent-targets`` is therefore pinned low and the operator's
    ``worker`` setting caps the per-target half, so the ceiling is
    ``worker * MAX_CONCURRENT_TARGETS``. ``--delay`` (milliseconds, per worker)
    spaces requests out further.

    ``--include-all`` is deliberately never passed. It attaches the full request
    and response to every finding, and a response body from a client's
    application is not something to ship to the backend as a side effect of a
    scan. The report still carries the payload and the reflected evidence.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(targets))
        targets_file = tmp.name

    cmd = [
        program("dalfox"),
        "scan",
        "--input-type",
        "file",
        targets_file,
        "--format",
        "json",
        "--output",
        str(output_path),
        "--workers",
        str(worker),
        "--max-concurrent-targets",
        str(DALFOX_MAX_CONCURRENT_TARGETS),
        "--delay",
        str(delay),
        "--silence",
        "--no-color",
    ]
    if not mining:
        cmd.append("--skip-mining")
    return _run_tool_status(cmd, targets_file, "dalfox", timeout, ok_codes=DALFOX_OK_EXIT_CODES)


def run_vardrgate(job: dict, output_path: Path, timeout: int | None = None) -> None:
    """Run a VardrGate API authorization test job locally.

    ``job`` is the VardrGate job envelope (``{"config": {"test_case": ..., "execution": ...}}``).
    It is written to a private temp file and passed to ``vardrgate run``; the sanitized
    result JSON is written to ``output_path``. Cleanup is verified before success returns.
    """
    job_file, job_dir = _write_private_job(job)

    cmd = [
        program("vardrgate_api_test"),
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
