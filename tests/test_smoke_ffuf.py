"""Opt-in smoke test: the REAL ffuf binary, run through the real handler.

Everything else in this suite mocks the subprocess, which is how a wrong flag or a
misread exit code survives green tests. This runs the actual tool.

Opt-in, so a default `pytest` never launches a fuzzer:

    VARDRRUNNER_SMOKE=1 pytest tests/test_smoke_ffuf.py -v

Binary resolution: the normal managed install or PATH, or a directory given by
VARDRRUNNER_SMOKE_BIN_DIR. If ffuf cannot be found the tests skip with instructions
rather than failing.

Safety bounds (asserted, not just intended):
- the only target is a fixture server this test starts on 127.0.0.1;
- every request the fixture sees must come from loopback;
- the wordlist is a handful of names, the rate is capped, and traffic is capped by
  MAX_REQUESTS;
- every run is bounded by a 60s timeout.

This test found that ffuf exits 0 for an unreachable target, so the exit code cannot tell
"nothing there" from "could not look". The handler therefore probes each target first;
the last two tests pin both halves of that.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from vardrrunner import configs, handlers, runner

pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(
        os.environ.get("VARDRRUNNER_SMOKE") != "1",
        reason="opt-in: set VARDRRUNNER_SMOKE=1 to run tests against the real ffuf binary",
    ),
]

TOOL = "ffuf"
MAX_REQUESTS = 100  # observed: ~9 per run; this is a ceiling, not an expectation
RUN_TIMEOUT = 60
FOUND = {"admin": 200, "login": 200, "backup.bak": 403}


class _Site(BaseHTTPRequestHandler):
    """A tiny target: three real paths (one forbidden), everything else is a 404."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.seen.append((self.client_address[0], self.command, self.path))
        name = self.path.lstrip("/")
        status = FOUND.get(name, 404)
        body = b"forbidden" if status == 403 else (b"ok page" if status == 200 else b"")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Fixture:
    def __init__(self, server):
        self.server = server
        self.base = f"http://127.0.0.1:{server.server_address[1]}"

    def mark(self) -> int:
        return len(self.server.seen)

    def since(self, mark: int):
        return self.server.seen[mark:]


@pytest.fixture(scope="module")
def site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    server.seen = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield _Fixture(server)
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def dead_url():
    """A loopback port with nothing listening: connection refused, no network involved."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}"


@pytest.fixture(autouse=True)
def real_ffuf(monkeypatch):
    bindir = os.environ.get("VARDRRUNNER_SMOKE_BIN_DIR")
    if bindir:
        exe = Path(bindir) / (f"{TOOL}.exe" if os.name == "nt" else TOOL)
        if not exe.is_file():
            pytest.skip(f"{TOOL} not found in VARDRRUNNER_SMOKE_BIN_DIR ({bindir})")
        original = runner.program
        monkeypatch.setattr(
            runner, "program", lambda name: str(exe) if name == TOOL else original(name)
        )
    elif not runner.tool_available(TOOL):
        pytest.skip(
            f"{TOOL} is not installed. Run `vardrrunner tools install {TOOL}` "
            "or set VARDRRUNNER_SMOKE_BIN_DIR to a directory containing it."
        )


@pytest.fixture
def wordlist(monkeypatch, tmp_path):
    """Point the handler at a tiny wordlist, without touching ~/.vardrmap/wordlists."""

    def make(*words: str) -> Path:
        path = tmp_path / "smoke-words.txt"
        path.write_text("\n".join(words) + "\n")
        monkeypatch.setattr(runner, "resolve_wordlist", lambda name: path)
        return path

    return make


def _config() -> configs.FfufConfig:
    return configs.FfufConfig.from_dict({"rate": 50, "timeout": RUN_TIMEOUT})


def _assert_only_loopback_was_touched(site, mark):
    new = site.since(mark)
    assert len(new) <= MAX_REQUESTS, f"{len(new)} requests exceeds the {MAX_REQUESTS} ceiling"
    assert {client for client, _, _ in new} <= {"127.0.0.1"}
    assert {method for _, method, _ in new} == {"GET"}


def test_real_ffuf_finds_the_paths_and_the_handler_parses_them(site, wordlist, tmp_path):
    wordlist("admin", "login", "backup.bak", "nope-1", "nope-2")
    mark = site.mark()
    assert site.base.startswith("http://127.0.0.1:")

    out = handlers.REGISTRY[TOOL].execute([site.base], tmp_path, _config())

    records = [json.loads(line) for line in out.read_text().splitlines()]
    found = {r["input"]["FUZZ"]: r["status"] for r in records}
    # ffuf accepted every flag we pass (it ran), calibration dropped the 404s, and the
    # handler kept ffuf's own key spelling, which is what VardrMap's parser reads.
    assert found == FOUND
    for record in records:
        assert {"url", "input", "status", "length", "words", "lines", "content-type"} <= set(record)
    _assert_only_loopback_was_touched(site, mark)


def test_real_ffuf_with_no_matches_is_a_valid_empty_result(site, wordlist, tmp_path):
    wordlist("nope-1", "nope-2", "nope-3")
    mark = site.mark()

    out = handlers.REGISTRY[TOOL].execute([site.base], tmp_path, _config())

    assert out is None  # nothing to upload, and no error: the host really was looked at
    assert len(site.since(mark)) > 0, "a 'no matches' result must come from requests actually made"
    _assert_only_loopback_was_touched(site, mark)


def test_ffuf_exits_0_for_an_unreachable_target(site, dead_url, wordlist, tmp_path):
    """Pins the fact the next test depends on: the exit code cannot tell us.

    Observed on ffuf 2.3.0 with -s, -se and -sa alike. The run neither raises nor
    leaves any sign of failure, and the report is a perfectly valid empty one.
    """
    path = wordlist("admin", "login")
    mark = site.mark()
    report = tmp_path / "dead.json"

    runner.run_ffuf(dead_url, report, path, rate=50, timeout=RUN_TIMEOUT)  # does not raise

    assert json.loads(report.read_text())["results"] == []
    assert site.since(mark) == [], "the dead port must not have reached the fixture"


def test_an_unreachable_target_fails_the_job_instead_of_reporting_nothing_found(
    site, dead_url, wordlist, tmp_path
):
    """ffuf itself would report success with no results (previous test), so the handler's
    reachability probe is what turns that into a failure. Nothing is fuzzed."""
    wordlist("admin", "login")
    with pytest.raises(runner.ToolError, match="unreachable"):
        handlers.REGISTRY[TOOL].execute([dead_url], tmp_path, _config())


@pytest.mark.parametrize("kind", ["self-signed", "expired", "hostname-mismatch"])
def test_real_ffuf_scans_untrusted_https_and_the_probe_agrees(kind, wordlist, tmp_path):
    """Pinned ffuf does not verify TLS, so the reachability probe must not either.

    A verifying probe failed the job on every one of these hosts even though ffuf scans
    them without complaint: self-signed certificates are routine on the internal and
    staging hosts a pentest covers. This runs the real ffuf, so it is the check that the
    probe and the tool it guards actually agree.
    """
    pytest.importorskip("cryptography")
    from tests import tlsfixture

    wordlist("admin", "login", "nope-1")
    server, base = tlsfixture.https_server(_Site, kind)
    try:
        assert base.startswith("https://127.0.0.1:")
        assert runner.probe_reachable(base) is None, "the probe must accept what ffuf accepts"

        out = handlers.REGISTRY[TOOL].execute([base], tmp_path, _config())

        records = [json.loads(line) for line in out.read_text().splitlines()]
        assert {r["input"]["FUZZ"] for r in records} == {"admin", "login"}
        assert {client for client, _, _ in server.seen} <= {"127.0.0.1"}
        assert len(server.seen) <= MAX_REQUESTS
    finally:
        server.shutdown()
        server.server_close()
