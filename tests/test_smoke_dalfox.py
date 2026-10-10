"""Opt-in smoke test: the REAL dalfox binary, run through the real handler.

Everything else in this suite mocks the subprocess, which is exactly how a wrong
flag or a misread exit code survives green tests. dalfox exits 1 when it *finds*
something, and a mocked `_run_tool` could never have shown that the job was being
failed at precisely that moment. This test runs the actual tool.

Opt-in, so a default `pytest` never launches a scanner:

    VARDRRUNNER_SMOKE=1 pytest tests/test_smoke_dalfox.py -v

Binary resolution: the normal managed install or PATH, or a directory given by
VARDRRUNNER_SMOKE_BIN_DIR. If dalfox cannot be found the tests skip with
instructions rather than failing.

Safety bounds (asserted, not just intended):
- the only target is a fixture server this test starts on 127.0.0.1;
- every request the fixture sees must come from loopback;
- concurrency is minimal (2 workers), parameter mining is off, and traffic is
  capped by MAX_REQUESTS;
- every run is bounded by a 60s timeout.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from vardrrunner import configs, handlers, runner

pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(
        os.environ.get("VARDRRUNNER_SMOKE") != "1",
        reason="opt-in: set VARDRRUNNER_SMOKE=1 to run tests against the real dalfox binary",
    ),
]

TOOL = "dalfox"
MAX_REQUESTS = 300  # observed: ~25-35 per run; this is a ceiling, not an expectation
RUN_TIMEOUT = 60
KNOWN_METHODS = {"reflection", "dom-verification", "ast", "oob", "library"}


class _Site(BaseHTTPRequestHandler):
    """A tiny target: one page that reflects ?q= unescaped, one that ignores it."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.seen.append((self.client_address[0], self.command, self.path))
        parts = urlsplit(self.path)
        q = parse_qs(parts.query).get("q", [""])[0]
        if parts.path == "/vuln":
            body = f"<html><body>You searched for: {q}</body></html>"  # deliberately unsafe
        elif parts.path == "/escaped":
            body = f"<html><body>You searched for: {escape(q)}</body></html>"
        else:
            body = "<html><body>nothing is reflected here</body></html>"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture(scope="module")
def site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield SimpleSite(server)
    finally:
        server.shutdown()
        server.server_close()


class SimpleSite:
    def __init__(self, server):
        self.server = server
        self.base = f"http://127.0.0.1:{server.server_address[1]}"

    @property
    def seen(self):
        return self.server.seen

    def mark(self) -> int:
        return len(self.server.seen)

    def since(self, mark: int):
        return self.server.seen[mark:]


@pytest.fixture
def dead_url():
    """A loopback port with nothing listening: connection refused, no network involved."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}"


@pytest.fixture(autouse=True)
def real_dalfox(monkeypatch):
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


def _config() -> configs.DalfoxConfig:
    return configs.DalfoxConfig.from_dict(
        {"worker": 2, "delay": 0, "mining": False, "timeout": RUN_TIMEOUT}
    )


def _assert_only_loopback_was_touched(site, mark):
    new = site.since(mark)
    assert len(new) <= MAX_REQUESTS, f"{len(new)} requests exceeds the {MAX_REQUESTS} ceiling"
    assert {client for client, _, _ in new} <= {"127.0.0.1"}
    assert {method for _, method, _ in new} <= {"GET", "POST", "HEAD"}


def test_a_vulnerable_page_exits_1_and_the_report_is_usable(site, tmp_path):
    mark = site.mark()
    target = f"{site.base}/vuln?q=hello"
    assert target.startswith("http://127.0.0.1:")

    code = runner.run_dalfox(
        [target], tmp_path / "direct.json", worker=2, delay=0, mining=False, timeout=RUN_TIMEOUT
    )
    # dalfox's documented "success, findings reported". The old handler failed here.
    assert code == runner.DALFOX_EXIT_FINDINGS == 1

    out = handlers.REGISTRY[TOOL].execute([target], tmp_path, _config())
    report = json.loads(out.read_text())
    findings = report["findings"]
    assert findings, "exit 1 must come with findings in the report"

    first = findings[0]
    assert first["type"] in {"V", "R", "A", "I"}
    assert first["detection_method"] in KNOWN_METHODS
    assert first["confidence"] in {"high", "low"}
    assert first["param"] == "q"
    assert first["inject_type"]
    # --include-all is never passed, so no request or response body is in the report.
    assert "request" not in first and "response" not in first
    assert report["meta"]["incomplete"] is False
    _assert_only_loopback_was_touched(site, mark)


def test_a_clean_page_exits_0_with_a_valid_empty_report(site, tmp_path):
    mark = site.mark()
    target = f"{site.base}/static?q=1"

    code = runner.run_dalfox(
        [target], tmp_path / "direct.json", worker=2, delay=0, mining=False, timeout=RUN_TIMEOUT
    )
    assert code == runner.DALFOX_EXIT_CLEAN == 0

    out = handlers.REGISTRY[TOOL].execute([target], tmp_path, _config())
    assert json.loads(out.read_text())["findings"] == []
    assert handlers._read_dalfox_findings(out) == []
    _assert_only_loopback_was_touched(site, mark)


def test_an_unreachable_target_fails_the_job(site, dead_url, tmp_path):
    """dalfox exits 2 here. It also writes a perfectly valid, empty report.

    That is the case that makes "a report exists" worthless as evidence of success:
    reading the file alone, this looks identical to a clean scan.
    """
    mark = site.mark()
    with pytest.raises(runner.ToolError, match="exited with code 2"):
        handlers.REGISTRY[TOOL].execute([f"{dead_url}/?q=1"], tmp_path, _config())
    assert site.since(mark) == [], "the dead port must not have reached the fixture"
