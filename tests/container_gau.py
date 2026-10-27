"""Real managed Gau -> Runner handler tests; only loopback synthetic providers."""

import json
import os
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from vardrrunner import config, configs, handlers, runner, toolchain


class Provider(BaseHTTPRequestHandler):
    requests = 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        Provider.requests += 1
        assert Provider.requests <= 16
        assert "api/v1/search/?q=domain:vardrsec.test" in self.path
        rows = (
            []
            if self.path.startswith("/empty/")
            else [
                {
                    "page": {"domain": "vardrsec.test", "url": "https://vardrsec.test/proof"},
                    "sort": [],
                },
                {
                    "page": {"domain": "vardrsec.test", "url": "https://vardrsec.test/filtered.js"},
                    "sort": [],
                },
            ]
        )
        body = (
            b"{"
            if self.path.startswith("/bad/")
            else json.dumps({"results": rows, "has_more": False}).encode()
        )
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RejectProxy(BaseHTTPRequestHandler):
    requests = 0

    def log_message(self, *args):
        pass

    def do_CONNECT(self):
        RejectProxy.requests += 1
        assert RejectProxy.requests <= 32
        self.send_response(502)  # Never forwards any provider traffic.
        self.send_header("Content-Length", "0")
        self.end_headers()


def check() -> None:
    assert os.geteuid() == 10001 and not os.access(config.tools_dir(), os.W_OK)
    assert toolchain.status("gau", "gau").detail == "verified source build; reviewed source patches"
    provenance = json.loads((config.tools_dir() / "provenance/gau/source.json").read_text())
    assert provenance["modules"]["github.com/lc/gau/v2"] == {"version": "(devel)", "checksum": None}
    assert set(provenance["source_patches"]) == {"flags", "worker", "main", "output"}
    fixture = Path("/tls-fixture")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), RejectProxy)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(fixture / "server.pem", fixture / "server-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threads = [
        threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        for s in (server, proxy)
    ]
    for thread in threads:
        thread.start()
    saved = {k: os.environ.get(k) for k in ("HOME", "SSL_CERT_FILE", "SSL_CERT_DIR")}
    checks = {}
    try:
        with tempfile.TemporaryDirectory(dir=config.config_dir()) as temporary:
            home = Path(temporary)
            os.environ["HOME"] = str(home)
            os.environ["SSL_CERT_DIR"] = str(home / "no-extra-roots")
            good = f"https://127.0.0.1:{server.server_port}/"
            cases = [
                ("untrusted", good, False, True, False, "urlscan"),
                ("explicit-trust", good, True, False, True, "urlscan"),
                (
                    "wrong-host",
                    f"https://localhost:{server.server_port}/",
                    True,
                    True,
                    False,
                    "urlscan",
                ),
                ("malformed", good + "bad/", True, True, False, "urlscan"),
                ("valid-empty", good + "empty/", True, False, False, "urlscan"),
                ("initialization", good, True, True, False, "commoncrawl"),
            ]
            for name, url, trust, fails, has_result, provider in cases:
                os.environ["SSL_CERT_FILE"] = str(fixture / "ca.pem") if trust else ""
                proxy_line = (
                    f'proxy="http://127.0.0.1:{proxy.server_port}"\n'
                    if name == "initialization"
                    else ""
                )
                (home / ".gau.toml").write_text(
                    'threads=1\ntimeout=2\nretries=0\nblacklist=[".js"]\n'
                    + proxy_line
                    + "[urlscan]\nhost="
                    + json.dumps(url)
                    + "\n",
                    encoding="utf-8",
                )
                output = home / name
                output.mkdir()
                cfg = configs.GauConfig.from_dict({"providers": [provider], "timeout": 15})
                try:
                    result = handlers.GauHandler().execute(["vardrsec.test"], output, cfg)
                except runner.ToolError:
                    assert fails, name
                    checks[name] = "failed through normal producing Runner path"
                else:
                    assert not fails and bool(result) == has_result, name
                    if result:
                        rows = [json.loads(line) for line in result.read_text().splitlines()]
                        assert rows == [{"url": "https://vardrsec.test/proof", "source": "gau"}]
                    checks[name] = "valid result" if result else "valid empty provider response"
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        for service in (server, proxy):
            service.shutdown()
            service.server_close()
        for thread in threads:
            thread.join(timeout=2)
    print(
        json.dumps(
            {"uid": 10001, "checks": checks, "network": "loopback only; proxy never forwards"}
        )
    )


if __name__ == "__main__":
    check()
