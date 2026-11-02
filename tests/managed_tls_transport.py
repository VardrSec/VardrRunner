"""Loopback test transport using the existing api.py client, never a runtime path."""

from types import SimpleNamespace
from urllib.parse import urlsplit

from vardrrunner.api import VardrMapClient


class FixtureTransport:
    def __init__(self, origin, token, ca_file, *, timeout=(1, 3)):
        parts = urlsplit(origin)
        assert parts.scheme == "https" and parts.hostname in {"localhost", "127.0.0.1"}
        self.client = VardrMapClient(origin, token, retries=0)
        self.failure_kind = None
        self.timeout = timeout
        # Instance-only policy: no production session defaults are changed.
        self.client.session.verify = str(ca_file)
        self.client.session.trust_env = False
        self.client.session.max_redirects = 0
        original = self.client.session.request

        def bounded_request(method, url, **kwargs):
            kwargs["timeout"] = self.timeout
            return original(method, url, **kwargs)

        self.client.session.request = bounded_request
        if not token:
            self.client.session.headers.pop("Authorization", None)

    def post(self, path, *, json):
        # All HTTP requests still originate in api.py. Its generic post returns
        # parsed JSON or raises; this adapts that existing result to the probe.
        try:
            payload = self.client.post(path, json=json)
        except Exception as error:
            self.failure_kind = type(error).__name__  # Never retain/log raw error or credentials.
            raise
        return SimpleNamespace(status_code=200, json=lambda: payload)

    def close(self):
        self.client.session.close()
