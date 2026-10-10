"""Throwaway HTTPS servers with deliberately untrustworthy certificates, for tests.

The certificate and key are generated at test time into a temp directory and deleted
straight after loading, so no private key is ever committed (a committed key would also,
rightly, trip the secret scanner). Needs the `cryptography` package, a dev-only
dependency; callers use ``pytest.importorskip("cryptography")``.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Each is a certificate a verifying client rejects and ffuf scans anyway.
KINDS = ("self-signed", "expired", "hostname-mismatch")


def _write_cert(kind: str, directory: Path) -> tuple[Path, Path]:
    now = dt.datetime.now(dt.timezone.utc)
    start, end = now - dt.timedelta(days=1), now + dt.timedelta(days=30)
    common_name, san = "localhost", ["127.0.0.1"]
    if kind == "expired":
        start, end = now - dt.timedelta(days=60), now - dt.timedelta(days=30)
    elif kind == "hostname-mismatch":
        common_name, san = "other.example", []
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # its own issuer: self-signed, trusted by nobody
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip)) for ip in san]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def https_server(handler: type[BaseHTTPRequestHandler], kind: str = "self-signed"):
    """Start an HTTPS server on 127.0.0.1 and return ``(server, base_url)``.

    The caller shuts it down. ``server.seen`` is an empty list handlers may append to.
    """
    assert kind in KINDS, kind
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.seen = []
    with tempfile.TemporaryDirectory() as tmp:
        cert_path, key_path = _write_cert(kind, Path(tmp))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"https://127.0.0.1:{server.server_address[1]}"
