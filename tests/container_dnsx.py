"""One real, bounded DNSx A lookup against an in-container synthetic resolver."""

import json
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor

from vardrrunner import runner


def check() -> None:
    question = b"\x08vardrsec\x04test\x00\x00\x01\x00\x01"
    with (
        ThreadPoolExecutor(max_workers=1) as pool,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver,
    ):
        resolver.bind(("127.0.0.1", 0))
        resolver.settimeout(5)

        def respond():
            query, peer = resolver.recvfrom(512)
            assert len(query) >= 12 + len(question) and query[4:6] == b"\x00\x01"
            assert query[12 : 12 + len(question)] == question
            response = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question
            response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4)
            resolver.sendto(response + socket.inet_aton("192.0.2.42"), peer)

        answer = pool.submit(respond)
        result = subprocess.run(
            [
                runner.program("dnsx"),
                "-l",
                "vardrsec.test",
                "-r",
                f"127.0.0.1:{resolver.getsockname()[1]}",
                "-a",
                "-j",
                "-silent",
                "-duc",
                "-t",
                "1",
                "-rl",
                "1",
                "-retry",
                "1",
                "-timeout",
                "2s",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        answer.result(timeout=5)
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    assert any(
        row.get("host") == "vardrsec.test" and row.get("a") == ["192.0.2.42"] for row in rows
    )


if __name__ == "__main__":
    check()
