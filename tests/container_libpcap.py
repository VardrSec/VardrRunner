"""Bounded offline libpcap interpreter checks; never opens a capture device."""

import ctypes
import ctypes.util
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


class Instruction(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint), ("instructions", ctypes.POINTER(Instruction))]


class Timeval(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_long)]


class Header(ctypes.Structure):
    _fields_ = [("timestamp", Timeval), ("caplen", ctypes.c_uint32), ("length", ctypes.c_uint32)]


CASES = {
    "accept_control": ([(0x06, 65535)], 65535),
    "valid_scratch_control": ([(0x00, 7), (0x02, 15), (0x60, 15), (0x16, 0)], 7),
    "invalid_load": ([(0x60, 16), (0x06, 1)], 0),
    "invalid_load_x": ([(0x61, 16), (0x06, 1)], 0),
    "invalid_store": ([(0x02, 16), (0x06, 1)], 0),
    "invalid_store_x": ([(0x03, 16), (0x06, 1)], 0),
    "backward_jump": ([(0x05, 0xFFFFFFFF), (0x06, 1)], 0),
}


def run_case(name):
    # Limits apply before loading native code. Each case has a separate process.
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    library = ctypes.util.find_library("pcap")
    if not library:
        raise RuntimeError("libpcap unavailable")
    lib = ctypes.CDLL(library)
    lib.pcap_offline_filter.argtypes = [
        ctypes.POINTER(Program),
        ctypes.POINTER(Header),
        ctypes.POINTER(ctypes.c_ubyte),
    ]
    lib.pcap_offline_filter.restype = ctypes.c_uint
    lib.pcap_lib_version.restype = ctypes.c_char_p
    pairs, expected = CASES[name]
    instructions = (Instruction * len(pairs))(*(Instruction(code, 0, 0, k) for code, k in pairs))
    program = Program(len(pairs), instructions)
    packet = (ctypes.c_ubyte * 1)(0)
    header = Header(Timeval(0, 0), 1, 1)
    result = lib.pcap_offline_filter(ctypes.byref(program), ctypes.byref(header), packet)
    if result != expected:
        raise RuntimeError(f"{name}: expected {expected}, got {result}")
    mapped = {
        Path(line.split()[-1]).resolve()
        for line in Path("/proc/self/maps").read_text().splitlines()
        if "/libpcap.so" in line and line.split()[-1].startswith("/")
    }
    if len(mapped) != 1:
        raise RuntimeError("Cannot bind the loaded libpcap to exactly one file")
    path = mapped.pop()
    return {
        "case": name,
        "result": result,
        "library": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "version": lib.pcap_lib_version().decode(),
    }


def main():
    if sys.argv[1:2] == ["--case"]:
        print(json.dumps(run_case(sys.argv[2])))
        return
    results = []
    for name in CASES:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--case", name],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        results.append(json.loads(result.stdout))
    identities = {(r["library"], r["sha256"], r["version"]) for r in results}
    if len(identities) != 1:
        raise RuntimeError("Library identity changed between checks")
    package = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package} ${Version} ${Architecture}\\n", "libpcap0.8t64"],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    ).stdout.strip()
    print(
        json.dumps(
            {
                "uid": os.getuid(),
                "package": package,
                "scope": "offline interpreter only; no capture or network",
                "cases": results,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
