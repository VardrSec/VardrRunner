"""Bounded native ARM64 probe; launch synthetic tests with an allowlisted environment."""

import ctypes
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import sysconfig
import xml.etree.ElementTree as ET


def main():
    source = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    assert os.name == "nt", "Requires Windows; Linux results cannot certify this probe"
    assert sys.version_info[:3] == (3, 14, 10)
    assert sysconfig.get_platform() == "win-arm64", "Emulated Python is excluded"
    assert platform.machine().lower() in {"arm64", "aarch64"}
    assert ctypes.sizeof(ctypes.c_void_p) == 8
    with open(sys.executable, "rb") as handle:
        handle.seek(0x3C)
        offset = struct.unpack("<I", handle.read(4))[0]
        handle.seek(offset)
        assert handle.read(4) == b"PE\0\0"
        machine = struct.unpack("<H", handle.read(2))[0]
        assert machine == 0xAA64, "Python executable must be ARM64 PE"

    allow = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE",
        "PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in allow}
    profile = output / "profile"
    profile.mkdir()
    for name in ("temp", "local", "roaming"):
        (profile / name).mkdir()
    env.update(
        USERPROFILE=str(profile), HOME=str(profile),
        TEMP=str(profile / "temp"), TMP=str(profile / "temp"),
        LOCALAPPDATA=str(profile / "local"), APPDATA=str(profile / "roaming"),
        PYTHONPATH=str(source), PYTHONNOUSERSITE="1", PYTHON_DOTENV_DISABLED="1",
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONUTF8="1",
    )
    files = [
        "test_execution_control.py", "test_windows_job_boundary.py", "test_runner.py",
        "test_recovery.py", "test_toolchain.py",
    ]
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *[f"tests/{name}" for name in files],
         "-q", "-o", "addopts=", f"--junitxml={output / 'tests.xml'}"],
        cwd=source, env=env, timeout=600, check=False,
    )
    receipt = {
        "python": platform.python_version(), "platform": sysconfig.get_platform(),
        "python_pe_machine": hex(machine), "os_version": platform.version(),
        "is_admin": bool(ctypes.windll.shell32.IsUserAnAdmin()),
        "scope": "synthetic owned Python processes and mocked unit boundaries",
        "pytest_exit_code": result.returncode,
        "docker_watchdog_gate": "FAILED/open; outside this probe",
    }
    (output / "runtime.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    assert result.returncode == 0, "Test failure remains a failure"
    cases = list(ET.parse(output / "tests.xml").getroot().iter("testcase"))
    native = [case for case in cases if case.get("classname", "").endswith("test_execution_control")
              and case.get("name", "").startswith((
                  "test_lease_expiring_during_native_launch_preparation",
                  "test_real_child_and_grandchild_termination",
                  "test_ordinary_exit_and_temp_cleanup",
                  "test_windows_contains_breakaway_attempt",
                  "test_windows_real_graceful_tree_and_owner_crash",
              ))]
    assert len(native) == 10, "All ten pinned native cases must be collected"
    assert all(len(case) == 0 for case in native), "Native cases must pass without skips"


if __name__ == "__main__":
    main()
