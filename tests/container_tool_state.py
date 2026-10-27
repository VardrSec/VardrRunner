"""Real image regression: Nuclei config is writable and survives replacement."""

import os
import subprocess
import sys
from pathlib import Path

from container_dnsx import check as check_dnsx

from vardrrunner import config, runner, toolchain

root = config.config_dir()
xdg_config, xdg_cache = [Path(os.environ[name]) for name in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME")]
assert os.getuid() == 10001
assert xdg_config == root and xdg_cache == root / "tool-cache"
assert (Path.home() / ".config").resolve() == root.resolve()
assert not os.access(config.tools_dir(), os.W_OK)
for name in ("katana", "dnsx", "naabu", "httpx", "subfinder", "ffuf"):
    assert toolchain.status(name, name).detail == "verified source build"
    assert (config.tools_dir() / "provenance" / name / "source.json").is_file()
result = subprocess.run(
    [runner.program("nuclei"), "-version"], capture_output=True, text=True, timeout=20
)
assert result.returncode == 0, result.stderr
assert (xdg_config / "nuclei").stat().st_uid == 10001
katana = subprocess.run(
    [runner.program("katana"), "-u", "http://127.0.0.1:1", "-duc", "-timeout", "1"],
    capture_output=True,
    text=True,
    timeout=20,
)
assert katana.returncode == 0 and "could not create runner" not in katana.stderr.lower(), (
    katana.stderr
)
assert (xdg_config / "katana" / "form-config.yaml").stat().st_uid == 10001
check_dnsx()
xdg_cache.mkdir(parents=True, exist_ok=True)
marker = xdg_cache / "replacement-check"
if sys.argv[1] == "create":
    marker.write_text("retained", encoding="utf-8")
else:
    assert sys.argv[1] == "check" and marker.read_text(encoding="utf-8") == "retained"
print(
    "PASS: real DNSx lookup, Nuclei config and persistent XDG state work as UID 10001; binaries remain immutable"
)
