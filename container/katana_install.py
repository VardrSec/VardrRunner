"""Register the image's checksum-verified Katana source build; not a user installer."""

import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from vardrrunner import config, toolchain

MODULE = "github.com/projectdiscovery/katana"
PATCHES = {
    "github.com/jackc/pgx/v5": "v5.9.2",
    "golang.org/x/net": "v0.60.0",
    "github.com/klauspost/compress": "v1.18.7",
}
COMPILER = "go1.27.3"


def install_source(source: Path) -> None:
    """Keep ordinary managed hash checks, with explicit source rather than archive origin."""
    names = ("katana", "katana.sha256", "build-info.txt", "go.mod", "go.sum")
    for name in names:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Source build artifact is missing or is a symlink")
        ceiling = toolchain.MAX_BINARY_BYTES if name == "katana" else 2 * 1024 * 1024
        if not 0 < path.stat().st_size <= ceiling:
            raise ValueError("Invalid source build artifact size")
    expected = (source / "katana.sha256").read_text(encoding="utf-8").split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Invalid builder binary checksum")
    actual = toolchain._sha256(source / "katana")
    if not toolchain._matches(actual, expected):
        raise ValueError("Source binary does not match the builder checksum")
    info = (source / "build-info.txt").read_text(encoding="utf-8")
    if info.splitlines()[0].split()[-1] != COMPILER:
        raise ValueError("Unexpected source compiler")
    modules = {}
    for line in info.splitlines()[1:]:
        fields = line.strip().split("\t")
        if fields[0] == "=>":
            raise ValueError("Unrecorded module replacement")
        if fields[0] in ("mod", "dep") and len(fields) == 4:
            if fields[1] in modules or not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", fields[3]):
                raise ValueError("Invalid source module checksum")
            modules[fields[1]] = {"version": fields[2], "checksum": fields[3]}
    entry = toolchain.load_manifest()["tools"]["katana"]
    root = modules.get(MODULE, {})
    if root.get("version") != "v" + entry["version"]:
        raise ValueError("Source version differs from the native tool pin")
    for name, version in PATCHES.items():
        if modules.get(name, {}).get("version") != version:
            raise ValueError("Required source dependency patch is missing")
    lock = toolchain._read_lock()
    target = config.tools_dir() / "katana"
    if "katana" in lock or target.exists():
        raise ValueError("Refuse to replace an existing managed Katana")
    config.tools_dir().mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".katana-source-", dir=config.tools_dir()) as temp:
        staged = Path(temp) / "katana"
        shutil.copyfile(source / "katana", staged)
        staged.chmod(0o755)
        if not toolchain._matches(toolchain._sha256(staged), expected):
            raise ValueError("Source binary changed while staging")
        toolchain._check_version(
            staged, "katana", entry["version"], entry.get("version_args", ["-version"])
        )
        provenance = config.tools_dir() / "provenance" / "katana"
        provenance.mkdir(parents=True, exist_ok=False)
        hashes = {}
        for name in ("go.mod", "go.sum", "build-info.txt"):
            shutil.copyfile(source / name, provenance / name)
            hashes[name] = hashlib.sha256((provenance / name).read_bytes()).hexdigest()
        origin = {
            "kind": "go-module-source",
            "module": MODULE,
            "compiler": COMPILER,
            "modules": modules,
            "provenance_sha256": hashes,
        }
        (provenance / "source.json").write_text(
            json.dumps(origin, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(staged, target)
        lock["katana"] = {
            "version": entry["version"],
            "platform": toolchain.platform_key(),
            "binary": "katana",
            "binary_sha256": expected,
            "origin": origin,
            "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        toolchain._write_lock(lock)


if __name__ == "__main__":
    if os.name != "posix" or os.getuid() != 0 or config.tools_dir() != Path("/opt/vardrtools"):
        raise SystemExit("This helper is restricted to the root image-build tools directory")
    install_source(Path("/tmp/katana-build"))
