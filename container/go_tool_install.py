"""Register the image's fixed, checksum-verified Go builds; not a user installer."""

import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from vardrrunner import config, toolchain

BUILDS = {
    "katana": {
        "module": "github.com/projectdiscovery/katana",
        "patches": {
            "github.com/jackc/pgx/v5": "v5.9.2",
            "golang.org/x/net": "v0.60.0",
            "github.com/klauspost/compress": "v1.18.7",
        },
    },
    "dnsx": {
        "module": "github.com/projectdiscovery/dnsx",
        "patches": {
            "golang.org/x/net": "v0.60.0",
            "github.com/klauspost/compress": "v1.18.7",
        },
    },
}
COMPILER = "go1.27.3"


def install_source(source: Path, name: str) -> None:
    """Keep ordinary managed hash checks, with explicit source rather than archive origin."""
    build = BUILDS[name]
    names = (name, name + ".sha256", "build-info.txt", "go.mod", "go.sum")
    for filename in names:
        path = source / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError("Source build artifact is missing or is a symlink")
        ceiling = toolchain.MAX_BINARY_BYTES if filename == name else 2 * 1024 * 1024
        if not 0 < path.stat().st_size <= ceiling:
            raise ValueError("Invalid source build artifact size")
    expected = (source / (name + ".sha256")).read_text(encoding="utf-8").split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Invalid builder binary checksum")
    actual = toolchain._sha256(source / name)
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
    entry = toolchain.load_manifest()["tools"][name]
    root = modules.get(build["module"], {})
    if root.get("version") != "v" + entry["version"]:
        raise ValueError("Source version differs from the native tool pin")
    for module, version in build["patches"].items():
        if modules.get(module, {}).get("version") != version:
            raise ValueError("Required source dependency patch is missing")
    lock = toolchain._read_lock()
    target = config.tools_dir() / name
    if name in lock or target.exists():
        raise ValueError("Refuse to replace an existing managed tool")
    config.tools_dir().mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{name}-source-", dir=config.tools_dir()) as temp:
        staged = Path(temp) / name
        shutil.copyfile(source / name, staged)
        staged.chmod(0o755)
        if not toolchain._matches(toolchain._sha256(staged), expected):
            raise ValueError("Source binary changed while staging")
        toolchain._check_version(
            staged, name, entry["version"], entry.get("version_args", ["-version"])
        )
        provenance = config.tools_dir() / "provenance" / name
        provenance.mkdir(parents=True, exist_ok=False)
        hashes = {}
        for filename in ("go.mod", "go.sum", "build-info.txt"):
            shutil.copyfile(source / filename, provenance / filename)
            hashes[filename] = hashlib.sha256((provenance / filename).read_bytes()).hexdigest()
        origin = {
            "kind": "go-module-source",
            "module": build["module"],
            "compiler": COMPILER,
            "modules": modules,
            "provenance_sha256": hashes,
        }
        (provenance / "source.json").write_text(
            json.dumps(origin, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(staged, target)
        lock[name] = {
            "version": entry["version"],
            "platform": toolchain.platform_key(),
            "binary": name,
            "binary_sha256": expected,
            "origin": origin,
            "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        toolchain._write_lock(lock)


if __name__ == "__main__":
    if os.name != "posix" or os.getuid() != 0 or config.tools_dir() != Path("/opt/vardrtools"):
        raise SystemExit("This helper is restricted to the root image-build tools directory")
    for name in BUILDS:
        install_source(Path("/tmp") / (name + "-build"), name)
