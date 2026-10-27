"""Register the image's fixed, checksum-verified Go builds; not a user installer."""

import hashlib
import json
import os
import re
import shutil
import sys
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
BUILDS["naabu"] = {
    "module": "github.com/projectdiscovery/naabu/v2",
    "patches": {
        "golang.org/x/net": "v0.60.0",
        "golang.org/x/crypto": "v0.57.0",
        "github.com/klauspost/compress": "v1.18.7",
    },
}
COMPILER = "go1.27.3"
BUILDS["gau"] = {
    "module": "github.com/lc/gau/v2",
    "patches": {
        "golang.org/x/net": "v0.60.0",
        "github.com/klauspost/compress": "v1.18.7",
        "github.com/sirupsen/logrus": "v1.9.3",
        "github.com/valyala/fasthttp": "v1.34.0",
    },
}
GAU_UPSTREAM = {
    "Path": "github.com/lc/gau/v2",
    "Version": "v2.2.4",
    "Sum": "h1:FKPek3tA4fSp/hFgM9NILpGUbC1ArKKab1KQGpNfxAQ=",
    "GoModSum": "h1:FeFAGvk2jn/xJ7fybHbhDax2Cn8ZnJQDykcuk3YfYj4=",
}
GAU_COMMIT = "5d4e1270e632732756fe98717520c43c86e8bd18"
GAU_UPSTREAM_FILES = {
    "upstream.go.mod": "982ee88fe43695f9572412857c36383bca91fa171521d9947fe9bbda717bcf90",
    "upstream.go.sum": "f520c530be233daa5dc23363e6fbf6aab3d214d4d33441cc6e001cf58308b3a9",
    "upstream.LICENSE": "2bc98dc696486599c0b0588972238256e567bc2639fd2a06372f5059f9f84e74",
}
GAU_PATCHES = {
    "output": {
        "path": "pkg/output/output.go",
        "before": "aa5ced1c3bcceee8a1d650a51fefd21e4f6be79ed9f5a9d92ad1e1612c8d65a0",
        "after": "88872a42f12d2ef7d189f6682cdb793f65ea132ff2666171c4e71b8857fdabef",
        "old": "if blacklistMap.Contains(strings.ToLower(path.Ext(u.Path))) {",
        "new": 'if path.Ext(u.Path) != "" && blacklistMap.Contains(strings.ToLower(path.Ext(u.Path))) {',
    },
    "flags": {
        "path": "runner/flags/flags.go",
        "before": "57336a02675b6f563b047dadf5fbb0c03206bb553ffc6f5d2b568713d268386d",
        "after": "929bf9179ae08a1bb0d45c5b51f09b770d8d5b0e7a333353efae88728769e70b",
        "old": "InsecureSkipVerify: true,",
        "new": "InsecureSkipVerify: false,",
    },
    "worker": {
        "path": "runner/runner.go",
        "before": "c8c66c037e46abb7b65de9a818ea2b9c5fc0e7c33c898e61178240b4e27f2e63",
        "after": "f4793ef4446d3bc9befa69d45f6598912d08ad3dd5573f625f5713a00ba24949",
        "old": '.Warnf("%s - %v", work.domain, err)',
        "new": '.Fatalf("%s - %v", work.domain, err)',
    },
    "main": {
        "path": "cmd/gau/main.go",
        "before": "c3fcdbbab1f843a1ee18848712310d4b4ec7cce50a3cf6c092b75c9f07dd0384",
        "after": "6c8a687107748eab762e94a7fb1ccf401ca99413487f406d8eba5c8dc291ff1f",
        "old": "log.Warn(err)",
        "new": "log.Fatal(err)",
    },
}


def check_files(source: Path, names, binary: str = "") -> None:
    for name in names:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Source build artifact is missing or is a symlink")
        ceiling = toolchain.MAX_BINARY_BYTES if name == binary else 2 * 1024 * 1024
        if not 0 < path.stat().st_size <= ceiling:
            raise ValueError("Invalid source build artifact size")


def gau_files() -> tuple[str, ...]:
    return (
        "upstream-module.json",
        "upstream.go.mod",
        "upstream.go.sum",
        "upstream.LICENSE",
    ) + tuple(f"{name}.{kind}.go" for name in GAU_PATCHES for kind in ("original", "patched"))


def gau_upstream(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or any(data.get(k) != v for k, v in GAU_UPSTREAM.items()):
        raise ValueError("Unexpected Gau upstream module identity")
    if not isinstance(data.get("Origin"), dict) or data["Origin"].get("Hash") != GAU_COMMIT:
        raise ValueError("Unexpected Gau source revision")
    return {**GAU_UPSTREAM, "commit": GAU_COMMIT}


def gau_provenance(source: Path) -> dict:
    check_files(source, gau_files())
    upstream = gau_upstream(source / "upstream-module.json")
    if any(
        toolchain._sha256(source / name) != digest for name, digest in GAU_UPSTREAM_FILES.items()
    ):
        raise ValueError("Gau upstream module files or license differ from review")
    for name, patch in GAU_PATCHES.items():
        before = (source / f"{name}.original.go").read_bytes()
        after = (source / f"{name}.patched.go").read_bytes()
        if (
            hashlib.sha256(before).hexdigest() != patch["before"]
            or hashlib.sha256(after).hexdigest() != patch["after"]
        ):
            raise ValueError("Gau source patch hash differs from review")
        old, new = patch["old"].encode(), patch["new"].encode()
        if before.count(old) != 1 or after != before.replace(old, new):
            raise ValueError("Gau source patch differs from the single reviewed substitution")
    return {
        "upstream_module": upstream,
        "upstream_files_sha256": dict(GAU_UPSTREAM_FILES),
        "source_patches": GAU_PATCHES,
    }


def patch_gau(build: Path) -> None:
    """Patch only four hash-pinned files in the verified downloaded source copy."""
    check_files(build, ("upstream-module.json",))
    gau_upstream(build / "upstream-module.json")
    source, provenance = build / "source", build / "provenance"
    check_files(source, ("go.mod", "go.sum", "LICENSE", *(p["path"] for p in GAU_PATCHES.values())))
    provenance.mkdir()
    shutil.copyfile(build / "upstream-module.json", provenance / "upstream-module.json")
    for name in ("go.mod", "go.sum", "LICENSE"):
        if toolchain._sha256(source / name) != GAU_UPSTREAM_FILES["upstream." + name]:
            raise ValueError("Gau upstream module files or license differ from review")
        shutil.copyfile(source / name, provenance / ("upstream." + name))
    for name, patch in GAU_PATCHES.items():
        path = source / patch["path"]
        original = path.read_bytes()
        if (
            hashlib.sha256(original).hexdigest() != patch["before"]
            or original.count(patch["old"].encode()) != 1
        ):
            raise ValueError("Gau source differs from the reviewed upstream file")
        patched = original.replace(patch["old"].encode(), patch["new"].encode())
        if hashlib.sha256(patched).hexdigest() != patch["after"]:
            raise ValueError("Unexpected Gau source patch")
        (provenance / f"{name}.original.go").write_bytes(original)
        (provenance / f"{name}.patched.go").write_bytes(patched)
        path.write_bytes(patched)
    gau_provenance(provenance)


def install_source(source: Path, name: str) -> None:
    """Keep ordinary managed hash checks, with explicit source rather than archive origin."""
    build = BUILDS[name]
    names = (name, name + ".sha256", "build-info.txt", "go.mod", "go.sum")
    check_files(source, names, binary=name)
    supplement = gau_provenance(source) if name == "gau" else {}
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
        if name == "gau" and fields == ["mod", build["module"], "(devel)"]:
            if fields[1] in modules:
                raise ValueError("Duplicate source module")
            modules[fields[1]] = {"version": "(devel)", "checksum": None}
        if fields[0] in ("mod", "dep") and len(fields) == 4:
            if fields[1] in modules or not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", fields[3]):
                raise ValueError("Invalid source module checksum")
            modules[fields[1]] = {"version": fields[2], "checksum": fields[3]}
    entry = toolchain.load_manifest()["tools"][name]
    root = modules.get(build["module"], {})
    version = "(devel)" if name == "gau" else "v" + entry["version"]
    if root.get("version") != version or (
        name == "gau" and "v" + entry["version"] != GAU_UPSTREAM["Version"]
    ):
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
        for filename in ("go.mod", "go.sum", "build-info.txt") + (
            gau_files() if name == "gau" else ()
        ):
            shutil.copyfile(source / filename, provenance / filename)
            hashes[filename] = hashlib.sha256((provenance / filename).read_bytes()).hexdigest()
        origin = {
            "kind": "go-module-source",
            "module": build["module"],
            "compiler": COMPILER,
            "modules": modules,
            "provenance_sha256": hashes,
            **supplement,
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
    if sys.argv[1:] == ["--patch-gau"]:
        patch_gau(Path("/build"))
    elif not sys.argv[1:]:
        for name in BUILDS:
            install_source(Path("/tmp") / (name + "-build"), name)
    else:
        raise SystemExit("Unsupported image-build operation")
