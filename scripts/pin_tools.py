"""Maintainer script: generate or check vardrrunner/tool_manifest.json.

    python scripts/pin_tools.py                     # re-pin every tool at its current version
    python scripts/pin_tools.py --set httpx=1.12.0  # move one tool to a new version
    python scripts/pin_tools.py --check             # re-download every pinned asset; fail on drift

Pinning downloads every platform archive, hashes it locally, and requires that
hash to match the tool's own published checksums file, then confirms the archive
contains the expected binary. A pin is only written when both agree. ``--check``
is what the weekly CI job runs: a pinned archive whose hash has changed upstream
means a release was replaced after we pinned it, and is a failure, not an update.

Never hand-edit hashes in the manifest; changes go through this script and review.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vardrrunner import api, manifests, toolchain  # noqa: E402

MANIFEST = ROOT / "vardrrunner" / toolchain.MANIFEST_RESOURCE


@dataclass(frozen=True)
class Source:
    """Where a tool is released and how its archives are named."""

    repo: str
    # Manifest platform key → (OS, arch, archive suffix) as spelled in asset names.
    platforms: dict[str, tuple[str, str, str]]
    # The binary's own version flag, when it is not ``-version``.
    version_args: tuple[str, ...] = ()


# ProjectDiscovery: `{tool}_{version}_{os}_{arch}.zip`, with macOS spelled "macOS".
_PD = {
    "windows-amd64": ("windows", "amd64", ".zip"),
    "linux-amd64": ("linux", "amd64", ".zip"),
    "linux-arm64": ("linux", "arm64", ".zip"),
    "macos-amd64": ("macOS", "amd64", ".zip"),
    "macos-arm64": ("macOS", "arm64", ".zip"),
}
# GoReleaser defaults (gau): "darwin", and tar.gz everywhere except Windows.
_GORELEASER = {
    "windows-amd64": ("windows", "amd64", ".zip"),
    "linux-amd64": ("linux", "amd64", ".tar.gz"),
    "linux-arm64": ("linux", "arm64", ".tar.gz"),
    "macos-amd64": ("darwin", "amd64", ".tar.gz"),
    "macos-arm64": ("darwin", "arm64", ".tar.gz"),
}

# Binary name is the tool name for every current entry.
SOURCES: dict[str, Source] = {
    "httpx": Source("projectdiscovery/httpx", _PD),
    "nuclei": Source("projectdiscovery/nuclei", _PD),
    "subfinder": Source("projectdiscovery/subfinder", _PD),
    "dnsx": Source("projectdiscovery/dnsx", _PD),
    "naabu": Source("projectdiscovery/naabu", _PD),
    "katana": Source("projectdiscovery/katana", _PD),
    "gau": Source("lc/gau", _GORELEASER, version_args=("--version",)),
}


def _github(path: str) -> Any:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.get(f"https://api.github.com{path}", headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()


def _upstream_checksums(assets: list[dict[str, Any]], workdir: Path) -> dict[str, str]:
    """Parse the release's own ``*checksums.txt`` into {asset name: sha256}."""
    listing = [a for a in assets if a["name"].endswith("checksums.txt")]
    if len(listing) != 1:
        raise SystemExit("expected exactly one checksums file in the release")
    path = workdir / "checksums.txt"
    api.download_asset(listing[0]["browser_download_url"], path, max_bytes=1024 * 1024)
    sums: dict[str, str] = {}
    for line in path.read_text("utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            sums[parts[1].lstrip("*")] = parts[0]
    return sums


def _members(archive: Path) -> list[str]:
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as tf:
            return [m.name.removeprefix("./") for m in tf.getmembers() if m.isreg()]
    with zipfile.ZipFile(archive) as zf:
        return zf.namelist()


def pin(tool: str, version: str) -> dict[str, Any]:
    source = SOURCES[tool]
    repo = source.repo
    release = _github(f"/repos/{repo}/releases/tags/v{version}")
    assets = release["assets"]
    platforms: dict[str, dict[str, str]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        upstream = _upstream_checksums(assets, workdir)
        for key, (os_name, arch, suffix) in source.platforms.items():
            wanted = f"{tool}_{version}_{os_name}_{arch}{suffix}"
            match = [a for a in assets if a["name"] == wanted]
            if not match:
                print(f"  {tool} {version}: no {key} build ({wanted}); skipping")
                continue
            archive = workdir / wanted
            api.download_asset(
                match[0]["browser_download_url"], archive, max_bytes=toolchain.MAX_ARCHIVE_BYTES
            )
            digest, _ = manifests.artifact_digest(archive)
            if upstream.get(wanted) != digest:
                raise SystemExit(f"{wanted}: local hash does not match the upstream checksums file")
            member = f"{tool}.exe" if key.startswith("windows-") else tool
            if member not in _members(archive):
                raise SystemExit(f"{wanted} does not contain {member}")
            platforms[key] = {"url": match[0]["browser_download_url"], "sha256": digest}
            print(f"  {tool} {version} {key}: {digest}")
    entry: dict[str, Any] = {
        "version": version,
        "binary": tool,
        "source": f"https://github.com/{repo}/releases/tag/v{version}",
        "platforms": platforms,
    }
    if source.version_args:
        entry["version_args"] = list(source.version_args)
    return entry


def check(manifest: dict[str, Any]) -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for tool, entry in sorted(manifest["tools"].items()):
            for key, asset in sorted(entry["platforms"].items()):
                path = Path(tmp) / f"{tool}-{key}.zip"
                api.download_asset(asset["url"], path, max_bytes=toolchain.MAX_ARCHIVE_BYTES)
                digest, _ = manifests.artifact_digest(path)
                if digest != asset["sha256"]:
                    failures += 1
                    print(
                        f"DRIFT {tool} {entry['version']} {key}: pinned {asset['sha256']}, got {digest}"
                    )
                else:
                    print(f"ok    {tool} {entry['version']} {key}")
                path.unlink()
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--set", action="append", default=[], metavar="TOOL=VERSION")
    parser.add_argument("--check", action="store_true", help="verify pinned hashes; change nothing")
    args = parser.parse_args()

    current: dict[str, Any] = (
        json.loads(MANIFEST.read_text("utf-8"))
        if MANIFEST.exists()
        else {"schema_version": toolchain.SCHEMA_VERSION, "tools": {}}
    )
    if args.check:
        toolchain.validate_manifest(current)
        failures = check(current)
        print(f"{failures} drifted asset(s)")
        return 1 if failures else 0

    versions = {tool: e["version"] for tool, e in current["tools"].items()}
    for item in args.set:
        tool, _, version = item.partition("=")
        if tool not in SOURCES or not version:
            raise SystemExit(f"--set expects TOOL=VERSION for one of {sorted(SOURCES)}")
        versions[tool] = version.lstrip("v")
    missing = sorted(set(SOURCES) - set(versions))
    if missing:
        raise SystemExit(f"no version known for {missing}; pass --set TOOL=VERSION")

    tools = {}
    for tool in sorted(SOURCES):
        print(f"pinning {tool} {versions[tool]}")
        tools[tool] = pin(tool, versions[tool])
    manifest = {"schema_version": toolchain.SCHEMA_VERSION, "tools": tools}
    toolchain.validate_manifest(manifest)
    manifests.write_atomic_text(MANIFEST, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"wrote {MANIFEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
