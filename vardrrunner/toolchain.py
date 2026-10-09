"""Pinned, verified installs of the tools VardrRunner executes.

Every tool VardrRunner can install is pinned in ``tool_manifest.json``, shipped
inside this package: an exact version and, per platform, a release archive URL
and its SHA-256. The hash comes from this package, never from the download site,
so tampering with a tool's release page is not enough to get a modified binary
installed — the attested VardrRunner release would have to be compromised too.

Installs land in ``~/.vardrmap/tools`` beside a receipt (``tools.lock.json``)
recording the SHA-256 of each installed binary. ``resolve`` re-hashes a managed
binary before it is first executed in a process and refuses to run one that no
longer matches its receipt. Tools without a managed install fall back to PATH,
which ``status`` reports as unverified.

Installation never runs a shell, never extracts anything but the one expected
file, and never leaves a half-written binary in place: the archive is verified
before it is opened, the binary is staged, version-checked, then moved into
place in a single rename.
"""

from __future__ import annotations

import hmac
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import IO, Any

from vardrrunner import api, config, manifests

MANIFEST_RESOURCE = "tool_manifest.json"
LOCK_NAME = "tools.lock.json"
SCHEMA_VERSION = 1

# Generous ceilings: the largest pinned archive today is well under 100 MB.
MAX_ARCHIVE_BYTES = 250 * 1024 * 1024
MAX_BINARY_BYTES = 400 * 1024 * 1024
_VERSION_TIMEOUT = 15

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# A version flag is a bare option, never a value: `-version`, `--version`.
_FLAG = re.compile(r"^-{1,2}[a-z][a-z-]*$")
_ARCHIVE_SUFFIXES = (".zip", ".tar.gz")
# A path inside an archive: relative, forward slashes, no drive, no climbing.
_MEMBER = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]*(?:/[A-Za-z0-9._][A-Za-z0-9._-]*)*$")


class ToolchainError(RuntimeError):
    """A managed tool could not be installed, removed, or resolved."""


class ToolIntegrityError(ToolchainError):
    """A managed tool binary does not match the hash recorded when it was installed."""


@dataclass(frozen=True)
class ToolStatus:
    name: str
    # "managed" (installed here and verified), "tampered" (installed here, hash
    # mismatch), "path" (unmanaged copy on PATH), "missing", or "system" (not
    # installable by VardrRunner — e.g. nmap — and found or not on PATH).
    source: str
    path: str | None
    installed_version: str | None
    pinned_version: str | None
    detail: str


# ── manifest ────────────────────────────────────────────────────────────────


_manifest_cache: dict[str, Any] | None = None


def load_manifest() -> dict[str, Any]:
    """Load and validate the pinned manifest shipped with this package."""
    global _manifest_cache
    if _manifest_cache is None:
        text = resources.files("vardrrunner").joinpath(MANIFEST_RESOURCE).read_text("utf-8")
        _manifest_cache = validate_manifest(json.loads(text))
    return _manifest_cache


def validate_manifest(data: Any) -> dict[str, Any]:
    """Reject a manifest that is malformed or pins anything but HTTPS URLs and SHA-256s."""
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ToolchainError("tool manifest has an unsupported schema")
    tools = data.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise ToolchainError("tool manifest lists no tools")
    for name, entry in tools.items():
        if not isinstance(entry, dict):
            raise ToolchainError(f"tool manifest entry for {name} is not an object")
        if not isinstance(entry.get("version"), str) or not entry["version"]:
            raise ToolchainError(f"tool manifest entry for {name} has no version")
        if not isinstance(entry.get("binary"), str) or not re.fullmatch(
            r"[a-z0-9_-]+", entry["binary"]
        ):
            raise ToolchainError(f"tool manifest entry for {name} has an invalid binary name")
        version_args = entry.get("version_args", ["-version"])
        if (
            not isinstance(version_args, list)
            or not version_args
            or not all(isinstance(a, str) and _FLAG.match(a) for a in version_args)
        ):
            raise ToolchainError(f"tool manifest entry for {name} has invalid version_args")
        platforms = entry.get("platforms")
        if not isinstance(platforms, dict) or not platforms:
            raise ToolchainError(f"tool manifest entry for {name} lists no platforms")
        for key, asset in platforms.items():
            if not isinstance(asset, dict):
                raise ToolchainError(f"{name} {key}: asset is not an object")
            url, digest = asset.get("url"), asset.get("sha256")
            if not isinstance(url, str) or not url.startswith("https://"):
                raise ToolchainError(f"{name} {key}: asset URL must be HTTPS")
            if not url.endswith(_ARCHIVE_SUFFIXES):
                raise ToolchainError(f"{name} {key}: asset must be a .zip or .tar.gz archive")
            if not isinstance(digest, str) or not _HEX64.match(digest):
                raise ToolchainError(f"{name} {key}: asset sha256 is not a SHA-256 hex digest")
            _validate_member(name, key, entry["binary"], asset)
    return data


def _validate_member(name: str, key: str, binary: str, asset: dict[str, Any]) -> None:
    """Check an asset's optional ``member``: where the binary sits in the archive.

    Most tools ship the binary at the archive root, which is the default. dalfox
    nests it one directory down, so the path is recorded in the manifest rather
    than discovered at install time — extraction stays "copy exactly this named
    entry", which is what makes traversal names elsewhere in the archive inert.

    The path must be relative, must use forward slashes, must not climb, and
    must end in the binary this entry installs, so a ``member`` cannot redirect
    the install to some other file that happens to be in the archive.
    """
    member = asset.get("member")
    if member is None:
        return
    expected = _member_name(binary, key)
    if not isinstance(member, str) or not member or not _MEMBER.match(member):
        raise ToolchainError(f"{name} {key}: member must be a relative path inside the archive")
    if ".." in member.split("/") or member.startswith("/"):
        raise ToolchainError(f"{name} {key}: member must not climb out of the archive")
    if member.split("/")[-1] != expected:
        raise ToolchainError(f"{name} {key}: member must end in {expected}")


def manageable(name: str) -> bool:
    """True when VardrRunner can install ``name`` itself."""
    return name in load_manifest()["tools"]


def manageable_tools() -> list[str]:
    return sorted(load_manifest()["tools"])


def platform_key() -> str:
    """This machine's manifest platform key, e.g. ``windows-amd64`` or ``macos-arm64``."""
    system = platform.system().lower()
    if system == "darwin":
        system = "macos"
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(
        machine, machine
    )
    return f"{system}-{arch}"


def _member_name(binary: str, key: str) -> str:
    return f"{binary}.exe" if key.startswith("windows-") else binary


# ── receipt ─────────────────────────────────────────────────────────────────


def lock_path() -> Path:
    return config.tools_dir() / LOCK_NAME


def _read_lock() -> dict[str, Any]:
    path = lock_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise ToolIntegrityError(
            f"{path} is unreadable; run `vardrrunner tools install --all` to rebuild it"
        ) from exc
    tools = data.get("tools") if isinstance(data, dict) else None
    return tools if isinstance(tools, dict) else {}


def _write_lock(tools: dict[str, Any]) -> None:
    payload = {"schema_version": SCHEMA_VERSION, "tools": tools}
    # Plain JSON, not write_atomic_json: the receipt holds no secrets, and the
    # redaction pass in that helper must never get a chance to alter a hash.
    manifests.write_atomic_text(lock_path(), json.dumps(payload, indent=2, sort_keys=True) + "\n")


# ── hashing ─────────────────────────────────────────────────────────────────


def _sha256(path: Path) -> str:
    digest, _ = manifests.artifact_digest(path)
    return digest


def _matches(actual: str, expected: str) -> bool:
    return hmac.compare_digest(actual.lower(), expected.lower())


# Verified binaries for this process, keyed by path, size, and mtime: a binary is
# re-hashed the first time it is resolved, and again if it changes on disk.
_verified: dict[str, tuple[int, int]] = {}


# ── install ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class InstallResult:
    name: str
    version: str
    path: Path
    already_installed: bool


def install(name: str, *, force: bool = False) -> InstallResult:
    """Download, verify, and install the pinned build of ``name`` for this platform."""
    tools = load_manifest()["tools"]
    if name not in tools:
        raise ToolchainError(f"{name} is not a tool VardrRunner can install")
    entry = tools[name]
    key = platform_key()
    asset = entry["platforms"].get(key)
    if asset is None:
        raise ToolchainError(f"no pinned {name} build for this platform ({key})")

    version = entry["version"]
    # Two different things: `filename` is what we install as, always the bare
    # binary name, so the receipt and `resolve()` stay simple. `archive_member`
    # is where it sits inside the archive, which for a nested layout (dalfox) is
    # one directory down.
    filename = _member_name(entry["binary"], key)
    archive_member = str(asset.get("member") or filename)
    target = config.tools_dir() / filename

    lock = _read_lock()
    current = lock.get(name)
    if not force and current and current.get("version") == version and target.exists():
        if _matches(_sha256(target), str(current.get("binary_sha256", ""))):
            return InstallResult(name, version, target, already_installed=True)

    config.tools_dir().mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=config.tools_dir()))
    try:
        archive = staging / ("asset.tar.gz" if asset["url"].endswith(".tar.gz") else "asset.zip")
        try:
            api.download_asset(asset["url"], archive, max_bytes=MAX_ARCHIVE_BYTES)
        except api.AssetDownloadError as exc:
            raise ToolchainError(f"{name}: {exc}") from exc

        archive_sha = _sha256(archive)
        if not _matches(archive_sha, asset["sha256"]):
            raise ToolIntegrityError(
                f"{name} {version}: downloaded archive does not match the pinned SHA-256; "
                "nothing was installed"
            )

        staged = staging / filename
        _extract_member(archive, archive_member, staged)
        _make_executable(staged)
        _check_version(staged, name, version, entry.get("version_args", ["-version"]))
        binary_sha = _sha256(staged)

        try:
            os.replace(staged, target)
        except PermissionError as exc:
            raise ToolchainError(
                f"could not replace {target}; stop the daemon or any running {name} and retry"
            ) from exc

        lock[name] = {
            "version": version,
            "platform": key,
            "binary": filename,
            "asset_sha256": archive_sha,
            "binary_sha256": binary_sha,
            "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        _write_lock(lock)
        _verified.pop(str(target), None)
        return InstallResult(name, version, target, already_installed=False)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _extract_member(archive: Path, member: str, dest: Path) -> None:
    """Copy exactly one named file out of the verified archive, bounded in size.

    Nothing is ever extracted by the archive's own paths: the one expected member is
    read and written to ``dest``, a path VardrRunner chose. Every other entry is
    ignored, so traversal names, links, and devices in the archive have no effect.
    """
    if archive.name.endswith(".tar.gz"):
        _extract_tar_member(archive, member, dest)
    else:
        _extract_zip_member(archive, member, dest)


def _extract_zip_member(archive: Path, member: str, dest: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as zf:
            try:
                info = zf.getinfo(member)
            except KeyError as exc:
                raise ToolchainError(f"{member} is missing from the pinned archive") from exc
            if info.is_dir() or info.file_size > MAX_BINARY_BYTES:
                raise ToolchainError(f"{member} in the pinned archive is not a usable binary")
            with zf.open(info) as src:
                _copy_bounded(src, dest, member)
    except zipfile.BadZipFile as exc:
        raise ToolchainError("the pinned archive is not a valid zip file") from exc


def _extract_tar_member(archive: Path, member: str, dest: Path) -> None:
    try:
        with tarfile.open(archive, "r:gz") as tf:
            info = None
            for candidate in (member, f"./{member}"):
                try:
                    info = tf.getmember(candidate)
                    break
                except KeyError:
                    continue
            if info is None:
                raise ToolchainError(f"{member} is missing from the pinned archive")
            # Regular files only: a symlink, hardlink, or device entry is refused.
            if not info.isreg() or info.size > MAX_BINARY_BYTES:
                raise ToolchainError(f"{member} in the pinned archive is not a usable binary")
            src = tf.extractfile(info)
            if src is None:
                raise ToolchainError(f"{member} in the pinned archive is not a usable binary")
            with src:
                _copy_bounded(src, dest, member)
    # gzip.BadGzipFile is an OSError; a truncated stream raises EOFError.
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ToolchainError("the pinned archive is not a valid tar.gz file") from exc


def _copy_bounded(src: IO[bytes], dest: Path, member: str) -> None:
    """Stream ``src`` to ``dest``, enforcing the size cap on bytes actually read."""
    written = 0
    with dest.open("wb") as out:
        while chunk := src.read(1024 * 1024):
            written += len(chunk)
            if written > MAX_BINARY_BYTES:
                raise ToolchainError(f"{member} exceeded the extraction size limit")
            out.write(chunk)


def _make_executable(path: Path) -> None:
    if os.name == "nt":
        return
    path.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def _check_version(binary: Path, name: str, version: str, version_args: list[str]) -> None:
    """Run the staged binary's version flag and require the pinned version."""
    try:
        result = subprocess.run(
            [str(binary), *version_args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolchainError(f"{name}: the downloaded binary would not run") from exc
    if not binary.exists():
        # Security tools (port scanners especially) are routinely flagged by
        # antivirus, which kills the process on launch and quarantines the file.
        raise ToolchainError(
            f"{name}: the binary was removed as soon as it ran, most likely quarantined by "
            f"antivirus. {antivirus_hint()}"
        )
    output = (result.stdout or "") + (result.stderr or "")
    if not re.search(rf"(?<![\d.])v?{re.escape(version)}(?![\d.])", output):
        raise ToolchainError(
            f"{name}: the downloaded binary does not report version {version}; nothing was installed"
        )


def antivirus_hint() -> str:
    """What to tell an operator whose antivirus removed a managed tool."""
    return (
        f"Penetration-testing tools are often flagged by antivirus; if you trust them, add an "
        f"exclusion for {config.tools_dir()} and run `vardrrunner tools install --force`."
    )


# ── verify / resolve ────────────────────────────────────────────────────────


def verify(name: str) -> None:
    """Raise ToolIntegrityError unless the managed ``name`` matches its receipt."""
    entry = _read_lock().get(name)
    if not entry:
        raise ToolIntegrityError(f"{name} is not installed by VardrRunner")
    path = config.tools_dir() / str(entry.get("binary", ""))
    if not path.is_file():
        raise ToolIntegrityError(
            f"{name}: the installed binary is missing (deleted, or quarantined by antivirus). {antivirus_hint()}"
        )
    if not _matches(_sha256(path), str(entry.get("binary_sha256", ""))):
        raise ToolIntegrityError(
            f"{name}: the installed binary changed since it was installed; "
            f"run `vardrrunner tools install {name} --force`"
        )


def resolve(name: str, binary: str) -> str:
    """The program to execute for ``name``: a verified managed path, or ``binary`` for PATH.

    A managed install that fails verification raises — it never silently falls
    back to an unverified PATH copy.
    """
    entry = _read_lock().get(name)
    managed_file = config.tools_dir() / _member_name(binary, platform_key())
    if not entry:
        if managed_file.exists():
            raise ToolIntegrityError(
                f"{managed_file} has no install receipt; run `vardrrunner tools install {name}`"
            )
        return binary

    path = config.tools_dir() / str(entry.get("binary", ""))
    try:
        st = path.stat()
    except OSError as exc:
        raise ToolIntegrityError(
            f"{name}: the installed binary is missing (deleted, or quarantined by antivirus). {antivirus_hint()}"
        ) from exc
    fingerprint = (st.st_size, st.st_mtime_ns)
    if _verified.get(str(path)) != fingerprint:
        verify(name)
        _verified[str(path)] = fingerprint
    return str(path)


# ── status / remove ─────────────────────────────────────────────────────────


def status(name: str, binary: str) -> ToolStatus:
    pinned = load_manifest()["tools"].get(name, {}).get("version")
    entry = _read_lock().get(name)
    if entry:
        path = str(config.tools_dir() / str(entry.get("binary", "")))
        try:
            verify(name)
        except ToolIntegrityError as exc:
            return ToolStatus(name, "tampered", path, entry.get("version"), pinned, str(exc))
        detail = "verified"
        if pinned and entry.get("version") != pinned:
            detail = f"verified; pinned version is now {pinned}"
        return ToolStatus(name, "managed", path, entry.get("version"), pinned, detail)

    on_path = shutil.which(binary)
    if pinned is None:
        detail = (
            "found on PATH (not installable by VardrRunner)" if on_path else "not found on PATH"
        )
        return ToolStatus(name, "system", on_path, None, None, detail)
    if on_path:
        return ToolStatus(
            name, "path", on_path, None, pinned, "unverified copy on PATH (not installed here)"
        )
    return ToolStatus(name, "missing", None, None, pinned, "not installed")


def remove(name: str) -> bool:
    """Delete a managed tool and its receipt entry. Returns False if it wasn't installed."""
    lock = _read_lock()
    entry = lock.pop(name, None)
    if entry is None:
        return False
    path = config.tools_dir() / str(entry.get("binary", ""))
    try:
        path.unlink(missing_ok=True)
    except PermissionError as exc:
        raise ToolchainError(f"could not delete {path}; stop any running {name} and retry") from exc
    _write_lock(lock)
    _verified.pop(str(path), None)
    return True


def purge() -> None:
    """Delete every managed tool, the receipt, and managed tool data."""
    for directory in (config.tools_dir(), config.data_dir()):
        if directory.exists():
            shutil.rmtree(directory)
    _verified.clear()
