"""Managed tool installs: pinning, verification, tamper detection, and removal.

No network and no real binaries: downloads copy a locally built zip, and the
version check is a mocked subprocess. The autouse fixture in conftest points
the tools and data directories at tmp_path.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from vardrrunner import api, config, toolchain

VERSION = "1.2.3"
KEY = "linux-amd64"  # member name has no .exe, so tests are platform-neutral


def _zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def fake(tmp_path, monkeypatch):
    """A one-tool manifest whose pinned archive is a local zip."""
    archive = _zip(tmp_path / "faketool.zip", {"faketool": b"binary-v1", "README.md": b"x"})
    manifest = {
        "schema_version": 1,
        "tools": {
            "faketool": {
                "version": VERSION,
                "binary": "faketool",
                "platforms": {
                    KEY: {"url": "https://example.test/faketool.zip", "sha256": _sha(archive)}
                },
            }
        },
    }
    monkeypatch.setattr(toolchain, "_manifest_cache", toolchain.validate_manifest(manifest))
    monkeypatch.setattr(toolchain, "platform_key", lambda: KEY)
    monkeypatch.setattr(toolchain, "_verified", {})

    state = SimpleNamespace(archive=archive, downloads=0, version_output=f"faketool v{VERSION}")

    def download(url, dest, *, max_bytes, timeout=60):
        state.downloads += 1
        dest.write_bytes(state.archive.read_bytes())

    def run(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout=state.version_output, stderr="")

    monkeypatch.setattr(api, "download_asset", download)
    monkeypatch.setattr(toolchain.subprocess, "run", run)
    return state


def _installed() -> Path:
    return config.tools_dir() / "faketool"


def _lock() -> dict:
    return json.loads(toolchain.lock_path().read_text())["tools"]


# ── manifest ────────────────────────────────────────────────────────────────


def test_shipped_manifest_is_valid_and_complete():
    """The real manifest pins every manageable tool for all five platforms."""
    toolchain._manifest_cache = None
    data = toolchain.load_manifest()
    assert set(data["tools"]) == {
        "httpx",
        "nuclei",
        "subfinder",
        "dnsx",
        "naabu",
        "katana",
        "gau",
        "ffuf",
        "dalfox",
    }
    for entry in data["tools"].values():
        assert set(entry["platforms"]) == {
            "windows-amd64",
            "linux-amd64",
            "linux-arm64",
            "macos-amd64",
            "macos-arm64",
        }


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda m: m.update(schema_version=2), "unsupported schema"),
        (lambda m: m.update(tools={}), "lists no tools"),
        (lambda m: m["tools"].update(t="x"), "not an object"),
        (lambda m: m["tools"]["t"].update(version=""), "no version"),
        (lambda m: m["tools"]["t"].update(binary="../evil"), "invalid binary name"),
        (lambda m: m["tools"]["t"].update(platforms={}), "lists no platforms"),
        (lambda m: m["tools"]["t"]["platforms"].update(k="x"), "asset is not an object"),
        (lambda m: m["tools"]["t"]["platforms"]["k"].update(url="http://x/a.zip"), "must be HTTPS"),
        (lambda m: m["tools"]["t"]["platforms"]["k"].update(sha256="abc"), "not a SHA-256"),
    ],
)
def test_validate_manifest_rejects(mutate, message):
    manifest = {
        "schema_version": 1,
        "tools": {
            "t": {
                "version": "1",
                "binary": "t",
                "platforms": {"k": {"url": "https://x/a.zip", "sha256": "a" * 64}},
            }
        },
    }
    mutate(manifest)
    with pytest.raises(toolchain.ToolchainError, match=message):
        toolchain.validate_manifest(manifest)


@pytest.mark.parametrize(
    "system, machine, expected",
    [
        ("Windows", "AMD64", "windows-amd64"),
        ("Linux", "x86_64", "linux-amd64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Darwin", "arm64", "macos-arm64"),
        ("Darwin", "x86_64", "macos-amd64"),
    ],
)
def test_platform_key(monkeypatch, system, machine, expected):
    monkeypatch.setattr(toolchain.platform, "system", lambda: system)
    monkeypatch.setattr(toolchain.platform, "machine", lambda: machine)
    assert toolchain.platform_key() == expected


def test_windows_member_has_exe_suffix():
    assert toolchain._member_name("httpx", "windows-amd64") == "httpx.exe"
    assert toolchain._member_name("httpx", "linux-amd64") == "httpx"


# ── install ─────────────────────────────────────────────────────────────────


def test_install_writes_binary_and_receipt(fake):
    result = toolchain.install("faketool")
    assert not result.already_installed
    assert _installed().read_bytes() == b"binary-v1"
    entry = _lock()["faketool"]
    assert entry["version"] == VERSION
    assert entry["asset_sha256"] == _sha(fake.archive)
    assert entry["binary_sha256"] == hashlib.sha256(b"binary-v1").hexdigest()
    # Staging is always cleaned up; only the binary and receipt remain.
    assert sorted(p.name for p in config.tools_dir().iterdir()) == ["faketool", "tools.lock.json"]


def test_install_is_idempotent_without_downloading(fake):
    toolchain.install("faketool")
    again = toolchain.install("faketool")
    assert again.already_installed
    assert fake.downloads == 1


def test_force_reinstalls(fake):
    toolchain.install("faketool")
    toolchain.install("faketool", force=True)
    assert fake.downloads == 2


def test_tampered_install_is_replaced_rather_than_trusted(fake):
    toolchain.install("faketool")
    _installed().write_bytes(b"evil")
    result = toolchain.install("faketool")
    assert not result.already_installed
    assert _installed().read_bytes() == b"binary-v1"


def test_archive_hash_mismatch_installs_nothing(fake, tmp_path):
    fake.archive = _zip(tmp_path / "other.zip", {"faketool": b"modified"})
    with pytest.raises(toolchain.ToolIntegrityError, match="does not match the pinned SHA-256"):
        toolchain.install("faketool")
    assert not _installed().exists()
    assert not toolchain.lock_path().exists()
    assert [p for p in config.tools_dir().iterdir()] == []  # no staging left behind


def test_only_the_named_member_is_extracted(fake, tmp_path, monkeypatch):
    """An archive carrying extra or path-traversing entries can't write anything else."""
    fake.archive = _zip(
        tmp_path / "hostile.zip", {"faketool": b"binary-v1", "../escape.txt": b"x", "a/b": b"y"}
    )
    entry = toolchain._manifest_cache["tools"]["faketool"]["platforms"][KEY]
    monkeypatch.setitem(entry, "sha256", _sha(fake.archive))
    toolchain.install("faketool")
    assert not (config.tools_dir().parent / "escape.txt").exists()
    assert sorted(p.name for p in config.tools_dir().iterdir()) == ["faketool", "tools.lock.json"]


def test_missing_member(fake, tmp_path, monkeypatch):
    fake.archive = _zip(tmp_path / "empty.zip", {"README.md": b"x"})
    entry = toolchain._manifest_cache["tools"]["faketool"]["platforms"][KEY]
    monkeypatch.setitem(entry, "sha256", _sha(fake.archive))
    with pytest.raises(toolchain.ToolchainError, match="missing from the pinned archive"):
        toolchain.install("faketool")


def test_not_a_zip(fake, tmp_path, monkeypatch):
    fake.archive = tmp_path / "junk.zip"
    fake.archive.write_bytes(b"not a zip")
    entry = toolchain._manifest_cache["tools"]["faketool"]["platforms"][KEY]
    monkeypatch.setitem(entry, "sha256", _sha(fake.archive))
    with pytest.raises(toolchain.ToolchainError, match="not a valid zip"):
        toolchain.install("faketool")


def test_oversized_member_rejected(fake, monkeypatch):
    monkeypatch.setattr(toolchain, "MAX_BINARY_BYTES", 4)
    with pytest.raises(toolchain.ToolchainError, match="not a usable binary"):
        toolchain.install("faketool")
    assert not _installed().exists()


def test_member_that_lies_about_its_size_is_cut_off(fake, monkeypatch):
    """The streamed byte count is enforced, not just the size the zip header claims."""
    real_getinfo = zipfile.ZipFile.getinfo

    def lying_getinfo(self, name):
        info = real_getinfo(self, name)
        info.file_size = 1
        return info

    monkeypatch.setattr(zipfile.ZipFile, "getinfo", lying_getinfo)
    monkeypatch.setattr(toolchain, "MAX_BINARY_BYTES", 4)
    with pytest.raises(toolchain.ToolchainError):
        toolchain.install("faketool")
    assert not _installed().exists()


def test_wrong_version_installs_nothing(fake):
    fake.version_output = "faketool v9.9.9"
    with pytest.raises(toolchain.ToolchainError, match=f"does not report version {VERSION}"):
        toolchain.install("faketool")
    assert not _installed().exists()


def test_version_must_match_exactly(fake):
    """1.2.3 must not be satisfied by 1.2.30 or 11.2.3."""
    fake.version_output = "faketool v1.2.30 / v11.2.3"
    with pytest.raises(toolchain.ToolchainError):
        toolchain.install("faketool")


def test_binary_quarantined_on_launch_explains_antivirus(fake, monkeypatch):
    def run_and_vanish(cmd, **kwargs):
        Path(cmd[0]).unlink()
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(toolchain.subprocess, "run", run_and_vanish)
    with pytest.raises(toolchain.ToolchainError, match="antivirus"):
        toolchain.install("faketool")
    assert not _installed().exists()


@pytest.mark.parametrize("error", [OSError("exec format"), subprocess.TimeoutExpired("x", 15)])
def test_binary_that_will_not_run(fake, monkeypatch, error):
    def boom(cmd, **kwargs):
        raise error

    monkeypatch.setattr(toolchain.subprocess, "run", boom)
    with pytest.raises(toolchain.ToolchainError, match="would not run"):
        toolchain.install("faketool")


def test_download_failure(fake, monkeypatch):
    def fail(url, dest, *, max_bytes, timeout=60):
        raise api.AssetDownloadError("tool asset download failed")

    monkeypatch.setattr(api, "download_asset", fail)
    with pytest.raises(toolchain.ToolchainError, match="download failed"):
        toolchain.install("faketool")


def test_unknown_tool_and_unsupported_platform(fake, monkeypatch):
    with pytest.raises(toolchain.ToolchainError, match="not a tool VardrRunner can install"):
        toolchain.install("nmap")
    monkeypatch.setattr(toolchain, "platform_key", lambda: "plan9-mips")
    with pytest.raises(toolchain.ToolchainError, match="no pinned faketool build"):
        toolchain.install("faketool")


def test_binary_in_use_cannot_be_replaced(fake, monkeypatch):
    def locked(src, dst):
        raise PermissionError("in use")

    monkeypatch.setattr(toolchain.os, "replace", locked)
    with pytest.raises(toolchain.ToolchainError, match="stop the daemon"):
        toolchain.install("faketool")


# ── verify / resolve ────────────────────────────────────────────────────────


def test_verify_detects_tampering(fake):
    toolchain.install("faketool")
    toolchain.verify("faketool")
    _installed().write_bytes(b"evil")
    with pytest.raises(toolchain.ToolIntegrityError, match="changed since it was installed"):
        toolchain.verify("faketool")


def test_verify_missing_binary_mentions_antivirus(fake):
    toolchain.install("faketool")
    _installed().unlink()
    with pytest.raises(toolchain.ToolIntegrityError, match="antivirus"):
        toolchain.verify("faketool")


def test_verify_not_installed(fake):
    with pytest.raises(toolchain.ToolIntegrityError, match="not installed"):
        toolchain.verify("faketool")


def test_resolve_falls_back_to_path_name(fake):
    assert toolchain.resolve("faketool", "faketool") == "faketool"


def test_resolve_returns_verified_managed_path(fake):
    toolchain.install("faketool")
    assert toolchain.resolve("faketool", "faketool") == str(_installed())


def test_resolve_refuses_tampered_binary(fake):
    toolchain.install("faketool")
    _installed().write_bytes(b"evil-but-same-length?")
    with pytest.raises(toolchain.ToolIntegrityError):
        toolchain.resolve("faketool", "faketool")


def test_resolve_refuses_binary_without_receipt(fake):
    config.tools_dir().mkdir(parents=True)
    _installed().write_bytes(b"dropped here by someone")
    with pytest.raises(toolchain.ToolIntegrityError, match="no install receipt"):
        toolchain.resolve("faketool", "faketool")


def test_resolve_missing_managed_binary(fake):
    toolchain.install("faketool")
    _installed().unlink()
    with pytest.raises(toolchain.ToolIntegrityError, match="missing"):
        toolchain.resolve("faketool", "faketool")


def test_resolve_hashes_once_until_the_file_changes(fake, monkeypatch):
    toolchain.install("faketool")
    calls = []
    real = toolchain._sha256
    monkeypatch.setattr(toolchain, "_sha256", lambda p: calls.append(p) or real(p))
    toolchain.resolve("faketool", "faketool")
    toolchain.resolve("faketool", "faketool")
    assert len(calls) == 1
    _installed().write_bytes(b"evil-longer-content")
    with pytest.raises(toolchain.ToolIntegrityError):
        toolchain.resolve("faketool", "faketool")


def test_corrupt_receipt_fails_closed(fake):
    toolchain.install("faketool")
    toolchain.lock_path().write_text("{not json")
    with pytest.raises(toolchain.ToolIntegrityError, match="unreadable"):
        toolchain.resolve("faketool", "faketool")


def test_receipt_with_unexpected_shape_is_empty(fake):
    config.tools_dir().mkdir(parents=True)
    toolchain.lock_path().write_text(json.dumps(["not", "a", "dict"]))
    assert toolchain._read_lock() == {}


# ── status / remove / purge ─────────────────────────────────────────────────


def test_status_managed_and_outdated(fake, monkeypatch):
    toolchain.install("faketool")
    assert toolchain.status("faketool", "faketool").source == "managed"
    monkeypatch.setitem(toolchain._manifest_cache["tools"]["faketool"], "version", "2.0.0")
    st = toolchain.status("faketool", "faketool")
    assert st.source == "managed" and "pinned version is now 2.0.0" in st.detail


def test_status_tampered(fake):
    toolchain.install("faketool")
    _installed().write_bytes(b"evil")
    assert toolchain.status("faketool", "faketool").source == "tampered"


def test_status_path_missing_and_system(fake, monkeypatch):
    monkeypatch.setattr(toolchain.shutil, "which", lambda b: "/usr/bin/" + b)
    assert toolchain.status("faketool", "faketool").source == "path"
    st = toolchain.status("nmap", "nmap")
    assert st.source == "system" and st.path == "/usr/bin/nmap"
    monkeypatch.setattr(toolchain.shutil, "which", lambda b: None)
    assert toolchain.status("faketool", "faketool").source == "missing"
    assert toolchain.status("nmap", "nmap").detail == "not found on PATH"


def test_remove(fake):
    assert toolchain.remove("faketool") is False
    toolchain.install("faketool")
    assert toolchain.remove("faketool") is True
    assert not _installed().exists()
    assert "faketool" not in _lock()


def test_remove_binary_in_use(fake, monkeypatch):
    toolchain.install("faketool")

    def locked(self, missing_ok=False):
        raise PermissionError("in use")

    monkeypatch.setattr(Path, "unlink", locked)
    with pytest.raises(toolchain.ToolchainError, match="could not delete"):
        toolchain.remove("faketool")


def test_purge_removes_tools_and_data(fake):
    toolchain.install("faketool")
    config.data_dir().mkdir(parents=True)
    (config.data_dir() / "templates.txt").write_text("x")
    toolchain.purge()
    assert not config.tools_dir().exists()
    assert not config.data_dir().exists()
    toolchain.purge()  # nothing left: still fine
