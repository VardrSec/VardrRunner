"""The `tools` commands, runner integration with managed installs, and asset download."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests
import typer

from vardrrunner import api, config, runner, toolchain
from vardrrunner.commands import doctor
from vardrrunner.commands import tools as tools_cmd


def _status(source, version=None, detail="", path=None):
    return toolchain.ToolStatus("httpx", source, path, version, "1.12.0", detail)


# ── api.download_asset ──────────────────────────────────────────────────────


class _Response:
    def __init__(self, chunks, url="https://example.test/a.zip", status=200):
        self.chunks, self.url, self.status = chunks, url, status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        if self.status >= 400:
            raise requests.HTTPError("404")

    def iter_content(self, chunk_size):
        yield from self.chunks


def test_download_writes_file(tmp_path):
    dest = tmp_path / "a.zip"
    with patch("vardrrunner.api.requests.get", return_value=_Response([b"ab", b"cd"])):
        api.download_asset("https://example.test/a.zip", dest, max_bytes=10)
    assert dest.read_bytes() == b"abcd"


def test_download_refuses_plain_http(tmp_path):
    with pytest.raises(api.AssetDownloadError, match="HTTPS"):
        api.download_asset("http://example.test/a.zip", tmp_path / "a", max_bytes=10)


def test_download_refuses_redirect_off_https(tmp_path):
    response = _Response([b"x"], url="http://mirror.test/a.zip")
    with patch("vardrrunner.api.requests.get", return_value=response):
        with pytest.raises(api.AssetDownloadError, match="redirected"):
            api.download_asset("https://example.test/a.zip", tmp_path / "a", max_bytes=10)


def test_download_enforces_size_limit(tmp_path):
    with patch("vardrrunner.api.requests.get", return_value=_Response([b"abcdef", b"ghij"])):
        with pytest.raises(api.AssetDownloadError, match="download limit"):
            api.download_asset("https://example.test/a.zip", tmp_path / "a", max_bytes=8)


def test_download_wraps_request_errors(tmp_path):
    with patch("vardrrunner.api.requests.get", return_value=_Response([], status=404)):
        with pytest.raises(api.AssetDownloadError, match="download failed"):
            api.download_asset("https://example.test/a.zip", tmp_path / "a", max_bytes=8)


# ── runner integration ──────────────────────────────────────────────────────


def test_program_uses_resolved_path(monkeypatch):
    monkeypatch.setattr(toolchain, "resolve", lambda name, binary: f"/managed/{binary}")
    assert runner.program("httpx") == "/managed/httpx"


def test_program_refuses_failed_verification(monkeypatch):
    def tampered(name, binary):
        raise toolchain.ToolIntegrityError("httpx: the installed binary changed")

    monkeypatch.setattr(toolchain, "resolve", tampered)
    with pytest.raises(runner.ToolError, match="changed"):
        runner.program("httpx")
    assert runner.tool_available("httpx") is False
    assert runner.tool_version("httpx") is None


def test_tool_available_uses_managed_path(monkeypatch):
    monkeypatch.setattr(toolchain, "resolve", lambda name, binary: "/managed/httpx")
    monkeypatch.setattr(runner.shutil, "which", lambda p: p if p.startswith("/managed") else None)
    assert runner.tool_available("httpx") is True
    assert runner.tool_available("not-a-tool") is False


def test_tool_commands_execute_the_managed_binary(monkeypatch, tmp_path):
    """Every run_* builds its argv from program(), so a managed install is what runs."""
    monkeypatch.setattr(toolchain, "resolve", lambda name, binary: f"/managed/{binary}")
    seen = []
    monkeypatch.setattr(runner, "_run_tool", lambda cmd, temp, tool, timeout: seen.append(cmd[0]))
    runner.run_httpx(["a.test"], tmp_path / "o.jsonl")
    runner.run_subfinder(["a.test"], tmp_path / "o.jsonl")
    assert seen == ["/managed/httpx", "/managed/subfinder"]


def test_check_tool_hint_names_the_install_command(monkeypatch):
    monkeypatch.setattr(runner, "tool_available", lambda name: False)
    with pytest.raises(typer.BadParameter, match="vardrrunner tools install httpx"):
        runner.check_tool("httpx")
    with pytest.raises(typer.BadParameter, match="Install it and make sure"):
        runner.check_tool("nmap")


# ── tools commands ──────────────────────────────────────────────────────────


def _result(name, already=False):
    return toolchain.InstallResult(name, "1.0.0", config.tools_dir() / name, already)


def test_install_requires_names_or_all():
    with pytest.raises(typer.Exit) as exc:
        tools_cmd.install([], all_tools=False, force=False)
    assert exc.value.exit_code == 1


def test_install_all_installs_every_manageable_tool(monkeypatch):
    calls = []
    monkeypatch.setattr(
        toolchain, "install", lambda n, force: calls.append((n, force)) or _result(n)
    )
    monkeypatch.setattr(tools_cmd, "pcap_available", lambda: True)
    tools_cmd.install([], all_tools=True, force=True)
    assert calls == [(n, True) for n in toolchain.manageable_tools()]


def test_install_continues_past_failures_then_exits_nonzero(monkeypatch, capsys):
    def install(name, force):
        if name == "httpx":
            raise toolchain.ToolIntegrityError("httpx: does not match the pinned SHA-256")
        return _result(name, already=True)

    monkeypatch.setattr(toolchain, "install", install)
    with pytest.raises(typer.Exit) as exc:
        tools_cmd.install(["httpx", "dnsx"], all_tools=False, force=False)
    assert exc.value.exit_code == 1
    out = capsys.readouterr().out
    assert "FAIL httpx" in out and "OK dnsx" in out and "already installed" in out


def test_install_naabu_warns_when_capture_library_missing(monkeypatch, capsys):
    monkeypatch.setattr(toolchain, "install", lambda n, force: _result(n))
    monkeypatch.setattr(tools_cmd, "pcap_available", lambda: False)
    tools_cmd.install(["naabu"], all_tools=False, force=False)
    assert "WARN" in capsys.readouterr().out


def test_pcap_detection_and_hint_on_this_platform(monkeypatch):
    assert isinstance(tools_cmd.pcap_available(), bool)
    assert "naabu needs" in tools_cmd.pcap_hint()


def test_list_shows_every_allowlisted_tool(monkeypatch, capsys):
    monkeypatch.setattr(toolchain, "status", lambda n, b: _status("managed", "1.12.0", "verified"))
    tools_cmd.list_tools()
    out = capsys.readouterr().out
    for name in ("httpx", "nmap", "naabu"):
        assert name in out


def test_verify_exits_nonzero_on_tampering(monkeypatch, capsys):
    statuses = {
        "httpx": _status("managed", "1.12.0"),
        "dnsx": _status("tampered", detail="changed"),
    }
    monkeypatch.setattr(toolchain, "status", lambda n, b: statuses.get(n, _status("missing")))
    with pytest.raises(typer.Exit) as exc:
        tools_cmd.verify()
    assert exc.value.exit_code == 1
    assert "FAIL dnsx" in capsys.readouterr().out


def test_verify_with_nothing_installed(monkeypatch, capsys):
    monkeypatch.setattr(toolchain, "status", lambda n, b: _status("missing"))
    tools_cmd.verify()
    assert "No managed tools installed" in capsys.readouterr().out


def test_remove(monkeypatch, capsys):
    monkeypatch.setattr(toolchain, "remove", lambda n: n == "httpx")
    tools_cmd.remove("httpx")
    tools_cmd.remove("dnsx")
    out = capsys.readouterr().out
    assert "Removed httpx" in out and "dnsx is not installed" in out


def test_remove_error(monkeypatch):
    def locked(name):
        raise toolchain.ToolchainError("could not delete")

    monkeypatch.setattr(toolchain, "remove", locked)
    with pytest.raises(typer.Exit):
        tools_cmd.remove("httpx")


def test_purge_requires_confirmation(monkeypatch):
    purged = MagicMock()
    monkeypatch.setattr(toolchain, "purge", purged)
    monkeypatch.setattr(typer, "confirm", lambda prompt: False)
    with pytest.raises(typer.Exit):
        tools_cmd.purge(yes=False)
    purged.assert_not_called()
    tools_cmd.purge(yes=True)
    purged.assert_called_once()


def test_purge_error(monkeypatch):
    def fail():
        raise OSError("in use")

    monkeypatch.setattr(toolchain, "purge", fail)
    with pytest.raises(typer.Exit):
        tools_cmd.purge(yes=True)


# ── doctor ──────────────────────────────────────────────────────────────────


def _tool_checks(monkeypatch, statuses, available=False):
    monkeypatch.setattr(toolchain, "status", lambda n, b: statuses.get(n, _status("missing")))
    monkeypatch.setattr(runner, "tool_available", lambda n: available)
    monkeypatch.setattr(runner, "tool_version", lambda n: "v9")
    monkeypatch.setattr(tools_cmd, "pcap_available", lambda: False)
    return {c.name: c for c in doctor._check_tools()}


def test_doctor_managed_tool_is_ok(monkeypatch):
    checks = _tool_checks(monkeypatch, {"httpx": _status("managed", "1.12.0")})
    assert checks["tool: httpx"].status is doctor.Health.OK
    assert "managed, verified" in checks["tool: httpx"].detail


def test_doctor_tampered_tool_fails(monkeypatch):
    checks = _tool_checks(monkeypatch, {"httpx": _status("tampered", detail="changed")})
    assert checks["tool: httpx"].status is doctor.Health.FAIL
    assert "--force" in checks["tool: httpx"].remediation


def test_doctor_path_copy_is_an_unverified_warning(monkeypatch):
    checks = _tool_checks(monkeypatch, {}, available=True)
    assert checks["tool: httpx"].status is doctor.Health.WARN
    assert "unverified" in checks["tool: httpx"].detail
    # nmap can't be managed, so a PATH copy is simply OK.
    assert checks["tool: nmap"].status is doctor.Health.OK


def test_doctor_missing_tool_names_the_install_command(monkeypatch):
    checks = _tool_checks(monkeypatch, {})
    assert "tools install httpx" in checks["tool: httpx"].remediation
    assert "ensure it is on PATH" in checks["tool: nmap"].remediation


def test_doctor_naabu_without_capture_library_warns(monkeypatch):
    checks = _tool_checks(monkeypatch, {"naabu": _status("managed", "2.6.1")})
    assert checks["tool: naabu capture library"].status is doctor.Health.WARN
