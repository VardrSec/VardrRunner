"""katana and gau: configs, command construction, result normalization, and installs.

The katana fixture line mirrors real katana 1.8.0 output captured during
development: full raw request/response, bodies included, on every line.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from vardrrunner import api, config, configs, handlers, runner, toolchain

KATANA_LINE = {
    "timestamp": "2026-10-08T03:27:47-05:00",
    "request": {
        "method": "GET",
        "endpoint": "http://127.0.0.1:8765/admin/login.html",
        "tag": "a",
        "attribute": "href",
        "source": "http://127.0.0.1:8765/",
        "raw": "GET /admin/login.html HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n\r\n",
    },
    "response": {
        "status_code": 200,
        "headers": {"Content-Length": "32", "Content-Type": "text/html"},
        "body": "<html><body>login</body></html>\n",
        "content_length": 32,
        "raw": "HTTP/1.0 200 OK\r\n\r\n<html><body>login</body></html>\n",
    },
}


# ── invariants ──────────────────────────────────────────────────────────────


def test_every_installable_tool_can_actually_run():
    """A tool the installer pins must be allowlisted and have a handler."""
    for name in toolchain.manageable_tools():
        assert name in runner.ALLOWED_TOOLS, name
        assert name in handlers.REGISTRY, name


# ── configs ─────────────────────────────────────────────────────────────────


def test_katana_config_defaults_and_parsing():
    assert configs.KatanaConfig.from_dict({}) == configs.KatanaConfig()
    cfg = configs.KatanaConfig.from_dict({"depth": "5", "js_crawl": "true", "limit": "20"})
    assert (cfg.depth, cfg.js_crawl, cfg.limit) == (5, True, 20)
    assert configs.KatanaConfig.from_dict({"js_crawl": False}).js_crawl is False


@pytest.mark.parametrize("bad", [{"depth": 0}, {"depth": 11}, {"js_crawl": "yes"}, {"limit": 0}])
def test_katana_config_rejects(bad):
    with pytest.raises(configs.ConfigError):
        configs.KatanaConfig.from_dict(bad)


def test_gau_config_defaults_and_providers():
    cfg = configs.GauConfig.from_dict({})
    assert cfg.subs is True and cfg.providers == ()
    cfg = configs.GauConfig.from_dict({"subs": "false", "providers": "otx, wayback,otx"})
    assert cfg.subs is False and cfg.providers == ("otx", "wayback")
    assert configs.GauConfig.from_dict({"providers": ["urlscan"]}).providers == ("urlscan",)


@pytest.mark.parametrize("bad", [{"providers": "otx,evil"}, {"providers": 3}, {"subs": "maybe"}])
def test_gau_config_rejects(bad):
    with pytest.raises(configs.ConfigError):
        configs.GauConfig.from_dict(bad)


# ── command construction ────────────────────────────────────────────────────


def _capture(monkeypatch):
    seen = SimpleNamespace(cmd=None, temp=None, target_text=None)

    def fake_run(cmd, temp, tool, timeout):
        seen.cmd, seen.temp = cmd, temp
        if temp:
            seen.target_text = Path(temp).read_text()
            Path(temp).unlink()

    monkeypatch.setattr(runner, "program", lambda name: f"/managed/{name}")
    monkeypatch.setattr(runner, "_run_tool", fake_run)
    return seen


def test_run_katana_argv(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    runner.run_katana(["https://a.test", "https://b.test"], tmp_path / "k.jsonl", depth=2)
    assert seen.cmd[0] == "/managed/katana"
    assert seen.cmd[1:3] == ["-list", seen.temp]
    for flag in ("-jsonl", "-silent", "-no-color", "-disable-update-check"):
        assert flag in seen.cmd
    assert seen.cmd[seen.cmd.index("-depth") + 1] == "2"
    assert seen.cmd[seen.cmd.index("-o") + 1] == str(tmp_path / "k.jsonl")
    assert "-js-crawl" not in seen.cmd
    assert seen.target_text == "https://a.test\nhttps://b.test"
    runner.run_katana(["https://a.test"], tmp_path / "k.jsonl", js_crawl=True)
    assert "-js-crawl" in seen.cmd


def test_run_gau_argv_ends_options_before_domains(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    runner.run_gau(["a.test", "b.test"], tmp_path / "g.jsonl", providers=("otx", "wayback"))
    assert seen.cmd[:4] == ["/managed/gau", "--json", "--o", str(tmp_path / "g.jsonl")]
    assert "--subs" in seen.cmd
    assert seen.cmd[seen.cmd.index("--providers") + 1] == "otx,wayback"
    # Domains always follow "--", so none can be read as an option.
    assert seen.cmd[-3:] == ["--", "a.test", "b.test"]
    runner.run_gau(["a.test"], tmp_path / "g.jsonl", subs=False)
    assert "--subs" not in seen.cmd and "--providers" not in seen.cmd


# ── katana handler ──────────────────────────────────────────────────────────


def _katana_execute(tmp_path, lines, config=None):
    def fake_run(targets, out, depth=3, js_crawl=False, timeout=None):
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with patch("vardrrunner.runner.run_katana", side_effect=fake_run):
        return handlers.KatanaHandler().execute(
            ["http://t.test"], tmp_path, config or configs.KatanaConfig()
        )


def test_katana_execute_keeps_metadata_and_drops_bodies(tmp_path):
    out = _katana_execute(tmp_path, [json.dumps(KATANA_LINE)])
    assert out is not None and out.name == "katana_import.jsonl"
    [record] = [json.loads(line) for line in out.read_text().splitlines()]
    assert record == {
        "url": "http://127.0.0.1:8765/admin/login.html",
        "method": "GET",
        "status_code": 200,
        "content_length": 32,
        "content_type": "text/html",
        "source": "katana",
    }
    assert "login</body>" not in out.read_text()


def test_katana_execute_skips_junk_and_duplicates(tmp_path):
    lowercase = json.loads(json.dumps(KATANA_LINE))
    lowercase["request"]["endpoint"] = "http://t.test/other"
    lowercase["response"]["headers"] = {"content-type": "application/json"}
    lines = [
        json.dumps(KATANA_LINE),
        json.dumps(KATANA_LINE),  # duplicate
        "not json",
        "",
        json.dumps(["a", "list"]),
        json.dumps({"request": {"method": "GET"}}),  # no endpoint
        json.dumps({"request": "bad", "response": "bad"}),
        json.dumps(lowercase),
    ]
    out = _katana_execute(tmp_path, lines)
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["url"] for r in records] == [
        KATANA_LINE["request"]["endpoint"],
        "http://t.test/other",
    ]
    assert records[1]["content_type"] == "application/json"


def test_katana_record_tolerates_odd_types():
    rec = handlers._katana_record(
        {"request": {"endpoint": "http://t.test"}, "response": {"status_code": "200", "headers": 5}}
    )
    assert rec == {
        "url": "http://t.test",
        "method": "GET",
        "status_code": None,
        "content_length": None,
        "content_type": None,
        "source": "katana",
    }


def test_katana_execute_no_results(tmp_path):
    assert _katana_execute(tmp_path, ["not json"]) is None


def test_katana_execute_missing_output_file(tmp_path):
    with patch("vardrrunner.runner.run_katana"):
        assert handlers.KatanaHandler().execute(["x"], tmp_path, configs.KatanaConfig()) is None


def test_katana_upload_label_and_handoff(tmp_path):
    out = _katana_execute(tmp_path, [json.dumps(KATANA_LINE)])
    client = MagicMock()
    client.import_file.return_value = {"import_record": {"imported_count": 1}}
    handler = handlers.KatanaHandler()
    assert handler.upload(client, "eng", out) == "imported 1 endpoint(s)"
    client.import_file.assert_called_once_with("eng", "katana", str(out))
    assert handler.extract_handoff_targets(out) == [KATANA_LINE["request"]["endpoint"]]
    label = handler.running_label(["a", "b"], configs.KatanaConfig(depth=2, js_crawl=True))
    assert "depth 2" in label and "JavaScript" in label and "2 target" in label


def test_katana_resolves_scope_or_recon_targets():
    with patch("vardrrunner.handlers._resolve_standard", return_value=["https://a.test"]) as res:
        assert handlers.KatanaHandler().resolve_targets(
            MagicMock(), "eng", "recon", configs.KatanaConfig()
        ) == ["https://a.test"]
    assert res.call_args.args[2] == "recon"


# ── gau handler ─────────────────────────────────────────────────────────────


def _gau_execute(tmp_path, lines):
    def fake_run(domains, out, subs=True, providers=(), timeout=None):
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with patch("vardrrunner.runner.run_gau", side_effect=fake_run):
        return handlers.GauHandler().execute(["a.test"], tmp_path, configs.GauConfig())


def test_gau_execute_dedupes_and_labels_source(tmp_path):
    lines = [
        json.dumps({"url": "https://a.test/x"}),
        json.dumps({"url": "https://a.test/x"}),
        json.dumps({"url": ""}),
        json.dumps({"other": 1}),
        "garbage",
        json.dumps({"url": "https://a.test/y?id=1"}),
    ]
    out = _gau_execute(tmp_path, lines)
    assert [json.loads(line) for line in out.read_text().splitlines()] == [
        {"url": "https://a.test/x", "source": "gau"},
        {"url": "https://a.test/y?id=1", "source": "gau"},
    ]


def test_gau_execute_no_results(tmp_path):
    assert _gau_execute(tmp_path, ["garbage"]) is None


def test_gau_resolves_wildcard_domains_only():
    client = MagicMock()
    client.scope.return_value = {
        "in": [{"value": "*.a.test"}, {"value": "b.test"}, {"value": "*."}],
    }
    assert handlers.GauHandler().resolve_targets(client, "eng", "scope", configs.GauConfig()) == [
        "a.test"
    ]


def test_gau_upload_label_and_handoff(tmp_path):
    out = _gau_execute(tmp_path, [json.dumps({"url": "https://a.test/x"})])
    client = MagicMock()
    client.import_file.return_value = {"import_record": {"imported_count": 1}}
    handler = handlers.GauHandler()
    assert handler.upload(client, "eng", out) == "imported 1 URL(s)"
    client.import_file.assert_called_once_with("eng", "gau", str(out))
    assert handler.extract_handoff_targets(out) == ["https://a.test/x"]
    assert "all providers" in handler.running_label(["a"], configs.GauConfig())
    assert "otx" in handler.running_label(["a"], configs.GauConfig(providers=("otx",)))


# ── tar.gz installs (gau ships tar.gz on Linux and macOS) ───────────────────


def _tar(path: Path, entries: list[tarfile.TarInfo | tuple[str, bytes]]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for entry in entries:
            if isinstance(entry, tarfile.TarInfo):
                tf.addfile(entry)
            else:
                name, data = entry
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return path


@pytest.fixture
def tar_tool(tmp_path, monkeypatch):
    state = SimpleNamespace(archive=None, calls=[])

    def set_archive(path: Path) -> None:
        state.archive = path
        manifest = {
            "schema_version": 1,
            "tools": {
                "taroo": {
                    "version": "2.2.4",
                    "binary": "taroo",
                    "version_args": ["--version"],
                    "platforms": {
                        "linux-amd64": {
                            "url": "https://example.test/taroo.tar.gz",
                            "sha256": toolchain._sha256(path),
                        }
                    },
                }
            },
        }
        monkeypatch.setattr(toolchain, "_manifest_cache", toolchain.validate_manifest(manifest))

    def download(url, dest, *, max_bytes, timeout=60):
        dest.write_bytes(state.archive.read_bytes())

    def run(cmd, **kwargs):
        state.calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="taroo version: 2.2.4", stderr="")

    monkeypatch.setattr(toolchain, "platform_key", lambda: "linux-amd64")
    monkeypatch.setattr(toolchain, "_verified", {})
    monkeypatch.setattr(api, "download_asset", download)
    monkeypatch.setattr(toolchain.subprocess, "run", run)
    state.set_archive = set_archive
    return state


def test_tar_gz_install_uses_manifest_version_flag(tar_tool, tmp_path):
    tar_tool.set_archive(_tar(tmp_path / "t.tar.gz", [("taroo", b"bin"), ("LICENSE", b"x")]))
    toolchain.install("taroo")
    assert (config.tools_dir() / "taroo").read_bytes() == b"bin"
    assert tar_tool.calls[0][1:] == ["--version"]


def test_tar_gz_member_with_dot_slash_prefix(tar_tool, tmp_path):
    tar_tool.set_archive(_tar(tmp_path / "t.tar.gz", [("./taroo", b"bin")]))
    toolchain.install("taroo")
    assert (config.tools_dir() / "taroo").read_bytes() == b"bin"


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE])
def test_tar_gz_refuses_links_and_directories(tar_tool, tmp_path, kind):
    link = tarfile.TarInfo("taroo")
    link.type = kind
    link.linkname = "/etc/passwd"
    tar_tool.set_archive(_tar(tmp_path / "t.tar.gz", [link]))
    with pytest.raises(toolchain.ToolchainError, match="not a usable binary"):
        toolchain.install("taroo")
    assert not (config.tools_dir() / "taroo").exists()


def test_tar_gz_missing_member(tar_tool, tmp_path):
    tar_tool.set_archive(_tar(tmp_path / "t.tar.gz", [("README.md", b"x")]))
    with pytest.raises(toolchain.ToolchainError, match="missing from the pinned archive"):
        toolchain.install("taroo")


def test_tar_gz_corrupt(tar_tool, tmp_path):
    bad = tmp_path / "t.tar.gz"
    bad.write_bytes(b"\x1f\x8bnot really gzip")
    tar_tool.set_archive(bad)
    with pytest.raises(toolchain.ToolchainError, match="not a valid tar.gz"):
        toolchain.install("taroo")


def test_tar_gz_oversized_member(tar_tool, tmp_path, monkeypatch):
    tar_tool.set_archive(_tar(tmp_path / "t.tar.gz", [("taroo", b"too-big")]))
    monkeypatch.setattr(toolchain, "MAX_BINARY_BYTES", 3)
    with pytest.raises(toolchain.ToolchainError, match="not a usable binary"):
        toolchain.install("taroo")


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda e: e.update(version_args=[]), "invalid version_args"),
        (lambda e: e.update(version_args=["--version", "; rm -rf /"]), "invalid version_args"),
        (lambda e: e.update(version_args="--version"), "invalid version_args"),
        (lambda e: e["platforms"]["k"].update(url="https://x/a.exe"), "zip or .tar.gz"),
    ],
)
def test_manifest_rejects_bad_version_args_and_archive_types(mutate, message):
    entry = {
        "version": "1",
        "binary": "t",
        "platforms": {"k": {"url": "https://x/a.zip", "sha256": "a" * 64}},
    }
    mutate(entry)
    with pytest.raises(toolchain.ToolchainError, match=message):
        toolchain.validate_manifest({"schema_version": 1, "tools": {"t": entry}})
