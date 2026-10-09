"""dalfox: config bounds, argv, report handling, and the nested-archive install path.

dalfox reports candidates. Nothing in this runner re-grades a match, renames a
tier or decides what is confirmed — the report is uploaded as dalfox wrote it and
VardrMap's importer reads dalfox's own field names, so the verification signal
survives end to end.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from vardrrunner import configs, handlers, runner, toolchain


def _report(*, incomplete: bool = False, findings: int = 1) -> dict:
    return {
        "findings": [
            {
                "type": "V",
                "detection_method": "dom-verification",
                "confidence": "high",
                "inject_type": "inHTML",
                "param": f"q{i}",
                "data": f"https://a.test/?q{i}=x",
                "severity": "High",
                "cwe": "CWE-79",
            }
            for i in range(findings)
        ],
        "meta": {"dalfox_version": "3.2.4", "findings_count": findings, "incomplete": incomplete},
    }


# ── configs ─────────────────────────────────────────────────────────────────


def test_config_defaults():
    cfg = configs.DalfoxConfig.from_dict({})
    assert (cfg.limit, cfg.worker, cfg.delay, cfg.mining) == (100, 10, 0, True)


def test_config_parsing():
    cfg = configs.DalfoxConfig.from_dict(
        {"limit": "20", "worker": "25", "delay": "250", "mining": "false"}
    )
    assert (cfg.limit, cfg.worker, cfg.delay, cfg.mining) == (20, 25, 250, False)


@pytest.mark.parametrize(
    "bad",
    [
        {"worker": 0},
        {"worker": 101},
        {"worker": "lots"},
        {"delay": -1},
        {"delay": 10_001},
        {"mining": "maybe"},
        {"limit": 0},
        {"timeout": 0},
    ],
)
def test_config_rejects(bad):
    with pytest.raises(configs.ConfigError):
        configs.DalfoxConfig.from_dict(bad)


def test_concurrency_bounds_cannot_be_opened_up():
    """worker is a load control, so it has a ceiling and no disabling value."""
    assert configs.DalfoxConfig.from_dict({"worker": 100}).worker == 100
    with pytest.raises(configs.ConfigError):
        configs.DalfoxConfig.from_dict({"worker": 500})


# ── argv ────────────────────────────────────────────────────────────────────


def _capture(monkeypatch):
    seen = SimpleNamespace(cmd=None, temp=None, target_text=None, timeout=None)

    def fake_run(cmd, temp, tool, timeout):
        seen.cmd, seen.temp, seen.timeout = cmd, temp, timeout
        if temp:
            seen.target_text = Path(temp).read_text()
            Path(temp).unlink()

    monkeypatch.setattr(runner, "program", lambda name: f"/managed/{name}")
    monkeypatch.setattr(runner, "_run_tool", fake_run)
    return seen


def test_run_dalfox_argv(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    runner.run_dalfox(["https://a.test/?q=1"], tmp_path / "d.json", worker=20, delay=250)
    assert seen.cmd[0] == "/managed/dalfox"
    # The scan subcommand is required for scan flags; `dalfox file` is legacy.
    assert seen.cmd[1] == "scan"
    assert seen.cmd[seen.cmd.index("--input-type") + 1] == "file"
    assert seen.temp in seen.cmd
    assert seen.cmd[seen.cmd.index("--format") + 1] == "json"
    assert seen.cmd[seen.cmd.index("--output") + 1] == str(tmp_path / "d.json")
    assert seen.cmd[seen.cmd.index("--workers") + 1] == "20"
    assert seen.cmd[seen.cmd.index("--delay") + 1] == "250"
    for flag in ("--silence", "--no-color"):
        assert flag in seen.cmd
    assert seen.target_text == "https://a.test/?q=1"
    assert "--skip-mining" not in seen.cmd


def test_run_dalfox_bounds_total_concurrency_not_just_per_target(monkeypatch, tmp_path):
    """`--workers` is per target and targets run concurrently, so the two multiply.

    Left at dalfox's defaults a job could have 2,500 requests in flight at a
    client's host.
    """
    seen = _capture(monkeypatch)
    runner.run_dalfox(["https://a.test"], tmp_path / "d.json")
    assert seen.cmd[seen.cmd.index("--max-concurrent-targets") + 1] == str(
        runner.DALFOX_MAX_CONCURRENT_TARGETS
    )
    assert runner.DALFOX_MAX_CONCURRENT_TARGETS <= 10


def test_run_dalfox_never_requests_request_or_response_bodies(monkeypatch, tmp_path):
    """--include-all would ship a client's response bodies to the backend."""
    seen = _capture(monkeypatch)
    runner.run_dalfox(["https://a.test"], tmp_path / "d.json")
    for flag in ("--include-all", "--include-request", "--include-response"):
        assert flag not in seen.cmd


def test_run_dalfox_skips_mining_when_disabled(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    runner.run_dalfox(["https://a.test"], tmp_path / "d.json", mining=False)
    assert "--skip-mining" in seen.cmd


# ── handler ─────────────────────────────────────────────────────────────────


def test_handler_is_registered_and_installable():
    assert "dalfox" in handlers.REGISTRY
    assert "dalfox" in runner.ALLOWED_TOOLS
    assert toolchain.manageable("dalfox")


def test_execute_returns_the_report(monkeypatch, tmp_path):
    handler = handlers.REGISTRY["dalfox"]
    monkeypatch.setattr(
        runner,
        "run_dalfox",
        lambda targets, output, **kw: output.write_text(json.dumps(_report())),
    )
    out = handler.execute(["https://a.test"], tmp_path, configs.DalfoxConfig.from_dict({}))
    assert out == tmp_path / "dalfox.json"
    # Uploaded as dalfox wrote it: the tier is not translated here.
    assert json.loads(out.read_text())["findings"][0]["type"] == "V"


def test_execute_fails_when_no_report_is_written(monkeypatch, tmp_path):
    """An absent report means unknown, which is not "no XSS found"."""
    handler = handlers.REGISTRY["dalfox"]
    monkeypatch.setattr(runner, "run_dalfox", lambda targets, output, **kw: None)
    with pytest.raises(runner.ToolError, match="unknown"):
        handler.execute(["https://a.test"], tmp_path, configs.DalfoxConfig.from_dict({}))


def test_execute_passes_the_configured_load_controls(monkeypatch, tmp_path):
    handler = handlers.REGISTRY["dalfox"]
    seen = {}

    def fake(targets, output, **kwargs):
        seen.update(kwargs)
        output.write_text(json.dumps(_report()))

    monkeypatch.setattr(runner, "run_dalfox", fake)
    cfg = configs.DalfoxConfig.from_dict({"worker": 5, "delay": 100, "mining": False})
    handler.execute(["https://a.test"], tmp_path, cfg)
    assert seen["worker"] == 5 and seen["delay"] == 100 and seen["mining"] is False


def test_upload_reports_new_candidates_not_findings(monkeypatch, tmp_path):
    """The backend dedupes dalfox, and nothing here has been verified."""
    handler = handlers.REGISTRY["dalfox"]
    output = tmp_path / "dalfox.json"
    output.write_text(json.dumps(_report()))
    client = MagicMock()
    client.import_file.return_value = {"import_record": {"imported_count": 3}}
    summary = handler.upload(client, "e1", output, job_id="j1")
    assert summary == "imported 3 new XSS candidate(s)"
    assert client.import_file.call_args[0][:2] == ("e1", "dalfox")
    assert client.import_file.call_args.kwargs["job_id"] == "j1"


def test_upload_surfaces_an_incomplete_scan(tmp_path):
    """An incomplete scan that found nothing is not evidence of nothing to find."""
    handler = handlers.REGISTRY["dalfox"]
    output = tmp_path / "dalfox.json"
    output.write_text(json.dumps(_report(incomplete=True, findings=0)))
    client = MagicMock()
    client.import_file.return_value = {"import_record": {"imported_count": 0}}
    assert "incomplete" in handler.upload(client, "e1", output)


@pytest.mark.parametrize(
    "text", ["not json", json.dumps({"findings": []}), json.dumps({"meta": "nope"}), ""]
)
def test_incomplete_check_tolerates_a_report_it_cannot_read(tmp_path, text):
    path = tmp_path / "d.json"
    path.write_text(text)
    assert handlers._dalfox_incomplete(path) is False


def test_resolve_targets_dedupes_urls(monkeypatch):
    handler = handlers.REGISTRY["dalfox"]
    monkeypatch.setattr(
        handlers,
        "_resolve_standard",
        lambda *a, **k: ["https://a.test/?q=1", "https://a.test/?q=1", " ", "https://b.test/?x=2"],
    )
    assert handler.resolve_targets(
        MagicMock(), "e1", "recon", configs.DalfoxConfig.from_dict({})
    ) == [
        "https://a.test/?q=1",
        "https://b.test/?x=2",
    ]


def test_running_label_states_the_load_controls():
    handler = handlers.REGISTRY["dalfox"]
    cfg = configs.DalfoxConfig.from_dict({"worker": 5, "delay": 100, "mining": False})
    label = handler.running_label(["https://a.test"], cfg)
    assert "5 workers/target" in label and "100ms" in label and "no mining" in label


# ── the nested-archive install path ─────────────────────────────────────────


def _manifest(member: str | None, binary: str = "dalfox"):
    asset: dict = {"url": "https://example.test/a.tar.gz", "sha256": "0" * 64}
    if member is not None:
        asset["member"] = member
    return {
        "schema_version": toolchain.SCHEMA_VERSION,
        "tools": {
            "dalfox": {
                "version": "3.2.4",
                "binary": binary,
                "version_args": ["--version"],
                "platforms": {"linux-amd64": asset},
            }
        },
    }


def test_a_nested_member_is_accepted():
    """dalfox ships its binary one directory down, unlike every other pinned tool."""
    toolchain.validate_manifest(_manifest("dalfox-v3.2.4-linux-x86_64/dalfox"))


def test_an_absent_member_still_means_the_archive_root():
    toolchain.validate_manifest(_manifest(None))


@pytest.mark.parametrize(
    "member",
    [
        "../../etc/passwd/dalfox",  # climbing
        "/abs/dalfox",  # absolute
        "dir\\dalfox",  # backslash
        "dir/other",  # does not install the binary this entry names
        "dalfox.exe",  # wrong platform's binary
        "",
        "dir//dalfox",
    ],
)
def test_a_member_that_could_redirect_the_install_is_refused(member):
    """Extraction is "copy exactly this entry"; the name must not be able to wander."""
    with pytest.raises(toolchain.ToolchainError, match="member"):
        toolchain.validate_manifest(_manifest(member))


def test_shipped_dalfox_pins_a_nested_member_for_every_platform():
    entry = toolchain.load_manifest()["tools"]["dalfox"]
    assert entry["version_args"] == ["--version"]
    assert set(entry["platforms"]) == {
        "linux-amd64",
        "linux-arm64",
        "macos-amd64",
        "macos-arm64",
        "windows-amd64",
    }
    for key, asset in entry["platforms"].items():
        expected = "dalfox.exe" if key.startswith("windows-") else "dalfox"
        assert asset["member"].endswith(f"/{expected}"), key
