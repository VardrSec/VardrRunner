"""ffuf: config validation, wordlist resolution, argv, and result merging.

The report fixture mirrors a real `ffuf -of json` run: a top-level "results"
array whose entries carry `input.FUZZ`, `status`, `length`, `words`, `lines` and
`content-type`. VardrMap's own `parse_ffuf` reads exactly those keys, so the
handler preserves ffuf's spelling rather than inventing a compact shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from vardrrunner import configs, handlers, runner, toolchain


def _report(*paths: str) -> dict:
    return {
        "results": [
            {
                "input": {"FUZZ": path.rsplit("/", 1)[-1]},
                "url": f"https://a.test/{path}",
                "status": 200,
                "length": 12,
                "words": 3,
                "lines": 1,
                "content-type": "text/html",
            }
            for path in paths
        ]
    }


# ── configs ─────────────────────────────────────────────────────────────────


def test_config_defaults():
    cfg = configs.FfufConfig.from_dict({})
    assert cfg.wordlist == "common"
    assert cfg.extensions == ()
    assert cfg.match_codes is None
    assert cfg.rate == configs.FFUF_DEFAULT_RATE
    assert cfg.limit == 100


def test_config_parsing_normalizes_extensions_and_codes():
    cfg = configs.FfufConfig.from_dict(
        {
            "wordlist": " api-paths ",
            "extensions": "php, .bak, php",
            "match_codes": [200, "403", 200],
            "rate": "80",
        }
    )
    assert cfg.wordlist == "api-paths"
    # A bare extension gains its dot, and duplicates collapse.
    assert cfg.extensions == (".php", ".bak")
    assert cfg.match_codes == "200,403"
    assert cfg.rate == 80
    assert configs.FfufConfig.from_dict({"match_codes": "all"}).match_codes == "all"


@pytest.mark.parametrize(
    "bad",
    [
        # A wordlist is a name, and nothing path-shaped may pass for one.
        {"wordlist": "../../etc/passwd"},
        {"wordlist": "/usr/share/wordlists/common.txt"},
        {"wordlist": "C:/wordlists/common.txt"},
        {"wordlist": "sub/dir"},
        {"wordlist": "has space"},
        {"wordlist": "UPPER"},
        {"wordlist": "common.txt"},
        {"wordlist": 7},
        {"extensions": ".php;rm -rf /"},
        {"extensions": "-oN"},
        {"extensions": 3},
        {"match_codes": "20x"},
        {"match_codes": "200,everything"},
        {"match_codes": 3.5},
        {"rate": 0},
        {"rate": configs.FFUF_MAX_RATE + 1},
        {"rate": "fast"},
        {"limit": 0},
    ],
)
def test_config_rejects(bad):
    with pytest.raises(configs.ConfigError):
        configs.FfufConfig.from_dict(bad)


@pytest.mark.parametrize(
    "config, accepted",
    [
        # match_codes takes a bare status code, because a JSON caller naturally
        # sends one and VardrMap accepts it.
        ({"match_codes": 200}, True),
        ({"match_codes": [200, 403]}, True),
        ({"match_codes": "200,403"}, True),
        ({"match_codes": True}, False),
        ({"match_codes": 3.5}, False),
        # An extension is never a number, so there is no scalar form to support.
        ({"extensions": ".php"}, True),
        ({"extensions": [".php"]}, True),
        ({"extensions": 3}, False),
        ({"extensions": True}, False),
    ],
)
def test_accepted_types_match_vardrmaps_validator(config, accepted):
    """The two validators must agree on which types pass.

    VardrMap's `_validate_ffuf_config` has the same table (see its
    `test_accepted_types_match_the_runners`). A type this accepts but the
    backend refuses is a job the operator cannot queue; one the backend accepts
    but this refuses clears queue-time validation and then fails on the
    operator's machine, which is exactly what queue-time validation is for.
    """
    if accepted:
        configs.FfufConfig.from_dict(config)
    else:
        with pytest.raises(configs.ConfigError):
            configs.FfufConfig.from_dict(config)


def test_rate_cannot_be_disabled():
    """There is no value that means "unlimited" — the cap is not optional."""
    assert configs.FfufConfig.from_dict({"rate": ""}).rate == configs.FFUF_DEFAULT_RATE
    with pytest.raises(configs.ConfigError):
        configs.FfufConfig.from_dict({"rate": -1})


# ── base_url ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "target,expected",
    [
        ("app.example.test", "https://app.example.test"),
        ("https://app.example.test/", "https://app.example.test"),
        # Content discovery starts at the root, so a recon URL's path is dropped.
        ("https://app.example.test/login?a=1", "https://app.example.test"),
        ("http://10.0.0.1:8080/a/b", "http://10.0.0.1:8080"),
        ("HTTPS://App.Example.Test", "https://app.example.test"),
        ("http://[::1]:8080/a", "http://[::1]:8080"),
        ("*.example.test", ""),
        ("ftp://example.test", ""),
        # Both of these survive a naive "https://" prefix as userinfo + host.
        ("mailto:a@b.test", ""),
        ("javascript:alert(1)", ""),
        # Credentials in a target are never replayed at the host.
        ("https://user:pw@a.test/x", ""),
        ("https://a.test:notaport/x", ""),
        ("   ", ""),
    ],
)
def test_base_url(target, expected):
    assert runner.base_url(target) == expected


# ── wordlist resolution ─────────────────────────────────────────────────────


@pytest.fixture
def wordlists(monkeypatch, tmp_path):
    directory = tmp_path / "wordlists"
    directory.mkdir()
    monkeypatch.setattr(runner.config, "wordlists_dir", lambda: directory)
    return directory


def test_resolve_wordlist_returns_the_named_file(wordlists):
    (wordlists / "common.txt").write_text("admin\nlogin\n")
    assert runner.resolve_wordlist("common") == wordlists / "common.txt"


def test_resolve_wordlist_missing_names_the_directory(wordlists):
    with pytest.raises(runner.ToolError) as exc:
        runner.resolve_wordlist("common")
    assert str(wordlists / "common.txt") in str(exc.value)


def test_resolve_wordlist_refuses_an_empty_file(wordlists):
    (wordlists / "common.txt").write_text("")
    with pytest.raises(runner.ToolError, match="empty"):
        runner.resolve_wordlist("common")


@pytest.mark.parametrize("name", ["../secrets", "a/b", "", "C:/x", "has space"])
def test_resolve_wordlist_refuses_anything_but_a_name(wordlists, name):
    """Defence in depth: the config gate already refused these."""
    (wordlists / "common.txt").write_text("admin\n")
    with pytest.raises(runner.ToolError):
        runner.resolve_wordlist(name)


def test_resolve_wordlist_never_leaves_its_directory(wordlists, tmp_path):
    """A traversal name must not reach a readable file one level up."""
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n")
    with pytest.raises(runner.ToolError):
        runner.resolve_wordlist("../outside")


# ── argv ────────────────────────────────────────────────────────────────────


def _capture(monkeypatch):
    seen = SimpleNamespace(cmd=None, tool=None, timeout=None)

    def fake_run(cmd, temp, tool, timeout):
        seen.cmd, seen.tool, seen.timeout = cmd, tool, timeout

    monkeypatch.setattr(runner, "program", lambda name: f"/managed/{name}")
    monkeypatch.setattr(runner, "_run_tool", fake_run)
    return seen


def test_run_ffuf_argv(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    wordlist = tmp_path / "common.txt"
    runner.run_ffuf("https://a.test", tmp_path / "f.json", wordlist, rate=25, timeout=60)
    assert seen.cmd[0] == "/managed/ffuf"
    assert seen.cmd[seen.cmd.index("-u") + 1] == "https://a.test/FUZZ"
    assert seen.cmd[seen.cmd.index("-of") + 1] == "json"
    assert seen.cmd[seen.cmd.index("-o") + 1] == str(tmp_path / "f.json")
    assert seen.cmd[seen.cmd.index("-rate") + 1] == "25"
    # Auto-calibration is not optional: a catch-all 200 would otherwise import
    # thousands of phantom paths into shared recon.
    assert "-ac" in seen.cmd
    assert "-noninteractive" in seen.cmd
    assert seen.timeout == 60
    assert "-e" not in seen.cmd and "-mc" not in seen.cmd


def test_run_ffuf_passes_the_wordlist_as_a_bare_path(monkeypatch, tmp_path):
    """No `-w path:KEYWORD`: a Windows path's own colon makes that form ambiguous."""
    seen = _capture(monkeypatch)
    wordlist = Path("C:/lists/common.txt")
    runner.run_ffuf("https://a.test", tmp_path / "f.json", wordlist)
    assert seen.cmd[seen.cmd.index("-w") + 1] == str(wordlist)
    assert not any(arg.endswith(":FUZZ") for arg in seen.cmd)


def test_run_ffuf_optional_filters(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    runner.run_ffuf(
        "https://a.test",
        tmp_path / "f.json",
        tmp_path / "w.txt",
        extensions=(".php", ".bak"),
        match_codes="200,403",
    )
    assert seen.cmd[seen.cmd.index("-e") + 1] == ".php,.bak"
    assert seen.cmd[seen.cmd.index("-mc") + 1] == "200,403"


# ── handler ─────────────────────────────────────────────────────────────────


def test_handler_is_registered_and_installable():
    assert "ffuf" in handlers.REGISTRY
    assert "ffuf" in runner.ALLOWED_TOOLS
    assert toolchain.manageable("ffuf")


def test_resolve_targets_collapses_recon_urls_to_unique_roots(monkeypatch):
    handler = handlers.REGISTRY["ffuf"]
    monkeypatch.setattr(
        handlers,
        "_resolve_standard",
        lambda *a, **k: [
            "https://a.test/login",
            "https://a.test/admin",  # same root — fuzzing it twice doubles the load
            "http://b.test:8080/x",
            "*.c.test",  # a wildcard is not a host
            "",
        ],
    )
    cfg = configs.FfufConfig.from_dict({})
    assert handler.resolve_targets(MagicMock(), "e1", "recon", cfg) == [
        "https://a.test",
        "http://b.test:8080",
    ]


def test_execute_runs_once_per_target_and_merges_results(monkeypatch, tmp_path):
    handler = handlers.REGISTRY["ffuf"]
    monkeypatch.setattr(runner, "resolve_wordlist", lambda name: tmp_path / f"{name}.txt")
    calls = []

    def fake_run(target, output, wordlist, **kwargs):
        calls.append((target, kwargs["rate"]))
        # The second target rediscovers /admin; it must be stored once.
        paths = ["admin", "login"] if target == "https://a.test" else ["admin", "backup"]
        output.write_text(json.dumps(_report(*paths)))

    monkeypatch.setattr(runner, "run_ffuf", fake_run)
    cfg = configs.FfufConfig.from_dict({"rate": 10})
    out = handler.execute(["https://a.test", "https://b.test"], tmp_path, cfg)

    assert [c[0] for c in calls] == ["https://a.test", "https://b.test"]
    assert {c[1] for c in calls} == {10}
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["input"]["FUZZ"] for r in records] == ["admin", "login", "backup"]
    # ffuf's own key spelling survives, so VardrMap's parse_ffuf needs no change.
    assert records[0]["content-type"] == "text/html"
    assert records[0]["status"] == 200


def test_execute_returns_none_when_nothing_was_found(monkeypatch, tmp_path):
    handler = handlers.REGISTRY["ffuf"]
    monkeypatch.setattr(runner, "resolve_wordlist", lambda name: tmp_path / "w.txt")
    monkeypatch.setattr(
        runner,
        "run_ffuf",
        lambda target, output, wordlist, **kw: output.write_text(json.dumps({"results": []})),
    )
    assert handler.execute(["https://a.test"], tmp_path, configs.FfufConfig.from_dict({})) is None


def test_execute_propagates_a_tool_failure_instead_of_skipping_a_target(monkeypatch, tmp_path):
    """Quietly skipping a host would report coverage the engagement does not have."""
    handler = handlers.REGISTRY["ffuf"]
    monkeypatch.setattr(runner, "resolve_wordlist", lambda name: tmp_path / "w.txt")

    def boom(target, output, wordlist, **kwargs):
        raise runner.ToolError("ffuf exited with code 2")

    monkeypatch.setattr(runner, "run_ffuf", boom)
    with pytest.raises(runner.ToolError):
        handler.execute(["https://a.test"], tmp_path, configs.FfufConfig.from_dict({}))


def test_execute_fails_when_the_wordlist_is_missing(monkeypatch, tmp_path, wordlists):
    handler = handlers.REGISTRY["ffuf"]
    called = []
    monkeypatch.setattr(runner, "run_ffuf", lambda *a, **k: called.append(a))
    with pytest.raises(runner.ToolError, match="not installed"):
        handler.execute(["https://a.test"], tmp_path, configs.FfufConfig.from_dict({}))
    assert called == []  # nothing was ever launched at the target


@pytest.mark.parametrize(
    "report",
    [
        "not json at all",
        json.dumps({"results": "nope"}),
        json.dumps({}),
        json.dumps([{"url": "https://a.test/x"}]),
    ],
)
def test_an_unreadable_report_fails_rather_than_reporting_no_matches(tmp_path, report):
    """ "Nothing found" and "outcome unknown" must not look the same.

    Returning [] for a broken report would finish the job green while claiming
    this host has nothing on it — recorded as coverage the scan never achieved.
    """
    path = tmp_path / "f.json"
    path.write_text(report)
    with pytest.raises(runner.ToolError, match="unknown"):
        handlers._ffuf_records(path)


def test_a_missing_report_fails(tmp_path):
    with pytest.raises(runner.ToolError, match="unknown"):
        handlers._ffuf_records(tmp_path / "absent.json")


def test_a_valid_empty_report_is_a_real_empty_result(tmp_path):
    """This is the case that legitimately means "ffuf found no matches"."""
    path = tmp_path / "f.json"
    path.write_text(json.dumps({"results": []}))
    assert handlers._ffuf_records(path) == []


def test_one_malformed_entry_does_not_discard_the_rest(tmp_path):
    """The report parsed, so the run is accounted for; skip the bad row only."""
    path = tmp_path / "f.json"
    path.write_text(
        json.dumps(
            {"results": [{"no_url": 1}, "string", {"url": ""}, *_report("admin")["results"]]}
        )
    )
    records = handlers._ffuf_records(path)
    assert [r["url"] for r in records] == ["https://a.test/admin"]


def test_execute_fails_the_job_when_a_report_is_unreadable(monkeypatch, tmp_path):
    handler = handlers.REGISTRY["ffuf"]
    monkeypatch.setattr(runner, "resolve_wordlist", lambda name: tmp_path / "w.txt")
    # ffuf "succeeds" but writes nothing readable — the job must not go green.
    monkeypatch.setattr(runner, "run_ffuf", lambda target, output, wordlist, **kw: None)
    with pytest.raises(runner.ToolError):
        handler.execute(["https://a.test"], tmp_path, configs.FfufConfig.from_dict({}))


def test_upload_chunks_and_reports_the_count(monkeypatch, tmp_path):
    handler = handlers.REGISTRY["ffuf"]
    seen = {}

    def fake_chunks(client, engagement_id, tool, output, max_bytes=None, job_id=""):
        seen.update(tool=tool, job_id=job_id)
        return 7

    monkeypatch.setattr(handlers, "_upload_jsonl_in_chunks", fake_chunks)
    path = tmp_path / "ffuf_import.jsonl"
    path.write_text("")
    assert handler.upload(MagicMock(), "e1", path, job_id="j1") == "imported 7 path(s)"
    assert seen == {"tool": "ffuf", "job_id": "j1"}


def test_handoff_targets_are_the_discovered_urls(tmp_path):
    handler = handlers.REGISTRY["ffuf"]
    path = tmp_path / "ffuf_import.jsonl"
    path.write_text(
        '{"url": "https://a.test/admin"}\n{"url": "https://a.test/admin"}\n{"url": "x"}\n'
    )
    assert handler.extract_handoff_targets(path) == ["https://a.test/admin", "x"]


def test_running_label_states_the_rate_and_wordlist():
    handler = handlers.REGISTRY["ffuf"]
    cfg = configs.FfufConfig.from_dict({"wordlist": "api", "extensions": ".php", "rate": 20})
    label = handler.running_label(["https://a.test"], cfg)
    assert "api" in label and ".php" in label and "20 req/s" in label


# ── manifest ────────────────────────────────────────────────────────────────


def test_version_flag_may_be_uppercase():
    """ffuf's version flag is `-V`; the validator allowed only lowercase before."""
    entry = {
        "version": "2.3.0",
        "binary": "ffuf",
        "version_args": ["-V"],
        "platforms": {"linux-amd64": {"url": "https://example.test/a.tar.gz", "sha256": "0" * 64}},
    }
    toolchain.validate_manifest(
        {"schema_version": toolchain.SCHEMA_VERSION, "tools": {"ffuf": entry}}
    )


@pytest.mark.parametrize("args", [["-w=x"], ["--out file"], ["version"], ["-"], [""], ["-V;id"]])
def test_version_args_still_reject_anything_but_a_bare_flag(args):
    entry = {
        "version": "1.0.0",
        "binary": "ffuf",
        "version_args": args,
        "platforms": {"linux-amd64": {"url": "https://example.test/a.tar.gz", "sha256": "0" * 64}},
    }
    with pytest.raises(toolchain.ToolchainError, match="version_args"):
        toolchain.validate_manifest(
            {"schema_version": toolchain.SCHEMA_VERSION, "tools": {"ffuf": entry}}
        )


def test_ffuf_is_pinned_for_every_supported_platform():
    entry = toolchain.load_manifest()["tools"]["ffuf"]
    assert entry["version_args"] == ["-V"]
    assert set(entry["platforms"]) == {
        "linux-amd64",
        "linux-arm64",
        "macos-amd64",
        "macos-arm64",
        "windows-amd64",
    }
