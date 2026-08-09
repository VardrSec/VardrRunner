"""Unit tests for the tool handlers and registry."""

import json
from unittest.mock import MagicMock, patch

import pytest

from vardrrunner import configs, handlers


def test_registry_covers_all_tools():
    assert set(handlers.REGISTRY) == {
        "httpx",
        "nuclei",
        "nmap",
        "subfinder",
        "dnsx",
        "naabu",
        "vardrgate_api_test",
    }
    for name, handler in handlers.REGISTRY.items():
        assert handler.tool == name


def test_parse_config_returns_typed_config():
    cfg = handlers.REGISTRY["httpx"].parse_config({"limit": 5})
    assert isinstance(cfg, configs.HttpxConfig) and cfg.limit == 5


def test_parse_config_propagates_validation_error():
    with pytest.raises(configs.ConfigError):
        handlers.REGISTRY["nmap"].parse_config({"timing": 9})


def test_default_running_label():
    label = handlers.HttpxHandler().running_label(["a", "b"], configs.HttpxConfig())
    assert label == "httpx against 2 target(s)"


def test_nuclei_running_label_includes_severity():
    label = handlers.NucleiHandler().running_label(["a"], configs.NucleiConfig(severity="high"))
    assert "severity=high" in label


def test_nmap_resolve_normalizes_and_dedupes_hosts():
    client = MagicMock()
    with patch(
        "vardrrunner.handlers._resolve_standard",
        return_value=["https://a.com/x", "http://a.com/y", "10.0.0.1:80"],
    ):
        out = handlers.NmapHandler().resolve_targets(client, "p", "recon", configs.NmapConfig())
    assert out == ["a.com", "10.0.0.1"]


def test_nmap_upload_no_services_skips_create(tmp_path):
    client = MagicMock()
    with patch("vardrrunner.runner.parse_nmap_xml", return_value=[]):
        summary = handlers.NmapHandler().upload(client, "p", tmp_path / "nmap.xml")
    assert "no open ports" in summary
    client.create_services.assert_not_called()


def test_nmap_upload_posts_services(tmp_path):
    client = MagicMock()
    client.create_services.return_value = {"created": 1, "updated": 2}
    svcs = [{"host": "h", "port": 80}]
    with patch("vardrrunner.runner.parse_nmap_xml", return_value=svcs):
        summary = handlers.NmapHandler().upload(client, "p", tmp_path / "nmap.xml")
    client.create_services.assert_called_once_with("p", svcs)
    assert "1 new" in summary and "2 updated" in summary


def test_subfinder_execute_builds_jsonl(tmp_path):
    def fake_run(domains, out, timeout=None):
        out.write_text("a.example.com\nb.example.com\n")
        return 0

    with patch("vardrrunner.runner.run_subfinder", side_effect=fake_run):
        out = handlers.SubfinderHandler().execute(
            ["example.com"], tmp_path, configs.SubfinderConfig()
        )
    assert out is not None and out.name == "subfinder_httpx.jsonl"
    lines = out.read_text().splitlines()
    assert len(lines) == 2 and '"host": "a.example.com"' in lines[0]


def test_subfinder_execute_no_results_returns_none(tmp_path):
    def fake_run(domains, out, timeout=None):
        out.write_text("")
        return 0

    with patch("vardrrunner.runner.run_subfinder", side_effect=fake_run):
        out = handlers.SubfinderHandler().execute(
            ["example.com"], tmp_path, configs.SubfinderConfig()
        )
    assert out is None


def test_subfinder_resolve_extracts_wildcard_domains():
    client = MagicMock()
    client.scope.return_value = {
        "in": [
            {"value": "*.example.com"},
            {"value": "app.example.com"},  # not a wildcard — skipped
            {"value": "*.target.io"},
        ],
        "out": [],
    }
    out = handlers.SubfinderHandler().resolve_targets(
        client, "p", "scope", configs.SubfinderConfig()
    )
    assert out == ["example.com", "target.io"]


def _vardrgate_cfg() -> configs.VardrGateConfig:
    return configs.VardrGateConfig.from_dict(
        {
            "test_case": {
                "id": "profile-check",
                "request": {"method": "GET", "url": "https://api.example.com/users/42"},
            },
            "execution": {"timeout_seconds": 10},
        }
    )


def test_vardrgate_parse_config_requires_test_case():
    with pytest.raises(configs.ConfigError):
        handlers.REGISTRY["vardrgate_api_test"].parse_config({"execution": {}})


def test_vardrgate_resolve_targets_uses_request_url():
    out = handlers.VardrGateHandler().resolve_targets(MagicMock(), "p", "config", _vardrgate_cfg())
    assert out == ["https://api.example.com/users/42"]


def test_vardrgate_resolve_targets_falls_back_to_id():
    cfg = configs.VardrGateConfig.from_dict({"test_case": {"id": "no-url-case"}, "execution": {}})
    out = handlers.VardrGateHandler().resolve_targets(MagicMock(), "p", "config", cfg)
    assert out == ["no-url-case"]


def test_vardrgate_execute_writes_result(tmp_path):
    captured = {}

    def fake_run(job, out, timeout=None):
        captured["job"] = job
        captured["timeout"] = timeout
        out.write_text('{"test_case_id":"profile-check","findings":[]}')

    with patch("vardrrunner.runner.run_vardrgate", side_effect=fake_run):
        out = handlers.VardrGateHandler().execute([], tmp_path, _vardrgate_cfg())

    assert out is not None and out.name == "vardrgate_result.json"
    # The envelope handed to the binary carries the test case and execution block.
    assert captured["job"]["config"]["test_case"]["id"] == "profile-check"
    assert captured["timeout"] == 10


def test_vardrgate_upload_posts_result_to_job(tmp_path):
    client = MagicMock()
    result = tmp_path / "vardrgate_result.json"
    result.write_text(
        '{"findings":[{"category":"potential_bola"},{"category":"unexpected_access"}]}'
    )

    summary = handlers.VardrGateHandler().upload(client, "p", result, job_id="job_abc")

    client.post.assert_called_once()
    path_arg = client.post.call_args[0][0]
    assert path_arg == "/jobs/job_abc/upload"
    assert "2 finding(s)" in summary


def test_vardrgate_upload_without_job_id_skips_post(tmp_path):
    client = MagicMock()
    result = tmp_path / "vardrgate_result.json"
    result.write_text('{"findings":[]}')

    summary = handlers.VardrGateHandler().upload(client, "p", result)

    client.post.assert_not_called()
    assert "0 finding(s)" in summary


def test_resolve_secrets_from_env(monkeypatch):
    monkeypatch.setenv("OWNER_TOKEN", "s3cr3t")
    tc = {
        "identities": [
            {"id": "owner", "credential": {"type": "bearer", "value_env": "OWNER_TOKEN"}}
        ]
    }
    out = handlers._resolve_identity_secrets(tc)
    cred = out["identities"][0]["credential"]
    assert cred["value"] == "s3cr3t"
    assert "value_env" not in cred
    # The original is not mutated (deep copy).
    assert "value" not in tc["identities"][0]["credential"]


def test_resolve_secrets_missing_env_fails(monkeypatch):
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    tc = {
        "identities": [{"id": "owner", "credential": {"type": "bearer", "value_env": "NOPE_TOKEN"}}]
    }
    with pytest.raises(configs.ConfigError):
        handlers._resolve_identity_secrets(tc)


def test_resolve_secrets_from_keychain():
    tc = {"identities": [{"id": "o", "credential": {"type": "bearer", "value_keychain": "acct"}}]}
    with patch("vardrrunner.keychain.get_secret", return_value="kc-secret") as gs:
        out = handlers._resolve_identity_secrets(tc)
    gs.assert_called_once_with("acct")
    assert out["identities"][0]["credential"]["value"] == "kc-secret"


def test_resolve_secrets_missing_keychain_fails():
    tc = {"identities": [{"id": "o", "credential": {"type": "bearer", "value_keychain": "acct"}}]}
    with patch("vardrrunner.keychain.get_secret", return_value=None):
        with pytest.raises(configs.ConfigError):
            handlers._resolve_identity_secrets(tc)


def test_resolve_secrets_ambiguous_fails(monkeypatch):
    monkeypatch.setenv("T", "x")
    tc = {
        "identities": [
            {"id": "o", "credential": {"type": "bearer", "value": "lit", "value_env": "T"}}
        ]
    }
    with pytest.raises(configs.ConfigError):
        handlers._resolve_identity_secrets(tc)


def test_resolve_secrets_literal_and_anonymous_untouched():
    tc = {
        "identities": [
            {"id": "lit", "credential": {"type": "bearer", "value": "keep-me"}},
            {"id": "anon", "credential": {"type": "static_header", "header": "", "value": ""}},
        ]
    }
    out = handlers._resolve_identity_secrets(tc)
    assert out["identities"][0]["credential"]["value"] == "keep-me"
    assert out["identities"][1]["credential"]["value"] == ""


def test_vardrgate_execute_resolves_env_secret(monkeypatch, tmp_path):
    monkeypatch.setenv("OWNER_TOKEN", "resolved-token")
    cfg = configs.VardrGateConfig.from_dict(
        {
            "test_case": {
                "id": "x",
                "identities": [
                    {"id": "o", "credential": {"type": "bearer", "value_env": "OWNER_TOKEN"}}
                ],
                "request": {"url": "https://a/"},
            },
            "execution": {},
        }
    )
    captured = {}

    def fake_run(job, out, timeout=None):
        captured["job"] = job
        out.write_text('{"findings":[]}')

    with patch("vardrrunner.runner.run_vardrgate", side_effect=fake_run):
        handlers.VardrGateHandler().execute([], tmp_path, cfg)

    cred = captured["job"]["config"]["test_case"]["identities"][0]["credential"]
    assert cred["value"] == "resolved-token" and "value_env" not in cred


def test_httpx_upload_summary(tmp_path):
    client = MagicMock()
    client.import_file.return_value = {"import_record": {"imported_count": 3}}
    summary = handlers.HttpxHandler().upload(client, "p", tmp_path / "httpx.jsonl")
    client.import_file.assert_called_once()
    assert "3" in summary


def test_dnsx_execute_builds_recon_jsonl(tmp_path):
    def fake_run(hosts, out, timeout=None):
        out.write_text("a.example.com\nb.example.com\n")
        return 0

    with patch("vardrrunner.runner.run_dnsx", side_effect=fake_run):
        out = handlers.DnsxHandler().execute(["a.example.com"], tmp_path, configs.DnsxConfig())
    assert out is not None and out.name == "dnsx_httpx.jsonl"
    lines = out.read_text().splitlines()
    assert len(lines) == 2 and '"source": "dnsx"' in lines[0]


def test_dnsx_execute_no_results_returns_none(tmp_path):
    with patch(
        "vardrrunner.runner.run_dnsx", side_effect=lambda h, o, timeout=None: o.write_text("")
    ):
        out = handlers.DnsxHandler().execute(["a.example.com"], tmp_path, configs.DnsxConfig())
    assert out is None


def test_naabu_upload_posts_services(tmp_path):
    client = MagicMock()
    client.create_services.return_value = {"created": 2, "updated": 0}
    svcs = [{"host": "h", "port": 80, "protocol": "tcp"}]
    with patch("vardrrunner.runner.parse_naabu_json", return_value=svcs):
        summary = handlers.NaabuHandler().upload(client, "p", tmp_path / "naabu.json")
    client.create_services.assert_called_once_with("p", svcs)
    assert "2 new" in summary


def test_naabu_upload_no_ports_skips_create(tmp_path):
    client = MagicMock()
    with patch("vardrrunner.runner.parse_naabu_json", return_value=[]):
        summary = handlers.NaabuHandler().upload(client, "p", tmp_path / "naabu.json")
    assert "no open ports" in summary
    client.create_services.assert_not_called()


# ---------------------------------------------------------------------------
# extract_handoff_targets
# ---------------------------------------------------------------------------


def test_httpx_extract_handoff_targets_urls(tmp_path):
    f = tmp_path / "httpx.jsonl"
    f.write_text(
        '{"url": "https://app.example.com", "host": "app.example.com"}\n'
        '{"url": "https://api.example.com", "host": "api.example.com"}\n'
    )
    targets = handlers.HttpxHandler().extract_handoff_targets(f)
    assert targets == ["https://app.example.com", "https://api.example.com"]


def test_httpx_extract_handoff_falls_back_to_host(tmp_path):
    f = tmp_path / "httpx.jsonl"
    f.write_text('{"host": "bare.example.com"}\n')
    targets = handlers.HttpxHandler().extract_handoff_targets(f)
    assert targets == ["bare.example.com"]


def test_httpx_extract_handoff_skips_invalid_json(tmp_path):
    f = tmp_path / "httpx.jsonl"
    f.write_text('{"url": "https://a.com"}\nnot-json\n{"url": "https://b.com"}\n')
    targets = handlers.HttpxHandler().extract_handoff_targets(f)
    assert targets == ["https://a.com", "https://b.com"]


def test_httpx_extract_handoff_missing_file(tmp_path):
    assert handlers.HttpxHandler().extract_handoff_targets(tmp_path / "nope.jsonl") == []


def test_subfinder_extract_handoff_targets(tmp_path):
    f = tmp_path / "subfinder_httpx.jsonl"
    f.write_text(
        '{"host": "a.example.com", "source": "subfinder"}\n'
        '{"host": "b.example.com", "source": "subfinder"}\n'
    )
    targets = handlers.SubfinderHandler().extract_handoff_targets(f)
    assert targets == ["a.example.com", "b.example.com"]


def test_dnsx_extract_handoff_targets(tmp_path):
    f = tmp_path / "dnsx_httpx.jsonl"
    f.write_text(
        '{"host": "resolved.example.com", "source": "dnsx"}\n'
        '{"host": "other.example.com", "source": "dnsx"}\n'
    )
    targets = handlers.DnsxHandler().extract_handoff_targets(f)
    assert targets == ["resolved.example.com", "other.example.com"]


def test_nuclei_extract_handoff_targets_is_empty(tmp_path):
    f = tmp_path / "nuclei.jsonl"
    f.write_text('{"template-id": "cve-2021-44228", "host": "https://a.com"}\n')
    assert handlers.NucleiHandler().extract_handoff_targets(f) == []


def test_nmap_extract_handoff_targets_is_empty(tmp_path):
    assert handlers.NmapHandler().extract_handoff_targets(tmp_path / "nmap.xml") == []


# ---------------------------------------------------------------------------
# normalize_handoff_targets
# ---------------------------------------------------------------------------


def test_httpx_normalize_handoff_is_identity():
    targets = ["https://app.example.com", "https://api.example.com"]
    assert handlers.HttpxHandler().normalize_handoff_targets(targets) == targets


def test_nmap_normalize_strips_urls_to_hosts():
    targets = ["https://app.example.com/path", "http://10.0.0.1:8080"]
    result = handlers.NmapHandler().normalize_handoff_targets(targets)
    assert result == ["app.example.com", "10.0.0.1"]


def test_nmap_normalize_deduplicates():
    targets = ["https://app.example.com/x", "https://app.example.com/y"]
    assert handlers.NmapHandler().normalize_handoff_targets(targets) == ["app.example.com"]


def test_dnsx_normalize_strips_urls_to_hosts():
    targets = ["https://sub.example.com"]
    assert handlers.DnsxHandler().normalize_handoff_targets(targets) == ["sub.example.com"]


def test_naabu_normalize_strips_urls_to_hosts():
    targets = ["https://host.example.com:443/path"]
    assert handlers.NaabuHandler().normalize_handoff_targets(targets) == ["host.example.com"]


# ---------------------------------------------------------------------------
# _extract_jsonl_field — error paths
# ---------------------------------------------------------------------------


def test_extract_jsonl_field_oserror_logs_warning(tmp_path, caplog):
    import logging

    missing = tmp_path / "does_not_exist.jsonl"
    with caplog.at_level(logging.WARNING, logger="vardrrunner.handlers"):
        result = handlers._extract_jsonl_field(missing, "url")
    assert result == []
    assert any("Failed to read tool output" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# _write_host_import_jsonl
# ---------------------------------------------------------------------------


def test_write_host_import_jsonl_creates_file(tmp_path):
    out = tmp_path / "out.jsonl"
    handlers._write_host_import_jsonl(["a.example.com", "b.example.com"], "subfinder", out)
    lines = out.read_text().splitlines()
    assert len(lines) == 2
    obj = json.loads(lines[0])
    assert obj == {"host": "a.example.com", "source": "subfinder"}


def test_write_host_import_jsonl_empty_list(tmp_path):
    out = tmp_path / "out.jsonl"
    handlers._write_host_import_jsonl([], "dnsx", out)
    assert out.read_text() == ""
