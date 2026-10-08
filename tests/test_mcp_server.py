"""The MCP server: tool surface, read/write hints, filtering, writes, and error mapping.

Skipped entirely when the optional `mcp` extra is not installed. The server is
driven in-process with a fake VardrMapClient — no network, no real agent.
"""

from __future__ import annotations

import asyncio

import pytest
import requests

pytest.importorskip("mcp", reason="requires the optional 'mcp' extra")

from unittest.mock import MagicMock  # noqa: E402

from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402

from vardrrunner import mcp_server  # noqa: E402

# Tools an agent must never have: changing what it may test, or erasing work.
FORBIDDEN = {
    "add_scope",
    "set_scope",
    "update_scope",
    "delete_scope",
    "create_authorization",
    "update_authorization",
    "stop_work",
    "delete_finding",
    "delete_job",
    "delete_engagement",
    "create_api_key",
    "add_member",
    "update_settings",
}
EXPECTED = {
    "list_engagements",
    "get_engagement",
    "list_scope",
    "list_findings",
    "list_assets",
    "list_api_endpoints",
    "list_recon",
    "list_jobs",
    "get_job_events",
    "list_reports",
    "preview_job",
    "queue_job",
    "queue_pipeline",
    "create_finding",
}


def _server(fake):
    return mcp_server.build_server(client_factory=lambda: fake)


def _tools(srv):
    return {t.name: t for t in asyncio.run(srv.list_tools())}


def _call(srv, name, **args):
    """Invoke a tool; return its structured content, or raise the SDK ToolError."""
    result = asyncio.run(srv.call_tool(name, args))
    return result.structured_content


def _http_error(status, detail=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = {"detail": detail} if detail is not None else {}
    return requests.HTTPError(response=resp)


# ── tool surface and hints ───────────────────────────────────────────────────


def test_exposes_exactly_the_expected_tools():
    tools = _tools(_server(MagicMock()))
    assert set(tools) == EXPECTED
    assert not (set(tools) & FORBIDDEN)


def test_read_tools_are_marked_read_only_and_writes_are_not():
    tools = _tools(_server(MagicMock()))
    read = {
        "list_engagements",
        "get_engagement",
        "list_scope",
        "list_findings",
        "list_assets",
        "list_api_endpoints",
        "list_recon",
        "list_jobs",
        "get_job_events",
        "list_reports",
        "preview_job",  # a dry run changes nothing
    }
    for name in read:
        assert tools[name].annotations.read_only_hint is True, name
    for name in ("queue_job", "queue_pipeline", "create_finding"):
        assert tools[name].annotations.read_only_hint is False, name
        assert tools[name].annotations.destructive_hint is False, name


def test_server_instructions_warn_about_untrusted_data_and_scope():
    srv = _server(MagicMock())
    assert "untrusted data" in srv.instructions
    assert "cannot change" in srv.instructions and "scope" in srv.instructions


# ── read tools ────────────────────────────────────────────────────────────────


def test_list_engagements_projects_brief_fields():
    fake = MagicMock()
    fake.engagements.return_value = [
        {
            "id": "e1",
            "name": "Acme",
            "engagement_type": "pentest",
            "engagement_status": "active",
            "client_name": "Acme Inc",
            "secret": "should-not-matter",
        },
    ]
    out = _call(_server(fake), "list_engagements")
    assert out["count"] == 1
    assert out["items"][0] == {
        "id": "e1",
        "name": "Acme",
        "engagement_type": "pentest",
        "status": "active",
        "client": "Acme Inc",
    }


def test_get_engagement_includes_scope_and_tolerates_missing_stats():
    fake = MagicMock()
    fake.engagement.return_value = {
        "id": "e1",
        "name": "Acme",
        "scope": {"in": [{"value": "*.acme.com"}], "out": [{"value": "admin.acme.com"}]},
    }
    fake.get.side_effect = _http_error(500)  # stats endpoint errors
    out = _call(_server(fake), "get_engagement", engagement_id="e1")
    assert out["scope_in"] == [{"value": "*.acme.com"}]
    assert out["scope_out"] == [{"value": "admin.acme.com"}]
    assert out["stats"] == {}  # swallowed, not fatal


def test_list_findings_filters_by_severity():
    fake = MagicMock()
    fake.get.return_value = {
        "findings": [
            {"id": "f1", "severity": "high"},
            {"id": "f2", "severity": "low"},
            {"id": "f3", "severity": "High"},
        ],
        "total": 3,
    }
    out = _call(_server(fake), "list_findings", engagement_id="e1", severity="high")
    assert {f["id"] for f in out["items"]} == {"f1", "f3"}  # case-insensitive
    assert fake.get.call_args[0][0] == "/engagements/e1/findings"


def test_list_recon_filters_by_source():
    fake = MagicMock()
    fake.recon.return_value = [
        {"url": "a", "source": "katana"},
        {"url": "b", "source": "gau"},
        {"url": "c", "source": "katana"},
    ]
    out = _call(_server(fake), "list_recon", engagement_id="e1", source="katana")
    assert [r["url"] for r in out["items"]] == ["a", "c"]


def test_list_jobs_filters_by_status():
    fake = MagicMock()
    fake.get.return_value = {
        "jobs": [
            {"id": "j1", "status": "running"},
            {"id": "j2", "status": "done"},
        ]
    }
    out = _call(_server(fake), "list_jobs", engagement_id="e1", status="done")
    assert [j["id"] for j in out["items"]] == ["j2"]


def test_results_are_capped_with_true_total():
    fake = MagicMock()
    fake.get.return_value = {"assets": [{"id": i} for i in range(10)], "total": 100}
    out = _call(_server(fake), "list_assets", engagement_id="e1", limit=3)
    assert out["shown"] == 3 and out["count"] == 100 and out["truncated"] is True


def test_limit_is_clamped_to_max():
    fake = MagicMock()
    fake.recon.return_value = [{"url": str(i)} for i in range(5)]
    _call(_server(fake), "list_recon", engagement_id="e1", limit=99999)
    # recon() is asked for at most MAX_LIMIT, never the absurd value.
    assert fake.recon.call_args.kwargs["limit"] == mcp_server.MAX_LIMIT


# ── write tools ───────────────────────────────────────────────────────────────


def test_queue_job_posts_expected_body_and_returns_warnings():
    fake = MagicMock()
    fake.post.return_value = {
        "id": "job1",
        "status": "pending",
        "warnings": [{"reason": "target_out_of_scope"}],
    }
    out = _call(
        _server(fake),
        "queue_job",
        engagement_id="e1",
        tool_type="httpx",
        target_source="recon",
        config={"limit": 50},
    )
    (path,) = fake.post.call_args[0]
    assert path == "/engagements/e1/jobs"
    assert fake.post.call_args.kwargs["json"] == {
        "tool_type": "httpx",
        "target_source": "recon",
        "config": {"limit": 50},
    }
    assert out["warnings"][0]["reason"] == "target_out_of_scope"


def test_preview_job_hits_the_preview_endpoint():
    fake = MagicMock()
    fake.post.return_value = {"count": 12, "sample": ["a", "b"], "truncated": False}
    out = _call(_server(fake), "preview_job", engagement_id="e1", tool_type="nuclei")
    assert fake.post.call_args[0][0] == "/engagements/e1/jobs/preview"
    assert out["count"] == 12


def test_queue_pipeline_posts_stages():
    fake = MagicMock()
    fake.post.return_value = {"jobs": [{"id": "j1"}, {"id": "j2"}]}
    stages = [
        {"tool_type": "subfinder", "target_source": "scope", "config": {}},
        {"tool_type": "httpx", "target_source": "recon", "config": {}},
    ]
    out = _call(_server(fake), "queue_pipeline", engagement_id="e1", stages=stages)
    assert fake.post.call_args[0][0] == "/engagements/e1/pipelines"
    assert fake.post.call_args.kwargs["json"] == {"stages": stages}
    assert len(out["jobs"]) == 2


def test_create_finding_posts_body():
    fake = MagicMock()
    fake.post.return_value = {"id": "f1", "title": "IDOR"}
    _call(
        _server(fake),
        "create_finding",
        engagement_id="e1",
        title="IDOR",
        severity="high",
        summary="s",
        asset="api.acme.com",
        steps="1,2,3",
    )
    assert fake.post.call_args[0][0] == "/engagements/e1/findings"
    body = fake.post.call_args.kwargs["json"]
    assert (
        body["title"] == "IDOR" and body["severity"] == "high" and body["asset"] == "api.acme.com"
    )


# ── error mapping ─────────────────────────────────────────────────────────────


def test_404_becomes_a_non_revealing_tool_error():
    fake = MagicMock()
    fake.engagement.side_effect = _http_error(404, "Engagement not found")
    with pytest.raises(ToolError, match="another user"):
        _call(_server(fake), "get_engagement", engagement_id="x")


def test_400_detail_is_forwarded_to_the_agent():
    fake = MagicMock()
    fake.post.side_effect = _http_error(400, "tool_type must be one of [...]")
    with pytest.raises(ToolError, match="tool_type must be one of"):
        _call(_server(fake), "queue_job", engagement_id="e1", tool_type="bogus")


def test_connection_failure_is_readable():
    fake = MagicMock()
    fake.engagements.side_effect = requests.ConnectionError("refused")
    with pytest.raises(ToolError, match="Could not reach VardrMap"):
        _call(_server(fake), "list_engagements")


def test_unconfigured_client_surfaces_a_login_hint():
    def boom():
        raise RuntimeError("Not logged in")

    srv = mcp_server.build_server(client_factory=boom)
    with pytest.raises(ToolError, match="not configured"):
        _call(srv, "list_engagements")
