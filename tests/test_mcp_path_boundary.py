"""MCP identifiers cannot turn an allowed tool into a withheld HTTP operation."""

import asyncio
import json
from urllib.parse import urlsplit

import pytest
import requests

pytest.importorskip("mcp", reason="requires the optional 'mcp' extra")

from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402

from vardrrunner import api, mcp_server  # noqa: E402

WRITES = [
    ("preview_job", {"tool_type": "httpx"}, "jobs/preview"),
    ("queue_job", {"tool_type": "httpx"}, "jobs"),
    ("queue_pipeline", {"stages": []}, "pipelines"),
    ("draft_test_cases", {"endpoint_ids": ["ep1"]}, "test-cases/preview"),
    ("draft_report", {"title": "Synthetic draft"}, "reports"),
    ("create_finding", {"title": "Synthetic draft", "severity": "info"}, "findings"),
    ("propose_scope_item", {"value": "synthetic.invalid"}, "proposals"),
    ("propose_authorization", {}, "proposals"),
    ("propose_rate_ceiling", {"rate": 1}, "proposals"),
]
READS = [
    ("get_engagement", {}),
    ("list_scope", {}),
    ("list_findings", {}),
    ("list_assets", {}),
    ("list_api_endpoints", {}),
    ("list_recon", {}),
    ("list_jobs", {}),
    ("list_reports", {}),
    ("list_authorizations", {}),
    ("list_deliverables", {}),
    ("get_deliverable_revision", {"deliverable_id": "d1", "revision": 1}),
    ("get_finding_activity", {"finding_id": "f1"}),
    ("list_api_playbooks", {}),
    ("get_api_playbook", {"playbook_id": "API-01"}),
    ("list_evidence", {}),
    ("list_proposals", {}),
]
ATTACKS = [
    "e/proposals/private-synthetic-marker/approve?ignored=",
    "e/proposals/p/approve#",
    "e/../proposals/p/approve?",
    "e\\..\\proposals\\p\\approve?",
    "e%2fproposals%2fp%2fapprove%3f",
    "e%252fproposals%252fp%252fapprove%253f",
    "%2e%2e",
    ".",
    "..",
    "",
    "e?ignored=",
    "e#fragment",
    "e\r\n/approve",
    " e",
    "e ",
    "e\x00",
    "é",
]
LEGITIMATE = ["e1", "00000000-0000-0000-0000-000000000001", "legacy_ID-9.v1~"]


@pytest.fixture
def transport(monkeypatch):
    """Real MCP/API routing with a synthetic key and HTTP interception, never a socket."""
    client = api.VardrMapClient("https://synthetic.invalid/backend", "synthetic-no-authority")
    calls = []

    def forbidden_send(*args, **kwargs):
        raise AssertionError("Network is forbidden in route-boundary tests")

    def intercepted(method, url, **kwargs):
        prepared = requests.Request(
            method, url, json=kwargs.get("json"), params=kwargs.get("params")
        ).prepare()
        calls.append((prepared.method, urlsplit(prepared.url)))
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({"total": 0, "events": [], "activities": []}).encode()
        return response

    monkeypatch.setattr(requests.Session, "send", forbidden_send)
    monkeypatch.setattr(client.session, "request", intercepted)
    return mcp_server.build_server(client_factory=lambda: client), calls


def invoke(server, tool, arguments):
    return asyncio.run(server.call_tool(tool, arguments))


@pytest.mark.parametrize("tool,arguments,suffix", WRITES)
@pytest.mark.parametrize("identifier", ATTACKS)
def test_write_and_read_only_post_tools_refuse_route_injection(
    transport, tool, arguments, suffix, identifier
):
    server, calls = transport
    with pytest.raises(ToolError, match="Invalid route identifier") as error:
        invoke(server, tool, {"engagement_id": identifier, **arguments})
    assert "private-synthetic-marker" not in str(error.value)
    assert calls == []  # No proposal creation, approval, or other HTTP operation.


@pytest.mark.parametrize("tool,arguments", READS)
def test_read_engagement_routes_refuse_injection(transport, tool, arguments):
    server, calls = transport
    with pytest.raises(ToolError, match="Invalid route identifier"):
        invoke(server, tool, {"engagement_id": ATTACKS[0], **arguments})
    assert calls == []


@pytest.mark.parametrize(
    "tool,arguments,field",
    [
        ("get_job_events", {}, "job_id"),
        ("get_deliverable_revision", {"engagement_id": "e1", "revision": 1}, "deliverable_id"),
        ("get_finding_activity", {"engagement_id": "e1"}, "finding_id"),
        ("get_api_playbook", {"engagement_id": "e1"}, "playbook_id"),
    ],
)
@pytest.mark.parametrize("identifier", ATTACKS)
def test_nested_path_identifiers_cannot_change_routes(
    transport, tool, arguments, field, identifier
):
    server, calls = transport
    with pytest.raises(ToolError):
        invoke(server, tool, {**arguments, field: identifier})
    assert calls == []


@pytest.mark.parametrize("tool,arguments,suffix", WRITES)
@pytest.mark.parametrize("identifier", LEGITIMATE)
def test_legitimate_identifiers_preserve_exact_post_route(
    transport, tool, arguments, suffix, identifier
):
    server, calls = transport
    invoke(server, tool, {"engagement_id": identifier, **arguments})
    assert len(calls) == 1
    method, url = calls[0]
    assert method == "POST"
    assert url.netloc == "synthetic.invalid"
    assert url.path == f"/backend/engagements/{identifier}/{suffix}"
    assert url.query == url.fragment == ""


@pytest.mark.parametrize(
    "tool,arguments,path",
    [
        ("get_job_events", {"job_id": "job_1.v2~"}, "/jobs/job_1.v2~/events"),
        (
            "get_deliverable_revision",
            {"engagement_id": "e1", "deliverable_id": "d_1.v2~", "revision": 2},
            "/engagements/e1/deliverables/d_1.v2~/revisions/2",
        ),
        (
            "get_finding_activity",
            {"engagement_id": "e1", "finding_id": "f_1.v2~"},
            "/engagements/e1/findings/f_1.v2~/activity",
        ),
    ],
)
def test_legitimate_nested_identifiers_preserve_exact_read_route(transport, tool, arguments, path):
    server, calls = transport
    invoke(server, tool, arguments)
    assert len(calls) == 1
    assert calls[0][0] == "GET" and calls[0][1].path == "/backend" + path
