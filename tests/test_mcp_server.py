"""The MCP server: tool surface, read/write hints, filtering, writes, prompts, errors.

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
    "list_authorizations",
    "list_deliverables",
    "get_deliverable_revision",
    "get_finding_activity",
    "list_methodologies",
    "get_methodology",
    "preview_job",
    "draft_test_cases",
    "queue_job",
    "queue_pipeline",
    "create_finding",
    "draft_report",
}
# Writes that exist in VardrMap and are withheld on purpose. The scope/auth/delete
# set above is withheld so an agent cannot widen what it may test or erase work;
# these two are withheld because they are assertions only a person can make.
FORBIDDEN_ASSERTIONS = {
    "save_test_cases",
    "save_reviewed_cases",
    "create_test_case",
    "create_deliverable",
    "create_deliverable_revision",
    "update_deliverable",
}
EXPECTED_PROMPTS = {"brief", "triage", "untested", "methodology", "retest"}


def _server(fake):
    return mcp_server.build_server(client_factory=lambda: fake)


def _tools(srv):
    return {t.name: t for t in asyncio.run(srv.list_tools())}


def _prompts(srv):
    return {p.name: p for p in asyncio.run(srv.list_prompts())}


def _expand(srv, name, **args):
    """Expand a prompt to the text the agent would receive."""
    result = asyncio.run(srv.get_prompt(name, args))
    parts = []
    for message in result.messages:
        content = message.content
        parts.append(getattr(content, "text", str(content)))
    return "\n".join(parts)


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


def test_no_tool_makes_an_assertion_only_a_person_can_make():
    """Saving a case declares a human reviewed it; a deliverable revision goes to the client.

    Both are drafted or read here and finished by the operator, so neither has a
    tool — distinct from the scope/delete set, which is withheld to bound what a
    compromised agent could do.
    """
    tools = set(_tools(_server(MagicMock())))
    assert not (tools & FORBIDDEN_ASSERTIONS)


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
        "list_authorizations",
        "list_deliverables",
        "get_deliverable_revision",
        "get_finding_activity",
        "list_methodologies",
        "get_methodology",
        "preview_job",  # a dry run changes nothing
        "draft_test_cases",  # generates drafts; stores and queues nothing
    }
    for name in read:
        assert tools[name].annotations.read_only_hint is True, name
    for name in ("queue_job", "queue_pipeline", "create_finding", "draft_report"):
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


@pytest.mark.parametrize(
    "tool,key,path,filter_name,filter_value,max_limit",
    [
        ("list_findings", "findings", "findings", "severity", "high", 200),
        ("list_recon", "recon", "recon", "source", "gau", 500),
        ("list_jobs", "jobs", "jobs", "status", "done", 500),
        ("list_assets", "assets", "assets", None, None, 500),
        ("list_api_endpoints", "endpoints", "api/endpoints", None, None, 500),
        ("list_reports", "reports", "reports", None, None, 200),
    ],
)
def test_pages_use_backend_filters_and_matching_total(
    tool, key, path, filter_name, filter_value, max_limit
):
    fake = MagicMock()
    fake.get.return_value = {key: [{"id": "later-match"}], "total": 601}
    args = {"engagement_id": "e1", "limit": 9999, "offset": 500}
    if filter_name:
        args[filter_name] = filter_value.upper()
    out = _call(_server(fake), tool, **args)
    params = {"limit": max_limit, "offset": 500}
    if filter_name:
        params[filter_name] = filter_value
    fake.get.assert_called_once_with(f"/engagements/e1/{path}", params=params)
    assert out["count"] == 601
    assert out["next_offset"] == 501
    assert out["items"] == [{"id": "later-match"}]
    assert out["truncated"] is True


def test_events_have_next_page_and_last_page():
    fake = MagicMock()
    fake.get.return_value = {"events": [{"id": "last"}], "total": 51}
    out = _call(_server(fake), "get_job_events", job_id="j1", offset=50)
    assert out["next_offset"] is None
    assert out["count"] == 51
    fake.get.assert_called_once_with("/jobs/j1/events", params={"limit": 50, "offset": 50})


def test_empty_page_retains_total_without_looping():
    fake = MagicMock()
    fake.get.return_value = {"recon": [], "total": 10}
    out = _call(_server(fake), "list_recon", engagement_id="e1", offset=20)
    assert out["count"] == 10 and out["shown"] == 0 and out["next_offset"] is None


@pytest.mark.parametrize(
    "tool,args", [("list_recon", {"engagement_id": "e1"}), ("list_engagements", {})]
)
def test_negative_offset_is_rejected(tool, args):
    with pytest.raises(ToolError, match="offset"):
        _call(_server(MagicMock()), tool, offset=-1, **args)


def test_old_backend_does_not_invent_total():
    fake = MagicMock()
    fake.get.return_value = {"recon": [{"id": "one"}]}
    with pytest.raises(ToolError, match="v0.39.0"):
        _call(_server(fake), "list_recon", engagement_id="e1")


def test_engagement_pages_are_reachable():
    fake = MagicMock()
    fake.engagements.return_value = [{"id": str(i)} for i in range(60)]
    out = _call(_server(fake), "list_engagements", offset=50)
    assert out["items"][0]["id"] == "50"
    assert out["count"] == 60 and out["shown"] == 10
    assert out["next_offset"] is None


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


# ── authorizations, deliverables, finding history ─────────────────────────────


def test_list_authorizations_caps_a_bare_list():
    """This endpoint returns a plain array, not a paginated envelope."""
    fake = MagicMock()
    fake.get.return_value = [
        {"id": "a1", "status": "active", "starts_at": "2026-01-01"},
        {"id": "a2", "status": "expired"},
    ]
    out = _call(_server(fake), "list_authorizations", engagement_id="e1")
    fake.get.assert_called_once_with("/engagements/e1/authorizations")
    assert out["count"] == 2
    assert out["items"][0]["id"] == "a1"


def test_list_authorizations_pages_what_it_advertises():
    """A next_offset the caller cannot follow is worse than no paging at all.

    The last record was unreachable: the tool emitted next_offset but took no
    offset argument.
    """
    fake = MagicMock()
    fake.get.return_value = [{"id": f"a{i}"} for i in range(501)]
    srv = _server(fake)
    first = _call(srv, "list_authorizations", engagement_id="e1", limit=500)
    assert (first["count"], first["shown"], first["next_offset"]) == (501, 500, 500)
    last = _call(srv, "list_authorizations", engagement_id="e1", limit=500, offset=500)
    assert last["items"] == [{"id": "a500"}]
    assert last["next_offset"] is None


def test_list_authorizations_rejects_a_negative_offset():
    with pytest.raises(ToolError, match="offset"):
        _call(_server(MagicMock()), "list_authorizations", engagement_id="e1", offset=-1)


def test_list_authorizations_unknown_shape_is_not_reported_as_none():
    """An unreadable response must not become "this engagement has no authorization"."""
    fake = MagicMock()
    fake.get.return_value = {"unexpected": True}
    with pytest.raises(ToolError, match="unknown"):
        _call(_server(fake), "list_authorizations", engagement_id="e1")


def test_list_deliverables_pages():
    fake = MagicMock()
    fake.get.return_value = {"deliverables": [{"id": "d1", "latest_revision": 3}], "total": 1}
    out = _call(_server(fake), "list_deliverables", engagement_id="e1")
    fake.get.assert_called_once_with(
        "/engagements/e1/deliverables", params={"limit": 50, "offset": 0}
    )
    assert out["items"][0]["latest_revision"] == 3


def test_get_deliverable_revision_reads_one_immutable_revision():
    fake = MagicMock()
    fake.get.return_value = {"revision": 2, "markdown": "# Report", "content_hash": "abc"}
    out = _call(
        _server(fake),
        "get_deliverable_revision",
        engagement_id="e1",
        deliverable_id="d1",
        revision=2,
    )
    fake.get.assert_called_once_with("/engagements/e1/deliverables/d1/revisions/2")
    assert out["markdown"] == "# Report"


def test_get_finding_activity_pages_the_history():
    fake = MagicMock()
    fake.get.return_value = {"activities": [{"kind": "retest"}], "total": 1}
    out = _call(_server(fake), "get_finding_activity", engagement_id="e1", finding_id="f1")
    fake.get.assert_called_once_with(
        "/engagements/e1/findings/f1/activity", params={"limit": 50, "offset": 0}
    )
    assert out["items"][0]["kind"] == "retest"


# ── methodologies ─────────────────────────────────────────────────────────────


def test_list_methodologies_needs_no_api_call_and_names_the_edition():
    """The checklists ship with the package; nothing is fetched to read them."""
    fake = MagicMock()
    out = _call(_server(fake), "list_methodologies")
    assert fake.mock_calls == []
    versions = {row["id"]: row["version"] for row in out["items"]}
    assert versions == {"owasp-api-top10": "2023", "owasp-wstg": "4.2"}
    assert "never coverage" in out["note"]
    # by_method counts how items are tested, not whether they have been.
    assert "not whether they have been" in out["note"]
    assert set(out["items"][0]["by_method"]) == {"tooling", "manual"}


def test_get_methodology_pages_items_and_echoes_the_version():
    fake = MagicMock()
    srv = _server(fake)
    first = _call(srv, "get_methodology", methodology_id="owasp-api-top10", limit=4)
    assert fake.mock_calls == []
    assert (first["count"], first["shown"], first["next_offset"]) == (10, 4, 4)
    assert first["version"] == "2023" and first["methodology"] == "owasp-api-top10"
    assert "CC BY-SA" in first["attribution"]
    assert first["items"][0]["id"] == "API1:2023"
    last = _call(srv, "get_methodology", methodology_id="owasp-api-top10", offset=8)
    assert last["next_offset"] is None


def test_get_methodology_items_carry_a_method_and_no_status():
    out = _call(_server(MagicMock()), "get_methodology", methodology_id="owasp-wstg")
    for item in out["items"]:
        assert item["method"] in {"tooling", "manual"}
        assert not {"status", "covered", "done", "coverage", "evidence"} & set(item)


def test_get_methodology_states_its_scope():
    """The WSTG entry is category-level; a reader must not take it for scenarios."""
    out = _call(_server(MagicMock()), "get_methodology", methodology_id="owasp-wstg")
    assert "Category-level" in out["scope"]
    assert "WSTG-v42-INFO-02" in out["scope"]


def test_get_methodology_rejects_an_unknown_id_and_a_negative_offset():
    srv = _server(MagicMock())
    with pytest.raises(ToolError, match="unknown methodology"):
        _call(srv, "get_methodology", methodology_id="owasp-top-42")
    with pytest.raises(ToolError, match="offset"):
        _call(srv, "get_methodology", methodology_id="owasp-wstg", offset=-1)


def test_methodology_prompt_separates_evidenced_from_suggested():
    text = _expand(_server(MagicMock()), "methodology", engagement_id="e1")
    for heading in (
        "**Evidenced**",
        "**Not evidenced, a job would help**",
        "**Not evidenced, needs hands-on work**",
    ):
        assert heading in text
    assert "job ids or finding ids" in text
    assert "A tool having run is not coverage" in text
    assert "candidate, not a finding" in text


def test_methodology_prompt_sorts_on_the_record_not_the_method():
    """A hand-tested item that was written up is evidenced.

    The first version routed every `manual` item to "requires manual testing"
    whatever the record said, which conflated how an item is tested with whether
    it has been.
    """
    text = _expand(_server(MagicMock()), "methodology", engagement_id="e1")
    assert "how an item is tested, not whether it has been" in text
    assert "Sort on the record, not on the method" in text
    assert "is **evidenced**" in text
    # And the converse: a tooling item is not evidenced just because a tool exists.
    assert "something must actually have run" in text


def test_methodology_prompt_does_not_cite_unassessed_wstg_scenarios():
    text = _expand(_server(MagicMock()), "methodology", engagement_id="e1")
    assert "twelve top-level categories" in text
    assert "WSTG-v42-INFO-02" in text
    assert "not actually assessed" in text


def test_methodology_prompt_forbids_a_coverage_score():
    """A percentage invites exactly the reading the rest of the prompt forbids."""
    text = _expand(_server(MagicMock()), "methodology", engagement_id="e1")
    assert "Do not report a percentage or a score" in text
    assert "not a certification of compliance" in text


def test_methodology_prompt_asks_which_methodology_when_none_given():
    text = _expand(_server(MagicMock()), "methodology", engagement_id="e1")
    assert "list_methodologies" in text and "ask which to use" in text
    assert "Use methodology owasp-wstg" in _expand(
        _server(MagicMock()), "methodology", engagement_id="e1", methodology_id="owasp-wstg"
    )


# ── drafting ──────────────────────────────────────────────────────────────────


def test_draft_test_cases_posts_endpoint_ids_and_stores_nothing():
    fake = MagicMock()
    fake.post.return_value = {"drafts": [{"name": "GET /x"}], "total": 1, "review_notes": []}
    out = _call(_server(fake), "draft_test_cases", engagement_id="e1", endpoint_ids=["ep1", "ep2"])
    assert fake.post.call_args[0][0] == "/engagements/e1/test-cases/preview"
    assert fake.post.call_args.kwargs["json"] == {
        "limit": 20,
        "offset": 0,
        "endpoint_ids": ["ep1", "ep2"],
    }
    assert out["total"] == 1


def test_draft_test_cases_accepts_an_openapi_document():
    fake = MagicMock()
    fake.post.return_value = {"drafts": [], "total": 0}
    _call(
        _server(fake),
        "draft_test_cases",
        engagement_id="e1",
        openapi={"openapi": "3.0.0"},
        base_url="https://api.acme.test",
    )
    body = fake.post.call_args.kwargs["json"]
    assert body["openapi"] == {"openapi": "3.0.0"}
    assert body["base_url"] == "https://api.acme.test"


@pytest.mark.parametrize(
    "args",
    [
        {},  # neither source
        {"endpoint_ids": ["ep1"], "openapi": {"openapi": "3.0.0"}},  # both
    ],
)
def test_draft_test_cases_requires_exactly_one_source(args):
    fake = MagicMock()
    with pytest.raises(ToolError, match="either endpoint_ids or an openapi"):
        _call(_server(fake), "draft_test_cases", engagement_id="e1", **args)
    fake.post.assert_not_called()


def test_draft_test_cases_rejects_a_negative_offset():
    with pytest.raises(ToolError, match="offset"):
        _call(
            _server(MagicMock()),
            "draft_test_cases",
            engagement_id="e1",
            endpoint_ids=["ep1"],
            offset=-1,
        )


def test_draft_report_always_posts_a_draft_status():
    """An agent must not be able to mark a write-up final or delivered."""
    fake = MagicMock()
    fake.post.return_value = {"id": "r1", "status": "draft"}
    _call(
        _server(fake),
        "draft_report",
        engagement_id="e1",
        title="IDOR on /orders",
        finding_id="f1",
        summary="s",
        remediation="fix",
    )
    assert fake.post.call_args[0][0] == "/engagements/e1/reports"
    body = fake.post.call_args.kwargs["json"]
    assert body["status"] == "draft"
    assert body["finding_id"] == "f1" and body["remediation"] == "fix"


def test_draft_report_takes_no_status_argument():
    tool = _tools(_server(MagicMock()))["draft_report"]
    assert "status" not in (tool.input_schema.get("properties") or {})


# ── prompts ───────────────────────────────────────────────────────────────────


def test_exposes_exactly_the_expected_prompts():
    assert set(_prompts(_server(MagicMock()))) == EXPECTED_PROMPTS


@pytest.mark.parametrize("name", sorted(EXPECTED_PROMPTS))
def test_prompt_fetches_nothing_when_expanded(name):
    """A prompt is instructions only — it must never paste target-controlled data in.

    Prompt text is the most trusted content in the agent's context, so embedding
    findings or recon URLs would launder them into that position. Expansion
    touching the API client at all is the regression this guards.
    """
    fake = MagicMock()
    text = _expand(_server(fake), name, engagement_id="e1")
    assert fake.mock_calls == []
    assert "e1" in text


@pytest.mark.parametrize("name", sorted(EXPECTED_PROMPTS))
def test_prompt_without_an_engagement_asks_instead_of_guessing(name):
    text = _expand(_server(MagicMock()), name)
    assert "list_engagements" in text
    assert "not guess" in text or "Do not guess" in text


@pytest.mark.parametrize("name", sorted(EXPECTED_PROMPTS))
def test_every_prompt_marks_tool_output_untrusted(name):
    assert "not instructions" in _expand(_server(MagicMock()), name, engagement_id="e1")


@pytest.mark.parametrize("name", ["triage", "untested", "retest"])
def test_prompts_that_can_queue_require_preview_and_approval(name):
    text = _expand(_server(MagicMock()), name, engagement_id="e1")
    assert "preview_job" in text
    assert "approve" in text or "agrees" in text or "choose" in text


def test_brief_is_read_only_and_queues_nothing():
    text = _expand(_server(MagicMock()), "brief", engagement_id="e1")
    assert "Queue nothing" in text
    assert "queue_job" not in text and "queue_pipeline" not in text


def test_triage_severity_narrows_the_request():
    srv = _server(MagicMock())
    assert "Limit this to high findings" in _expand(
        srv, "triage", engagement_id="e1", severity=" high "
    )
    assert "Cover every severity" in _expand(srv, "triage", engagement_id="e1")


def test_triage_does_not_claim_a_finding_edit_tool():
    text = _expand(_server(MagicMock()), "triage", engagement_id="e1")
    assert "no tool to change one" in text
    assert "next_offset" in text  # pages the whole inventory, not just the first page


def test_retest_targets_one_finding_when_given_and_otherwise_asks():
    srv = _server(MagicMock())
    assert "Retest finding f9" in _expand(srv, "retest", engagement_id="e1", finding_id="f9")
    assert "ask which to take" in _expand(srv, "retest", engagement_id="e1")


def test_retest_allows_an_inconclusive_result():
    text = _expand(_server(MagicMock()), "retest", engagement_id="e1")
    assert "Inconclusive is a real answer" in text


# ── prompts match the tool surface ────────────────────────────────────────────
#
# Green expansion tests prove phrasing, not feasibility: a prompt can be
# perfectly worded and still instruct the agent to do something no tool here can
# do. These pin the prompts against what the server actually exposes.


@pytest.mark.parametrize("name", sorted(EXPECTED_PROMPTS))
def test_prompts_only_name_tools_that_exist(name):
    """Every `snake_case` tool reference in a prompt must be a real tool."""
    import re

    srv = _server(MagicMock())
    text = _expand(srv, name, engagement_id="e1")
    mentioned = {
        word
        for word in re.findall(r"\b[a-z]+(?:_[a-z]+)+\b", text)
        # Config keys and CLI flags share the naming style; only check names that
        # look like this server's tools.
        if word.startswith(("list_", "get_", "queue_", "create_", "preview_"))
    }
    assert mentioned <= set(_tools(srv)), mentioned - set(_tools(srv))


def test_brief_reads_the_authorization_from_the_right_tool():
    """get_engagement does not return authorizations; list_authorizations does."""
    text = _expand(_server(MagicMock()), "brief", engagement_id="e1")
    assert "list_authorizations" in text
    assert "authorization window if one is set (get_engagement)" not in text


def test_brief_keeps_finding_reports_and_client_deliverables_distinct():
    text = _expand(_server(MagicMock()), "brief", engagement_id="e1")
    assert "list_reports" in text and "list_deliverables" in text
    assert "do not conflate them" in text


def test_retest_does_not_invent_a_finding_status():
    """VardrMap statuses are new/candidate/triaged/in_progress/closed."""
    text = _expand(_server(MagicMock()), "retest", engagement_id="e1")
    assert "remediated or awaiting verification" not in text
    for real in ("new", "candidate", "triaged", "in_progress", "closed"):
        assert real in text


def test_retest_reads_finding_history_rather_than_guessing_from_status():
    text = _expand(_server(MagicMock()), "retest", engagement_id="e1")
    assert "get_finding_activity" in text
    assert "history is the signal, not the status" in text


def test_retest_checks_whether_a_retest_already_happened():
    text = _expand(_server(MagicMock()), "retest", engagement_id="e1", finding_id="f1")
    assert "already been retested" in text


def test_triage_can_draft_a_write_up_but_not_finalise_one():
    text = _expand(_server(MagicMock()), "triage", engagement_id="e1")
    assert "draft_report" in text
    assert "cannot mark anything final or delivered" in text


def test_retest_states_that_a_job_cannot_be_scoped_to_one_asset():
    """queue_job takes a target source, not a target, so the prompt must not imply one."""
    text = _expand(_server(MagicMock()), "retest", engagement_id="e1")
    assert "cannot scope a job to one asset" in text
    # The local CLI is the route that does take a single target.
    assert "--target" in text


def test_retest_does_not_claim_a_scan_results_tool():
    text = _expand(_server(MagicMock()), "retest", engagement_id="e1")
    assert "no tool here that reads a job's scan results" in text


def test_untested_quotes_preview_counts_as_an_upper_bound():
    """ffuf collapses targets to roots after VardrMap resolves them."""
    text = _expand(_server(MagicMock()), "untested", engagement_id="e1")
    assert "upper bound" in text


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
    with pytest.raises(ToolError, match="not configured") as exc:
        _call(srv, "list_engagements")
    assert "vardrrunner login vardrmap" in str(exc.value)


def test_unconfigured_message_does_not_repeat_a_login_hint_already_given():
    def boom():
        raise RuntimeError("Not logged in. Run: vardrrunner login vardrmap (or set VARDRMAP_URL)")

    srv = mcp_server.build_server(client_factory=boom)
    with pytest.raises(ToolError) as exc:
        _call(srv, "list_engagements")
    assert str(exc.value).lower().count("login") == 1
